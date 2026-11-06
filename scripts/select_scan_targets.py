#!/usr/bin/env python3
"""Offline, deterministic scan matrix planner. See --help for the CLI contract."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "scan-targets.json"
MAX_TARGETS = 32
MAX_DIFF_BYTES = 4_000_000
NAME = re.compile(r"[a-z][a-z0-9-]*\Z")
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./~-]*\Z")
DEPTHS = ("minimum", "pr", "full")


class PlannerError(ValueError):
    """Invalid planner input or registry."""


def valid_path(path: str) -> bool:
    return (
        isinstance(path, str)
        and 0 < len(path) <= 512
        and not path.startswith("/")
        and "\\" not in path
        and all(part not in ("", ".", "..") for part in path.split("/"))
        and all(32 <= ord(char) <= 126 for char in path)
    )


def load_registry(path: Path = REGISTRY) -> list[dict[str, str]]:
    """Validate a bounded registry; never accept executable YAML or arbitrary paths."""
    try:
        if path.stat().st_size > 32_768:
            raise PlannerError("registry too large")

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise PlannerError("duplicate registry key")
                value[key] = item
            return value

        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PlannerError("cannot read registry") from exc
    if not isinstance(data, dict) or set(data) != {"targets"} or not isinstance(data["targets"], list):
        raise PlannerError("invalid registry structure")
    targets = data["targets"]
    if not 1 <= len(targets) <= MAX_TARGETS:
        raise PlannerError("invalid target count")
    seen: set[str] = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) not in (
            {"app", "path", "kind", "artifact-prefix"},
            {"app", "path", "kind", "artifact-prefix", "dockerfile", "context"},
        ):
            raise PlannerError("invalid target fields")
        app = target["app"]
        if not isinstance(app, str) or not NAME.fullmatch(app) or app in seen:
            raise PlannerError("invalid or duplicate app")
        seen.add(app)
        if any(not isinstance(value, str) for value in target.values()):
            raise PlannerError("target fields must be strings")
        if target["kind"] not in ("sample", "fixture"):
            raise PlannerError("invalid target kind")
        if target["path"] != f"apps/{app}" or target["artifact-prefix"] != app:
            raise PlannerError("invalid target path or artifact-prefix")
        if "dockerfile" in target and (
            target["dockerfile"] != f"apps/{app}/Dockerfile" or target["context"] != target["path"]
        ):
            raise PlannerError("invalid docker context")
    return targets


def check_app_coverage(targets: list[dict[str, str]], root: Path = ROOT) -> None:
    """Do not silently omit an app, including a symlink to an external directory."""
    expected = {target["app"] for target in targets}
    try:
        apps = root / "apps"
        if not stat.S_ISDIR(apps.lstat().st_mode):
            raise PlannerError("apps is not a real directory")
        actual: set[str] = set()
        for entry in apps.iterdir():
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise PlannerError("symlink under apps is unsafe")
            if stat.S_ISDIR(mode):
                actual.add(entry.name)
        if actual != expected:
            raise PlannerError(
                f"apps directory coverage mismatch: missing={sorted(expected - actual)}, "
                f"unregistered={sorted(actual - expected)}"
            )
    except OSError as exc:
        raise PlannerError("cannot inspect apps directories") from exc


def manual_selection(selection: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    """Explicit selections may include fixtures; implicit selections never do."""
    by_app = {target["app"]: target for target in targets}
    if selection == "all":
        return [target for target in targets if target["kind"] == "sample"]
    names = selection.split(",")
    if not names or any(name not in by_app for name in names) or len(names) != len(set(names)):
        raise PlannerError("invalid manual selection: unknown, empty, or duplicate app")
    selected = set(names)
    return [target for target in targets if target["app"] in selected]


def changed_paths(base: str, head: str) -> list[str] | None:
    """Return None when git cannot prove a complete diff; caller selects all samples."""
    if not all(REF.fullmatch(ref) and ".." not in ref and not ref.endswith("/") for ref in (base, head)):
        raise PlannerError("invalid git revision")
    try:
        revisions = []
        for ref in (base, head):
            result = subprocess.run(
                ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
                cwd=ROOT,
                capture_output=True,
                timeout=15,
                check=True,
            )
            revision = result.stdout.decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
                return None
            revisions.append(revision)
        result = subprocess.run(
            ["git", "diff", "--no-ext-diff", "--name-only", "-z", *revisions, "--"],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
            check=True,
        )
        if len(result.stdout) > MAX_DIFF_BYTES or (result.stdout and not result.stdout.endswith(b"\0")):
            return None
        paths = [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]
        if any(not valid_path(path) for path in paths):
            return None
        return paths
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def select_changed(paths: list[str] | None, targets: list[dict[str, str]]) -> tuple[list[dict[str, str]], bool]:
    """Unknown diff/shared file => all samples. Fixture-only/empty => explicit repo-only."""
    samples = [target for target in targets if target["kind"] == "sample"]
    if paths is None or any(not valid_path(path) for path in paths):
        return samples, False
    selected: set[str] = set()
    by_app = {target["app"]: target for target in targets}
    for path in paths:
        if path.endswith(("-lock.yaml", "-lock.json", ".lock", ".lock.hcl")) or Path(path).name in (
            "package-lock.json",
            "yarn.lock",
            "poetry.lock",
            "Pipfile.lock",
            "Cargo.lock",
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-ci.txt",
        ):
            return samples, False
        if path.startswith("apps/"):
            parts = path.split("/")
            if len(parts) >= 3 and parts[1] in by_app:
                if by_app[parts[1]]["kind"] == "sample":
                    selected.add(parts[1])
                continue
        # Shared/dependency/workflow/registry/unknown files may affect every sample.
        return samples, False
    return [target for target in samples if target["app"] in selected], not selected


def plan(selection: str, depth: str, base: str | None = None, head: str | None = None) -> dict:
    if depth not in DEPTHS:
        raise PlannerError("invalid depth")
    targets = load_registry()
    check_app_coverage(targets)
    if selection == "changed":
        if not base or not head:
            raise PlannerError("changed selection requires --base and --head")
        entries, repo_only = select_changed(changed_paths(base, head), targets)
    else:
        entries = manual_selection(selection, targets)
        repo_only = False
    include = [{key: value for key, value in target.items() if key != "kind"} | {"depth": depth} for target in entries]
    return {"matrix": {"include": include}, "repo_only": repo_only, "count": len(include)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--select", required=True, help="changed, all, or comma-separated app names")
    parser.add_argument("--depth", choices=DEPTHS, default="pr")
    parser.add_argument("--base", help="base git revision (required for changed)")
    parser.add_argument("--head", help="head git revision (required for changed)")
    parser.add_argument("--github-output", type=Path, help="append matrix, repo_only and count to caller-owned output")
    args = parser.parse_args(argv)
    try:
        if args.select != "changed" and (args.base or args.head):
            raise PlannerError("--base/--head only apply to changed")
        result = plan(args.select, args.depth, args.base, args.head)

        def compact(value: object) -> str:
            return json.dumps(value, separators=(",", ":"))

        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(f"matrix={compact(result['matrix'])}\n")
                output.write(f"repo_only={compact(result['repo_only'])}\n")
                output.write(f"count={result['count']}\n")
        print(compact(result))
        return 0
    except (PlannerError, OSError) as exc:
        print(f"scan target planner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
