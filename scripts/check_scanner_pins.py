#!/usr/bin/env python3
"""Report stale scanner tool pins in the reusable workflows.

The scan-*.yml and the CI workflows pin every CLI tool twice, as a
``<tool>-version`` and a ``<tool>-sha256`` input pair (for example
``trivy-version`` / ``trivy-sha256``). Dependabot moves the action SHAs but
not these arbitrary YAML values, so a tool version can drift silently stale
while its hash keeps the download reproducible.

This script is the detection half of that gap. With no flag it lists every
tool pin it finds (a pure read of the checked-out tree, no network). With
``--stale`` it asks the GitHub API for each tool's latest release and flags
every pin whose version differs from it; a pin whose latest release could not
be read is reported as UNKNOWN, never as current, and makes the exit code
non-zero the same way a stale pin does.

    python scripts/check_scanner_pins.py          # list pins, exit 0
    python scripts/check_scanner_pins.py --stale  # flag stale pins, exit 1/2

Exit codes: 0 all pins current (or valid list mode), 1 at least one stale pin,
2 invalid pins or no stale pin but at least one UNKNOWN. The token comes from GITHUB_TOKEN or
GH_TOKEN if present; the GitHub API also serves public releases without one.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Tool name (as it appears in ``<tool>-version``) to the GitHub repo whose
# release feed carries its version, for the tools this repository pins.
TOOL_REPOS: dict[str, str] = {
    "gitleaks": "gitleaks/gitleaks",
    "trivy": "aquasecurity/trivy",
    "grype": "anchore/grype",
    "osv-scanner": "google/osv-scanner",
    "tflint": "terraform-linters/tflint",
    "hadolint": "hadolint/hadolint",
    "shellcheck": "koalaman/shellcheck",
    "shfmt": "mvdan/sh",
    "tofu": "opentofu/opentofu",
    "arduino-cli": "arduino/arduino-cli",
}

# Track YAML indentation so only on.workflow_call.inputs declarations count.
# Reject incomplete or conflicting tool pins before any --stale API lookup.
KEY_RE = re.compile(r"^([ ]*)([A-Za-z0-9_-]+):(?:[ ]*(?:#.*)?)?$")
DEFAULT_RE = re.compile(r"^[ ]*default:[ ]*(.*)$")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9.-]+)?")
SHA_RE = re.compile(r"[0-9a-fA-F]{64}")


def _inputs(text: str, path: Path) -> dict[str, str | None]:
    """Read workflow_call input defaults only, keeping missing values visible."""
    levels: list[tuple[int, str]] = []
    values: dict[str, str | None] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while levels and levels[-1][0] >= indent:
            levels.pop()
        parents = [key for _, key in levels]
        match = KEY_RE.fullmatch(line)
        if parents == ["on", "workflow_call", "inputs"] and not match:
            candidate = re.match(r"^\s*([A-Za-z0-9_-]+-(?:version|sha256)):", line)
            if candidate:
                raise ValueError(f"{path}:{number}: unsupported {candidate.group(1)} input declaration")
        if match:
            key = match.group(2)
            if parents == ["on", "workflow_call", "inputs"] and key.endswith(("-version", "-sha256")):
                if key in values:
                    raise ValueError(f"{path}:{number}: duplicate {key} input")
                values[key] = None
            levels.append((indent, key))
        elif parents[:3] == ["on", "workflow_call", "inputs"] and len(parents) == 4:
            default = DEFAULT_RE.fullmatch(line)
            if not default and re.match(r"^\s*default:", line) and parents[3] in values:
                raise ValueError(f"{path}:{number}: unsupported {parents[3]} default")
            if default and parents[3] in values:
                if values[parents[3]] is not None:
                    raise ValueError(f"{path}:{number}: duplicate {parents[3]} default")
                value = default.group(1).strip()
                if len(value) >= 2 and value[0] in ('"', "'") and value.endswith(value[0]):
                    value = value[1:-1]
                values[parents[3]] = value
    return values


def pins() -> dict[str, dict[str, str]]:
    """Validated {tool: {version, sha256}} from workflow_call input defaults."""
    found: dict[str, dict[str, str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        inputs = _inputs(path.read_text(), path)
        tools = {key.removesuffix("-version").removesuffix("-sha256") for key in inputs}
        for tool in sorted(tools):
            version = inputs.get(f"{tool}-version")
            sha = inputs.get(f"{tool}-sha256")
            # Runtime versions without checksums are not scanner tool pins.
            if f"{tool}-sha256" not in inputs and (tool == "python" or tool.endswith("-python")):
                continue
            if not version or not VERSION_RE.fullmatch(version):
                raise ValueError(f"{path}: {tool}-version missing or invalid default")
            if not sha or not SHA_RE.fullmatch(sha):
                raise ValueError(f"{path}: {tool}-sha256 missing or invalid default")
            previous = found.get(tool)
            if previous and previous["version"] != version:
                raise ValueError(f"{path}: conflicting {tool} versions: {previous['version']} vs {version}")
            if previous and previous["sha256"] != sha:
                raise ValueError(f"{path}: conflicting {tool} sha256 defaults")
            found[tool] = {"version": version, "sha256": sha}
    return found


def normalize(version: str) -> str:
    """Drop a leading ``v`` and any trailing newline/spaces for comparison."""
    version = version.strip()
    if version.startswith("v") and len(version) > 1 and version[1].isdigit():
        return version[1:]
    return version


def latest_release(repo: str) -> tuple[str, str | None]:
    """(normalized latest tag, error) from the GitHub API."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "check-scanner-pins"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read())
        tag = body.get("tag_name", "")
        return normalize(tag), None
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as err:
        return "", str(err)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stale",
        action="store_true",
        help="ask the GitHub API for each tool's latest release and flag stale pins",
    )
    args = parser.parse_args()

    try:
        found = pins()
    except (ValueError, OSError, UnicodeError) as err:
        print(f"invalid scanner pins: {err}", file=sys.stderr)
        return 2
    if not found:
        print("no paired scanner tool pins found", file=sys.stderr)
        return 2

    tools = sorted(found)
    stale = 0
    unknown = 0
    for tool in tools:
        pin = found[tool]
        version = pin.get("version", "(no version input)")
        sha = pin.get("sha256", "(no sha256 input)")
        repo = TOOL_REPOS.get(tool)
        if not args.stale:
            note = "" if repo else "  # not in the known repo map"
            print(f"{tool}: {version} sha256={sha}{note}")
            continue
        if not repo:
            print(f"UNKNOWN  {tool}: pinned {version} but no repo mapping to check against")
            unknown += 1
            continue
        latest, error = latest_release(repo)
        if error:
            print(f"UNKNOWN  {tool}: pinned {version}, could not read latest ({error})")
            unknown += 1
        elif latest != normalize(version):
            print(f"STALE    {tool}: pinned {version}, latest {latest}")
            stale += 1
        else:
            print(f"OK       {tool}: {version}")

    if stale:
        print("\nstale pins found: bump the version and sha256 inputs together")
        return 1
    if unknown:
        print("\ncould not check every pin: fix the tool mapping or the network, then re-run")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
