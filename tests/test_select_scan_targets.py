"""Offline checks for the scan target registry and diff planner."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "select_scan_targets.py"
spec = importlib.util.spec_from_file_location("select_scan_targets", SCRIPT)
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def test_registry_all_types_and_fixtures():
    targets = planner.load_registry()
    assert {target["app"] for target in targets if target["kind"] == "sample"} == {
        "python-api",
        "typescript-web",
        "dotnet-api",
        "container-web",
        "infrastructure",
        "k8s",
    }
    assert {target["app"] for target in targets if target["kind"] == "fixture"} == {"fixture", "sample-app"}
    assert len(planner.manual_selection("all", targets)) == 6
    assert [target["app"] for target in planner.manual_selection("fixture,sample-app", targets)] == [
        "fixture",
        "sample-app",
    ]
    for target in targets:
        assert target["path"] == "apps/" + target["app"]
        assert target["artifact-prefix"] == target["app"]
        if "dockerfile" in target:
            assert target["context"] == target["path"]


@pytest.mark.parametrize(
    "selection", ["", "unknown", "all,fixture", ",fixture", "fixture,", "fixture,fixture", " fixture"]
)
def test_invalid_manual_selection(selection):
    with pytest.raises(planner.PlannerError):
        planner.manual_selection(selection, planner.load_registry())


@pytest.mark.parametrize("depth", planner.DEPTHS)
def test_matrix_depth_and_output(depth, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(planner, "changed_paths", lambda base, head: ["apps/k8s/new.yaml"])
    output = tmp_path / "output"
    assert (
        planner.main(
            [
                "--select",
                "changed",
                "--base",
                "base",
                "--head",
                "head",
                "--depth",
                depth,
                "--github-output",
                str(output),
            ]
        )
        == 0
    )
    matrix = json.loads(capsys.readouterr().out)
    assert matrix["repo_only"] is False
    assert matrix["count"] == 1
    assert matrix["matrix"] == {
        "include": [
            {
                "app": "k8s",
                "path": "apps/k8s",
                "artifact-prefix": "k8s",
                "dockerfile": "apps/k8s/Dockerfile",
                "context": "apps/k8s",
                "depth": depth,
            }
        ]
    }
    assert output.read_text() == (
        "matrix=" + json.dumps(matrix["matrix"], separators=(",", ":")) + "\nrepo_only=false\ncount=1\n"
    )


@pytest.mark.parametrize("path", ["apps/python-api/app.py", "apps/python-api/new.py", "apps/python-api/deleted.py"])
def test_modified_new_deleted_app_path(path):
    entries, repo_only = planner.select_changed([path], planner.load_registry())
    assert not repo_only
    assert [entry["app"] for entry in entries] == ["python-api"]


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/scan.yml",
        "scripts/security_gate.py",
        "requirements-dev.txt",
        "scan-targets.json",
        "apps/typescript-web/pnpm-lock.yaml",
        "apps/infrastructure/.terraform.lock.hcl",
        "apps/unknown/new.py",
        "README.md",
    ],
)
def test_shared_or_unknown_changes_select_all_samples(path):
    entries, repo_only = planner.select_changed([path], planner.load_registry())
    assert not repo_only
    assert len(entries) == 6


@pytest.mark.parametrize("paths", [[], ["apps/fixture/tests/test_cli.py"], ["apps/sample-app/sample.py"]])
def test_no_impacted_apps_is_explicit_repo_only(paths):
    entries, repo_only = planner.select_changed(paths, planner.load_registry())
    assert entries == [] and repo_only


@pytest.mark.parametrize(
    "paths", [None, ["apps/python-api/../k8s/workload.yaml"], ["/apps/k8s/a"], ["apps/k8s/a\nb"], ["apps\\k8s\\a"]]
)
def test_missing_diff_or_malformed_paths_fail_closed_to_all(paths):
    entries, repo_only = planner.select_changed(paths, planner.load_registry())
    assert len(entries) == 6 and not repo_only


def test_git_diff_deleted_and_new_files_and_safe_args(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1] == "rev-parse":
            return SimpleNamespace(stdout=("a" * 40 + "\n").encode())
        return SimpleNamespace(stdout=b"apps/python-api/old.py\0apps/dotnet-api/new.cs\0")

    monkeypatch.setattr(planner.subprocess, "run", fake_run)
    assert planner.changed_paths("main", "HEAD") == ["apps/python-api/old.py", "apps/dotnet-api/new.cs"]
    assert calls[-1] == ["git", "diff", "--no-ext-diff", "--name-only", "-z", "a" * 40, "a" * 40, "--"]
    with pytest.raises(planner.PlannerError):
        planner.changed_paths("--upload-pack=evil", "HEAD")


def test_missing_diff_fails_closed(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(planner.subprocess, "run", missing)
    assert len(planner.plan("changed", "pr", "HEAD~1", "HEAD")["matrix"]["include"]) == 6


def test_bad_registry_rejected(tmp_path):
    target = planner.load_registry()[0]
    for bad in [{**target, "path": "apps/../x"}, {**target, "kind": "unknown"}]:
        file = tmp_path / "registry.json"
        file.write_text(json.dumps({"targets": [bad]}))
        with pytest.raises(planner.PlannerError):
            planner.load_registry(file)
    file.write_text('{"targets":[],"targets":[]}')
    with pytest.raises(planner.PlannerError):
        planner.load_registry(file)


def test_repo_only_output(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(planner, "changed_paths", lambda base, head: [])
    output = tmp_path / "output"
    assert (
        planner.main(["--select", "changed", "--base", "main", "--head", "HEAD", "--github-output", str(output)]) == 0
    )
    assert json.loads(capsys.readouterr().out) == {"matrix": {"include": []}, "repo_only": True, "count": 0}
    assert output.read_text() == 'matrix={"include":[]}\nrepo_only=true\ncount=0\n'


def test_registry_coverage(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    targets = planner.load_registry()
    for target in targets:
        (apps / target["app"]).mkdir()
    planner.check_app_coverage(targets, tmp_path)
    extra = apps / "unexpected"
    extra.mkdir()
    with pytest.raises(planner.PlannerError, match="unregistered"):
        planner.check_app_coverage(targets, tmp_path)
    extra.rmdir()
    (apps / "fixture").rmdir()
    with pytest.raises(planner.PlannerError, match="missing"):
        planner.check_app_coverage(targets, tmp_path)
    (apps / "fixture").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(planner.PlannerError, match="symlink"):
        planner.check_app_coverage(targets, tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("app", 4),
        ("path", 4),
        ("kind", None),
        ("artifact-prefix", False),
        ("dockerfile", None),
        ("context", ["apps/python-api"]),
        ("path", "apps/python-api/../k8s"),
    ],
)
def test_registry_rejects_wrong_types_and_paths(field, value, tmp_path):
    target = planner.load_registry()[0].copy()
    target[field] = value
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"targets": [target]}))
    with pytest.raises(planner.PlannerError):
        planner.load_registry(path)


def test_cli_rejects_bad_input(capsys):
    assert planner.main(["--select", "changed"]) == 2
    assert planner.main(["--select", "unknown"]) == 2
    assert planner.main(["--select", "all", "--base", "HEAD"]) == 2
    assert "scan target planner" in capsys.readouterr().err
