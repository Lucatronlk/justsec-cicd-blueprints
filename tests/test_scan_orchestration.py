"""Offline contracts for independent app and repository security entrypoints."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTIVE = ROOT / ".github" / "workflows"
EXAMPLES = ROOT / "examples" / "workflows"
REGISTRY = ROOT / "scan-targets.json"


def workflow(name: str) -> dict:
    return yaml.safe_load((ACTIVE / name).read_text())


def events(doc: dict) -> dict:
    return doc.get("on") or doc.get(True) or {}


def targets() -> list[dict]:
    return json.loads(REGISTRY.read_text())["targets"]


def called_workflows(jobs: dict) -> set[str]:
    return {str(job.get("uses", "")).removeprefix("./.github/workflows/") for job in jobs.values() if "uses" in job}


def test_eight_registered_app_directories_have_independent_entrypoints():
    registered = targets()
    assert len(registered) == 8
    assert {p.name for p in (ROOT / "apps").iterdir() if p.is_dir()} == {t["app"] for t in registered}
    entrypoints = {p.name for p in ACTIVE.glob("ci-*.yml")}
    assert entrypoints == {f"ci-{t['app']}.yml" for t in registered} | {"ci-repo.yml"}
    assert not (ACTIVE / "ci.yml").exists(), "the matrix orchestrator must not remain active"
    assert {"legacy-ci.yml", "sample-python-api.yml"} <= {p.name for p in EXAMPLES.glob("*.yml")}
    assert not any(p.name.startswith("sample-") for p in ACTIVE.glob("*.yml"))
    assert not any(p.name.startswith("sample-") for p in ACTIVE.glob("*.yaml"))


def test_automatic_scans_are_isolated_to_each_sample_and_repo_ci():
    registered = targets()
    files = {p.name: events(yaml.safe_load(p.read_text())) for p in ACTIVE.glob("*.yml")}
    manual = {"single-scanner-test.yml", "pin-check.yml", "baseline-audit.yml"}
    for name in manual:
        assert set(files[name]) == {"workflow_dispatch"}
    automatic = {f"ci-{t['app']}.yml" for t in registered if t["kind"] == "sample"} | {"ci-repo.yml"}
    for name, triggers in files.items():
        if name in automatic:
            assert {"push", "pull_request", "workflow_dispatch"} <= set(triggers), name
        elif name.startswith("ci-") and name != "ci-repo.yml":
            assert set(triggers) == {"workflow_dispatch"}, f"{name} fixture must be manual-only"
        elif name not in manual:
            assert set(triggers) == {"workflow_call"}, f"{name} unexpectedly starts independently"


def test_each_app_entrypoint_scopes_work_to_its_own_directory():
    for target in targets():
        app = target["app"]
        doc = workflow(f"ci-{app}.yml")
        triggers = events(doc)
        for event in ("push", "pull_request") if target["kind"] == "sample" else ():
            paths = triggers[event].get("paths", [])
            assert any(f"apps/{app}/" in pattern for pattern in paths), f"{app}: missing path filter"
        jobs = doc["jobs"]
        assert "select" not in jobs and "app-scan" not in jobs, f"{app}: legacy matrix jobs remain"
        assert all("matrix" not in job.get("strategy", {}) for job in jobs.values()), app
        assert all("select_scan_targets.py" not in str(job) for job in jobs.values()), app
        assert doc["permissions"] == {"contents": "read"}
        for name, job in jobs.items():
            if job.get("uses", "").startswith("./.github/workflows/profile-"):
                if name == "image":
                    assert job["with"]["docker-context"] == target["context"]
                    assert job["with"]["dockerfile"] == target["dockerfile"]
                else:
                    assert job["with"]["working-directory"] == target["path"], f"{app}: {name} scans wrong tree"
                assert job["permissions"] == {"contents": "read", "security-events": "write"}
                assert job["with"]["upload-sarif"] is False


def test_pull_requests_use_pr_gate_and_image_and_full_are_manual_only():
    for target in targets():
        if target["kind"] != "sample":
            continue
        app = target["app"]
        doc = workflow(f"ci-{app}.yml")
        jobs = doc["jobs"]
        pr_jobs = [job for job in jobs.values() if job.get("uses") == "./.github/workflows/profile-pr-gate.yml"]
        assert pr_jobs, f"{app}: no PR security profile"
        assert any("pull_request" in str(job.get("if", "")) for job in pr_jobs), app
        for name, job in jobs.items():
            if job.get("uses") in ("./.github/workflows/profile-image.yml", "./.github/workflows/profile-full.yml"):
                condition = str(job.get("if", ""))
                assert "github.event_name == 'workflow_dispatch'" in condition, f"{app}: {name} is not manual-only"
                assert "||" not in condition and "pull_request" not in condition, f"{app}: {name} may run on PRs"
        if "dockerfile" in target:
            assert "profile-image.yml" in called_workflows(jobs), f"{app}: no opt-in image scan"
        assert "profile-full.yml" in called_workflows(jobs), f"{app}: no opt-in full scan"


def test_repo_ci_is_independent_and_cannot_be_skipped_by_app_selection():
    doc = workflow("ci-repo.yml")
    jobs = doc["jobs"]
    assert {"workflow-lint", "test", "secrets", "security-green"} <= set(jobs)
    assert "select" not in jobs and "app-scan" not in jobs
    gate = jobs["security-green"]
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == set(jobs) - {"security-green"}
    assert gate["permissions"] == {}
    assert jobs["secrets"]["uses"] == "./.github/workflows/profile-secrets.yml"
    assert jobs["secrets"]["permissions"] == {"contents": "read", "security-events": "write"}
    assert jobs["secrets"]["with"]["upload-sarif"] is False
    for name in ("workflow-lint", "test", "secrets"):
        assert f"needs.{name}.result" in str(gate["steps"][-1]["env"])
    assert "success" in gate["steps"][-1]["run"]
    assert doc["permissions"] == {"contents": "read"}
    lint_steps = jobs["workflow-lint"]["steps"]
    assert any("--require-hashes" in step.get("run", "") and "pyflakes" in step.get("run", "") for step in lint_steps)
    assert any(
        "raven-actions/actionlint@" in step.get("uses", "") and step.get("with", {}).get("pyflakes") is not False
        for step in lint_steps
    )


def test_terraform_profile_includes_dev_scans_and_keeps_the_gate_complete():
    dev = workflow("profile-dev.yml")["jobs"]
    tf = workflow("profile-tf.yml")["jobs"]
    dev_scans = {name: job["uses"] for name, job in dev.items() if name != "gate"}
    tf_scans = {name: job["uses"] for name, job in tf.items() if name != "gate"}
    assert set(dev_scans.items()) <= set(tf_scans.items()), (
        "Terraform must be a superset of dev, not replace Semgrep/Trivy fs"
    )
    assert {"trivy-config", "checkov"} <= set(tf_scans)
    gate = tf["gate"]
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == set(tf_scans)
    assert gate["uses"] == "./.github/workflows/security-gate.yml"
    assert gate["with"]["upstream-results"] == "${{ join(needs.*.result, ',') }}"
    for name, job in tf.items():
        if name != "gate":
            assert job["with"]["artifact-name"].startswith("${{ inputs.artifact-prefix }}-")
            assert job["permissions"].get("security-events") == "write", name
