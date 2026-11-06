"""The security gate and the scan family around it.

The gate is the one decision every profile ends in, so its policy is tested
here against a small report from each scanner, shaped like the real output
(field names taken from the tools' JSON at the pinned versions). No report
here carries a secret value; the scanners' own redaction is what the scan
workflows rely on.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
SCRIPT = REPO / "scripts" / "security_gate.py"
# scan-app orchestrates scanner workflows; it does not generate a report itself.
SCANS = sorted(path for path in WORKFLOWS.glob("scan-*.yml") if path.name != "scan-app.yml")
PROFILES = sorted(WORKFLOWS.glob("profile-*.yml"))
TODAY = "2026-10-08"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def inputs_of(path: Path) -> dict:
    doc = load(path)
    return (doc.get("on") or doc.get(True))["workflow_call"].get("inputs") or {}


# --- one small report per scanner -------------------------------------------

REPORTS = {
    "gitleaks.json": [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "app/config.py",
            "StartLine": 2,
            "Secret": "REDACTED",
        }
    ],
    "trufflehog.json": [
        {"DetectorName": "AWS", "Verified": True, "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}}},
        {"DetectorName": "Slack", "Verified": False, "SourceMetadata": {"Data": {"Git": {"file": "b.py", "line": 3}}}},
    ],
    "semgrep.json": {
        "results": [
            {
                "check_id": "py.shell-true",
                "path": "app.py",
                "start": {"line": 3},
                "extra": {"severity": "ERROR", "message": "m", "metadata": {"impact": "LOW"}},
            },
            {
                "check_id": "py.sqli",
                "path": "db.py",
                "start": {"line": 9},
                "extra": {"severity": "ERROR", "message": "m", "metadata": {}},
            },
        ],
        "errors": [],
    },
    "trivy-fs.json": {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-14343",
                        "PkgName": "PyYAML",
                        "InstalledVersion": "5.3",
                        "Severity": "CRITICAL",
                    }
                ],
            },
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS-0002", "Severity": "HIGH", "Status": "FAIL", "Title": "root user"},
                    {"ID": "DS-0026", "Severity": "LOW", "Status": "PASS", "Title": "healthcheck"},
                ],
            },
            {
                "Target": "config.py",
                "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS", "StartLine": 1}],
            },
        ]
    },
    "grype.json": {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-x", "severity": "Negligible"},
                "artifact": {"name": "pkg", "version": "1", "locations": [{"path": "/usr/lib/x"}]},
            }
        ]
    },
    "osv-scanner.json": {
        "results": [
            {
                "source": {"path": "/home/runner/work/repo/repo/requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "PYSEC-2020-96"},
                            {"id": "GHSA-y", "database_specific": {"severity": "MODERATE"}},
                        ],
                        "groups": [
                            {
                                "ids": ["PYSEC-2020-96"],
                                "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
                                "max_severity": "9.8",
                            },
                            {"ids": ["GHSA-y"], "aliases": ["GHSA-y"], "max_severity": ""},
                        ],
                    }
                ],
            }
        ]
    },
    "checkov.json": [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_23",
                        "check_name": "sg description",
                        "file_path": "/main.tf",
                        "file_line_range": [5, 12],
                        "severity": None,
                    }
                ]
            },
        },
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_3",
                        "check_name": "user",
                        "file_path": "/Dockerfile",
                        "file_line_range": [1, 3],
                        "severity": "HIGH",
                    }
                ]
            },
        },
    ],
    "kics.json": {
        "queries": [
            {
                "query_name": "S3 ACL public",
                "query_id": "38c5ee0d",
                "severity": "CRITICAL",
                "files": [{"file_name": "tf/main.tf", "line": 3}],
            }
        ]
    },
    "tflint.json": {
        "issues": [
            {
                "rule": {"name": "terraform_required_version", "severity": "warning"},
                "message": "m",
                "range": {"filename": "main.tf", "start": {"line": 1}},
            }
        ]
    },
    "hadolint.json": [
        {"code": "DL3007", "level": "warning", "file": "Dockerfile", "line": 1, "message": "latest"},
        {"code": "DL3002", "level": "error", "file": "Dockerfile", "line": 4, "message": "root"},
    ],
    "dependency-check.json": {
        "dependencies": [
            {
                "fileName": "log4j-core-2.14.1.jar",
                "filePath": "/src/lib/log4j-core-2.14.1.jar",
                "vulnerabilities": [{"name": "CVE-2021-44228", "severity": "CRITICAL"}],
            }
        ]
    },
}


def write_reports(directory: Path, names=None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, doc in REPORTS.items():
        if names and name not in names:
            continue
        if name == "trufflehog.json":
            (directory / name).write_text("\n".join(json.dumps(d) for d in doc) + "\n")
        else:
            (directory / name).write_text(json.dumps(doc))
    return directory


def gate(tmp_path: Path, results: Path, exceptions: dict | None = None, **env: str):
    findings = tmp_path / "findings.json"
    summary = tmp_path / "summary.md"
    base = {
        "PATH": os.environ["PATH"],
        "RESULTS_DIR": str(results),
        "FAIL_ON": "CRITICAL,HIGH",
        "FAIL_ON_SECRETS": "false",
        "FINDINGS_OUT": str(findings),
        "GITHUB_STEP_SUMMARY": str(summary),
        "TODAY": TODAY,
        "EXPECTED_REPORTS": ",".join(sorted({p.stem for p in results.rglob("*.json")})) or "gitleaks",
    }
    if exceptions is not None:
        path = tmp_path / "exceptions.json"
        path.write_text(json.dumps(exceptions))
        base["EXCEPTIONS_JSON"] = str(path)
    base.update(env)
    proc = subprocess.run([sys.executable, str(SCRIPT)], env=base, capture_output=True, text=True)
    out = json.loads(findings.read_text()) if findings.exists() else {}
    return proc.returncode, out, proc.stdout


def ids(items) -> set[str]:
    return {f["id"] for f in items}


# --- the policy --------------------------------------------------------------


def test_every_scanner_report_is_read_and_mapped_onto_one_scale(tmp_path):
    rc, out, _ = gate(tmp_path, write_reports(tmp_path / "r"))
    by = {(f["tool"], f["id"]): f["severity"] for f in out["findings"]}
    assert by[("gitleaks", "generic-api-key")] == "HIGH", "a gitleaks match is a likely secret"
    assert by[("trufflehog", "AWS")] == "CRITICAL", "a verified live credential"
    assert by[("trufflehog", "Slack")] == "MEDIUM", "unverified: reported, not blocking by default"
    assert by[("semgrep", "py.shell-true")] == "LOW", "a rule's impact outranks its ERROR level"
    assert by[("semgrep", "py.sqli")] == "HIGH", "ERROR with no impact is HIGH"
    assert by[("trivy-fs", "CVE-2020-14343")] == "CRITICAL"
    assert by[("trivy-fs", "DS-0002")] == "HIGH"
    assert ("trivy-fs", "DS-0026") not in by, "a passed misconfiguration check is not a finding"
    assert by[("trivy-fs", "aws-access-key-id")] == "CRITICAL"
    assert by[("grype", "GHSA-x")] == "LOW", "Negligible"
    assert by[("osv-scanner", "CVE-2020-1747")] == "CRITICAL", "CVSS 9.8, named by its CVE alias"
    assert by[("osv-scanner", "GHSA-y")] == "MEDIUM", "no score: the advisory's MODERATE"
    assert by[("checkov", "CKV_AWS_23")] == "MEDIUM", "no severity without a platform key"
    assert by[("checkov", "CKV_DOCKER_3")] == "HIGH"
    assert by[("kics", "38c5ee0d")] == "CRITICAL"
    assert by[("tflint", "terraform_required_version")] == "MEDIUM"
    assert by[("hadolint", "DL3002")] == "HIGH" and by[("hadolint", "DL3007")] == "MEDIUM"
    assert by[("dependency-check", "CVE-2021-44228")] == "CRITICAL"
    assert rc == 1


def test_critical_and_high_block_medium_and_low_are_reported(tmp_path):
    rc, out, _ = gate(tmp_path, write_reports(tmp_path / "r"))
    assert {f["severity"] for f in out["blocking"]} == {"CRITICAL", "HIGH"}
    assert any(f["severity"] in ("MEDIUM", "LOW") for f in out["findings"])
    assert rc == 1


def test_a_clean_report_passes(tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    (results / "trivy-fs.json").write_text(json.dumps({"Results": []}))
    (results / "gitleaks.json").write_text("[]")
    rc, out, text = gate(tmp_path, results)
    assert rc == 0 and out["blocking"] == []
    assert "**PASS**" in (tmp_path / "summary.md").read_text()


def test_fail_on_is_configurable_and_none_reports_only(tmp_path):
    results = write_reports(tmp_path / "r", ["tflint.json"])
    assert gate(tmp_path, results)[0] == 0, "a MEDIUM does not block by default"
    assert gate(tmp_path, results, FAIL_ON="CRITICAL,HIGH,MEDIUM")[0] == 1
    assert gate(tmp_path, write_reports(tmp_path / "all"), FAIL_ON="none")[0] == 0


def test_fail_on_secrets_blocks_unverified_secrets_too(tmp_path):
    results = write_reports(tmp_path / "r", ["trufflehog.json"])
    _, out, _ = gate(tmp_path, results)
    assert ids(out["blocking"]) == {"AWS"}
    _, out, _ = gate(tmp_path, results, FAIL_ON_SECRETS="true")
    assert ids(out["blocking"]) == {"AWS", "Slack"}


def test_a_failed_scan_job_fails_the_gate_even_with_clean_reports(tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    (results / "gitleaks.json").write_text("[]")
    rc, _, text = gate(tmp_path, results, UPSTREAM_RESULTS="success,failure,skipped")
    assert rc == 2 and "cannot pass" in text
    assert gate(tmp_path, results, UPSTREAM_RESULTS="success,skipped")[0] == 0, "a skipped scan is not a failure"


def test_missing_expected_report_fails_even_when_another_report_is_clean(tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    (results / "gitleaks.json").write_text("[]")
    rc, _, text = gate(tmp_path, results, EXPECTED_REPORTS="gitleaks,semgrep")
    assert rc == 2 and "missing expected report semgrep.json" in text


def test_duplicate_expected_report_fails(tmp_path):
    results = tmp_path / "r"
    for artifact in ("scan-gitleaks", "scan-other"):
        (results / artifact).mkdir(parents=True)
        (results / artifact / "gitleaks.json").write_text("[]")
    rc, _, text = gate(tmp_path, results, EXPECTED_REPORTS="gitleaks")
    assert rc == 2 and "duplicate report gitleaks.json" in text


def test_bad_upstream_status_fails_with_expected_report_present(tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    (results / "gitleaks.json").write_text("[]")
    for status in ("failure", "cancelled", "unknown"):
        assert gate(tmp_path, results, EXPECTED_REPORTS="gitleaks", UPSTREAM_RESULTS=status)[0] == 2


def test_missing_inventory_cannot_pass_with_clean_report(tmp_path):
    results = write_reports(tmp_path / "r", ["gitleaks.json"])
    rc, _, text = gate(tmp_path, results, EXPECTED_REPORTS="")
    assert rc == 2 and "EXPECTED_REPORTS must list" in text


def test_duplicate_inventory_names_and_unexpected_report_fail(tmp_path):
    results = write_reports(tmp_path / "r", ["gitleaks.json", "semgrep.json"])
    assert gate(tmp_path, results, EXPECTED_REPORTS="gitleaks,gitleaks")[0] == 2
    rc, _, text = gate(tmp_path, results, EXPECTED_REPORTS="gitleaks")
    assert rc == 2 and "unexpected report semgrep.json" in text


def test_no_report_at_all_is_not_a_pass(tmp_path):
    empty = tmp_path / "r"
    empty.mkdir()
    rc, _, text = gate(tmp_path, empty)
    assert rc == 2 and "no scanner report" in text


def test_an_unreadable_report_is_not_a_pass(tmp_path):
    results = tmp_path / "r"
    results.mkdir()
    (results / "semgrep.json").write_text("{not json")
    assert gate(tmp_path, results)[0] == 2


def test_locations_are_relative_to_the_checkout(tmp_path):
    _, out, _ = gate(tmp_path, write_reports(tmp_path / "r", ["osv-scanner.json", "dependency-check.json"]))
    assert {f["location"] for f in out["findings"]} == {"requirements.txt", "lib/log4j-core-2.14.1.jar"}


# --- exceptions --------------------------------------------------------------


def entry(**kw):
    return {"id": "CVE-2020-14343", "reason": "not reachable", "owner": "team", "expires": "2026-12-31", **kw}


def test_an_exception_waives_a_finding_until_it_expires(tmp_path):
    results = write_reports(tmp_path / "r", ["trivy-fs.json"])
    _, out, _ = gate(tmp_path, results, {"exceptions": [entry()]})
    assert "CVE-2020-14343" in ids(out["waived"]) and "CVE-2020-14343" not in ids(out["blocking"])
    _, out, _ = gate(tmp_path, results, {"exceptions": [entry(expires="2026-10-07")]})
    assert "CVE-2020-14343" in ids(out["blocking"]), "an expired exception no longer applies"
    assert "Expired exceptions" in (tmp_path / "summary.md").read_text()


def test_an_exception_can_be_narrowed_by_tool_and_path_and_widened_by_glob(tmp_path):
    results = write_reports(tmp_path / "r", ["trivy-fs.json", "kics.json"])
    _, out, _ = gate(tmp_path, results, {"exceptions": [entry(tool="grype")]})
    assert "CVE-2020-14343" in ids(out["blocking"]), "the tool does not match"
    _, out, _ = gate(tmp_path, results, {"exceptions": [entry(path="other/*")]})
    assert "CVE-2020-14343" in ids(out["blocking"]), "the path does not match"
    _, out, _ = gate(tmp_path, results, {"exceptions": [entry(id="CVE-2020-*", tool="trivy", path="requirements*")]})
    assert "CVE-2020-14343" in ids(out["waived"])


@pytest.mark.parametrize("missing", ["id", "reason", "owner", "expires"])
def test_an_incomplete_exception_fails_the_gate(tmp_path, missing):
    bad = entry()
    del bad[missing]
    rc, _, text = gate(tmp_path, write_reports(tmp_path / "r", ["gitleaks.json"]), {"exceptions": [bad]})
    assert rc == 2 and missing in text


def test_an_exception_date_must_be_a_date(tmp_path):
    rc, _, _ = gate(tmp_path, write_reports(tmp_path / "r", ["gitleaks.json"]), {"exceptions": [entry(expires="soon")]})
    assert rc == 2


def test_this_repositorys_exceptions_file_is_valid():
    doc = yaml.safe_load((REPO / ".github" / "security-exceptions.yml").read_text())
    for e in doc.get("exceptions") or []:
        assert all(str(e.get(k, "")).strip() for k in ("id", "reason", "owner", "expires")), e


# --- the workflows around it -------------------------------------------------


def inlined_gate_script() -> str:
    doc = load(WORKFLOWS / "security-gate.yml")
    step = next(s for s in doc["jobs"]["gate"]["steps"] if s.get("name") == "Decide")
    match = re.search(r"<<'PY'\n(.*)\nPY\n?$", step["run"], re.S)
    assert match, "the Decide step must run the script from a <<'PY' heredoc"
    return match.group(1)


def test_gate_download_preserves_artifact_directories_for_duplicate_detection():
    steps = load(WORKFLOWS / "security-gate.yml")["jobs"]["gate"]["steps"]
    download = next(s for s in steps if s.get("name") == "Download the scan reports")
    assert download["with"]["merge-multiple"] is False


def test_the_inlined_gate_script_is_scripts_security_gate_py():
    """One source, one copy: the workflow cannot read the file, so a test holds them identical."""
    assert inlined_gate_script().strip() == SCRIPT.read_text().strip(), (
        "security-gate.yml's Decide step differs from scripts/security_gate.py; regenerate the inlined copy"
    )


@pytest.mark.parametrize("path", SCANS, ids=lambda p: p.name)
def test_every_scan_uploads_its_report_under_the_callers_name(path):
    uploads = [
        s for s in load(path)["jobs"]["scan"]["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    w = uploads[0]["with"]
    assert w["name"] == "${{ inputs.artifact-name }}"
    assert w["if-no-files-found"] == "error", "a scan that wrote no report must fail, not pass silently"
    assert uploads[0]["if"] == "always()"
    assert inputs_of(path)["artifact-name"]["default"] == path.stem


@pytest.mark.parametrize("path", SCANS, ids=lambda p: p.name)
def test_every_scanner_image_is_pinned_by_digest(path):
    for name, spec in inputs_of(path).items():
        if name.endswith("-image"):
            assert re.search(r"@sha256:[0-9a-f]{64}$", spec["default"]), f"{path.name}: {name} is not pinned by digest"


@pytest.mark.parametrize("path", SCANS, ids=lambda p: p.name)
def test_no_scan_fails_on_findings(path):
    """Report-only: the gate decides. A scanner's own fail switch would decide first and differently."""
    text = path.read_text()
    for forbidden in ("--exit-code 1", "--fail-on", "--error ", "--failOnCVSS", " --fail "):
        assert forbidden not in text, f"{path.name} makes the scanner fail on findings ({forbidden.strip()})"


@pytest.mark.parametrize("path", PROFILES, ids=lambda p: p.name)
def test_every_profile_ends_in_the_gate_over_every_other_job(path):
    doc = load(path)
    gate_job = doc["jobs"]["gate"]
    assert gate_job["name"] == "Security gate"
    assert gate_job["if"] == "always()", "the gate must judge a run whose scans failed"
    assert set(gate_job["needs"]) == set(doc["jobs"]) - {"gate"}
    assert gate_job["uses"].startswith("./.github/workflows/security-gate.yml")
    w = gate_job["with"]
    assert w["upstream-results"] == "${{ join(needs.*.result, ',') }}"
    assert "expected-reports" in w
    assert w["artifact-prefix"] == "${{ inputs.artifact-prefix }}"
    assert w["fail-on"] == "${{ inputs.fail-on }}"
    assert inputs_of(path)["fail-on"]["default"] == "CRITICAL,HIGH"


@pytest.mark.parametrize("path", PROFILES, ids=lambda p: p.name)
def test_every_profile_scan_reports_under_the_profiles_prefix(path):
    for name, job in load(path)["jobs"].items():
        if "scan-" not in str(job.get("uses", "")):
            continue
        assert job["with"]["artifact-name"].startswith("${{ inputs.artifact-prefix }}-"), f"{path.name}: {name}"


@pytest.mark.parametrize("path", PROFILES, ids=lambda p: p.name)
def test_profile_expected_inventory_covers_each_scanner_report(path):
    doc = load(path)
    expected = doc["jobs"]["gate"]["with"]["expected-reports"]
    for job in doc["jobs"].values():
        scanner = str(job.get("uses", ""))
        if "scan-" not in scanner:
            continue
        artifact = job["with"]["artifact-name"].split("}-", 1)[1]
        stems = ("trivy-image", "grype") if artifact == "image" else (artifact,)
        for stem in stems:
            assert stem in expected, f"{path.name}: {stem} missing from inventory"
    if path.name == "profile-pr-gate.yml":
        assert "needs.detect.outputs.iac == 'true'" in expected
        assert "needs.detect.outputs.docker == 'true'" in expected


def test_scan_app_minimum_declares_its_expected_report():
    job = load(WORKFLOWS / "scan-app.yml")["jobs"]["minimum-gate"]
    assert job["with"]["expected-reports"] == "trivy-fs"


def test_profile_prefixes_do_not_collide():
    """The gate downloads `<prefix>-*`; a prefix that starts another would pull in its reports."""
    prefixes = [inputs_of(p)["artifact-prefix"]["default"] for p in PROFILES]
    for a in prefixes:
        for b in prefixes:
            assert a == b or not b.startswith(a + "-"), f"{a} is a prefix of {b}"
    assert len(set(prefixes)) == len(prefixes)
