"""Security gate: one decision over every scanner's report.

Scanners run report-only and upload their raw JSON; this reads all of them,
maps every finding to one severity scale, applies the caller's exceptions and
fails when a finding at a blocking severity is left. It is inlined into
.github/workflows/security-gate.yml (a reusable workflow cannot read a file
from the repository it lives in), and tests/test_security_gate.py holds the
inlined copy identical to this file.

Environment:
  RESULTS_DIR       directory holding the downloaded reports (searched recursively)
  FAIL_ON           comma-separated severities that block, e.g. "CRITICAL,HIGH"
  FAIL_ON_SECRETS   "true" blocks every secret finding whatever its severity
  EXCEPTIONS_JSON   optional path to the exceptions file converted to JSON
  UPSTREAM_RESULTS  optional comma/space-separated job results of the scan jobs
  EXPECTED_REPORTS   required comma-separated report basenames (without .json)
  CHECKOV_SEVERITY  severity for checkov findings that carry none (default MEDIUM)
  FINDINGS_OUT      optional path for the normalized findings JSON
  GITHUB_STEP_SUMMARY  optional path the Markdown summary is appended to
  TODAY             optional ISO date, for tests

Exit codes: 0 pass, 1 blocking findings, 2 the gate cannot judge (a scan job
failed, missing/duplicate/unreadable report or an invalid exception).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "ERROR": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "UNKNOWN": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
    "NOTE": "LOW",
    "NOTICE": "LOW",
    "STYLE": "LOW",
    "NEGLIGIBLE": "LOW",
    "TRACE": "LOW",
}


def sev(value, default: str = "MEDIUM") -> str:
    if value is None or str(value).strip() == "":
        return default
    return ALIASES.get(str(value).strip().upper(), default)


def cvss_sev(score) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    return "LOW" if s > 0 else None


# Absolute checkout paths (runner workspace, a container mount) are cut so a
# location reads the same in every report and an exception's `path` matches it.
WORKSPACE = re.compile(r"^(/home/runner/work/[^/]+/[^/]+/|/github/workspace/|/src/|/)")


def relative(location) -> str:
    location = str(location or "")
    root = os.environ.get("GITHUB_WORKSPACE", "")
    if root and location.startswith(root.rstrip("/") + "/"):
        return location[len(root.rstrip("/")) + 1 :]
    return WORKSPACE.sub("", location, count=1)


def finding(tool, kind, fid, severity, title, location):
    return {
        "tool": tool,
        "kind": kind,
        "id": str(fid),
        "severity": severity,
        "title": str(title or "")[:200],
        "location": relative(location),
    }


# --- one parser per tool, chosen by the report's file name -------------------


def parse_gitleaks(doc, tool):
    for f in doc or []:
        loc = f"{f.get('File', '')}:{f.get('StartLine', '')}"
        yield finding(tool, "secret", f.get("RuleID"), "HIGH", f.get("Description"), loc)


def parse_trufflehog(lines, tool):
    for f in lines:
        data = (f.get("SourceMetadata") or {}).get("Data") or {}
        src = next(iter(data.values()), {}) if data else {}
        loc = f"{src.get('file', '')}:{src.get('line', '')}"
        verified = bool(f.get("Verified"))
        title = f"{f.get('DetectorName')} ({'verified' if verified else 'unverified'})"
        yield finding(tool, "secret", f.get("DetectorName"), "CRITICAL" if verified else "MEDIUM", title, loc)


def parse_semgrep(doc, tool):
    for r in (doc or {}).get("results") or []:
        extra = r.get("extra") or {}
        impact = (extra.get("metadata") or {}).get("impact")
        severity = sev(impact) if impact else sev(extra.get("severity"))
        loc = f"{r.get('path', '')}:{(r.get('start') or {}).get('line', '')}"
        yield finding(tool, "code", r.get("check_id"), severity, extra.get("message"), loc)


def parse_trivy(doc, tool):
    for res in (doc or {}).get("Results") or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            title = f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or ''}"
            yield finding(tool, "vuln", v.get("VulnerabilityID"), sev(v.get("Severity")), title, target)
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine", "")
            fid = m.get("ID") or m.get("AVDID")
            yield finding(tool, "misconfig", fid, sev(m.get("Severity")), m.get("Title"), f"{target}:{line}")
        for s in res.get("Secrets") or []:
            loc = f"{target}:{s.get('StartLine', '')}"
            yield finding(tool, "secret", s.get("RuleID"), sev(s.get("Severity")), s.get("Title"), loc)


def parse_grype(doc, tool):
    for m in (doc or {}).get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        locs = a.get("locations") or [{}]
        title = f"{a.get('name')} {a.get('version')}"
        yield finding(tool, "vuln", v.get("id"), sev(v.get("severity")), title, locs[0].get("path", ""))


def parse_osv(doc, tool):
    for res in (doc or {}).get("results") or []:
        path = (res.get("source") or {}).get("path", "")
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            by_id = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            for g in p.get("groups") or []:
                ids = list(g.get("aliases") or []) + list(g.get("ids") or [])
                fid = next((i for i in ids if i.startswith("CVE-")), None) or next(
                    (i for i in ids if i.startswith("GHSA-")), ids[0] if ids else "unknown"
                )
                severity = cvss_sev(g.get("max_severity"))
                if severity is None:
                    for i in g.get("ids") or []:
                        db = (by_id.get(i) or {}).get("database_specific") or {}
                        if db.get("severity"):
                            severity = sev(db["severity"])
                            break
                title = f"{pkg.get('name')} {pkg.get('version')} ({pkg.get('ecosystem')})"
                yield finding(tool, "vuln", fid, severity or "MEDIUM", title, path)


def parse_checkov(doc, tool):
    default = sev(os.environ.get("CHECKOV_SEVERITY") or "MEDIUM")
    for part in doc if isinstance(doc, list) else [doc or {}]:
        for c in ((part.get("results") or {}).get("failed_checks")) or []:
            lines = c.get("file_line_range") or [""]
            loc = f"{c.get('file_path', '')}:{lines[0]}"
            yield finding(
                tool, "misconfig", c.get("check_id"), sev(c.get("severity"), default), c.get("check_name"), loc
            )


def parse_kics(doc, tool):
    for q in (doc or {}).get("queries") or []:
        for f in q.get("files") or [{}]:
            loc = f"{f.get('file_name', '')}:{f.get('line', '')}"
            yield finding(tool, "misconfig", q.get("query_id"), sev(q.get("severity")), q.get("query_name"), loc)


def parse_tflint(doc, tool):
    for i in (doc or {}).get("issues") or []:
        rule = i.get("rule") or {}
        rng = i.get("range") or {}
        loc = f"{rng.get('filename', '')}:{(rng.get('start') or {}).get('line', '')}"
        yield finding(tool, "lint", rule.get("name"), sev(rule.get("severity")), i.get("message"), loc)


def parse_hadolint(doc, tool):
    for i in doc or []:
        loc = f"{i.get('file', '')}:{i.get('line', '')}"
        yield finding(tool, "lint", i.get("code"), sev(i.get("level")), i.get("message"), loc)


def parse_dependency_check(doc, tool):
    for d in (doc or {}).get("dependencies") or []:
        for v in d.get("vulnerabilities") or []:
            severity = sev(v.get("severity"))
            title = f"{d.get('fileName')}: {v.get('name')}"
            yield finding(tool, "vuln", v.get("name"), severity, title, d.get("filePath") or d.get("fileName"))


PARSERS = [
    ("dependency-check", parse_dependency_check),
    ("osv-scanner", parse_osv),
    ("trufflehog", parse_trufflehog),
    ("gitleaks", parse_gitleaks),
    ("hadolint", parse_hadolint),
    ("semgrep", parse_semgrep),
    ("checkov", parse_checkov),
    ("tflint", parse_tflint),
    ("trivy", parse_trivy),
    ("grype", parse_grype),
    ("kics", parse_kics),
]


def load_report(path: Path, prefix: str):
    text = path.read_text(encoding="utf-8")
    if prefix == "trufflehog":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text) if text.strip() else None


def expected_names(raw: str):
    """Names are exact report stems, not scanner prefixes or artifact names."""
    names = [name.strip() for name in raw.split(",")]
    if not raw.strip() or any(not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) for name in names):
        return [], ["EXPECTED_REPORTS must list comma-separated report names (without .json)"]
    if len(names) != len(set(names)):
        return [], ["EXPECTED_REPORTS contains duplicate names"]
    # Trivy is emitted with a mode suffix; other report stems equal parser names.
    allowed = ({p for p, _ in PARSERS} - {"trivy"}) | {"trivy-fs", "trivy-config", "trivy-image"}
    unknown = sorted(set(names) - allowed)
    if unknown:
        return [], [f"unknown expected report name: {', '.join(unknown)}"]
    return names, []


def collect(results_dir: Path, expected: list[str]):
    findings, reports, errors = [], [], []
    seen = {}
    for path in sorted(results_dir.rglob("*.json")):
        name = path.name.lower()
        match = next(((p, fn) for p, fn in PARSERS if name.startswith(p)), None)
        if not match:
            continue
        prefix, parse = match
        seen.setdefault(name, []).append(path)
        tool = path.stem
        try:
            doc = load_report(path, prefix)
            findings.extend(parse(doc, tool))
            reports.append(tool)
        except (OSError, UnicodeError, ValueError, AttributeError, TypeError) as exc:
            errors.append(f"unreadable report {path.name}: {exc}")
    for name in expected:
        if name + ".json" not in seen:
            errors.append(f"missing expected report {name}.json")
    for name, paths in seen.items():
        if len(paths) > 1:
            errors.append(f"duplicate report {name} ({len(paths)} copies)")
        if expected and name not in {item + ".json" for item in expected}:
            errors.append(f"unexpected report {name}")
    return findings, reports, errors


# --- exceptions --------------------------------------------------------------

REQUIRED = ("id", "reason", "owner", "expires")


def load_exceptions(path: str | None, today: dt.date):
    """Returns (active, expired, errors). An entry missing a field is an error, not ignored."""
    if not path or not Path(path).is_file():
        return [], [], []
    text = Path(path).read_text(encoding="utf-8").strip()
    doc = json.loads(text) if text and text != "null" else {}
    entries = (doc or {}).get("exceptions") or []
    active, expired, errors = [], [], []
    for n, e in enumerate(entries, start=1):
        missing = [k for k in REQUIRED if not str((e or {}).get(k, "")).strip()]
        if missing:
            errors.append(f"exception #{n}: missing {', '.join(missing)}")
            continue
        try:
            until = dt.date.fromisoformat(str(e["expires"]))
        except ValueError:
            errors.append(f"exception #{n} ({e['id']}): expires is not a YYYY-MM-DD date")
            continue
        (active if until >= today else expired).append(e)
    return active, expired, errors


def excepted(f, entry) -> bool:
    if not fnmatch.fnmatchcase(f["id"], str(entry["id"])):
        return False
    if entry.get("tool") and not f["tool"].startswith(str(entry["tool"])):
        return False
    if entry.get("path") and not fnmatch.fnmatchcase(f["location"], str(entry["path"])):
        return False
    return True


# --- decision and report -----------------------------------------------------


def decide(findings, fail_on, fail_on_secrets, active):
    blocking, waived = [], []
    for f in findings:
        rule = next((e for e in active if excepted(f, e)), None)
        if rule is not None:
            waived.append({**f, "exception_owner": rule["owner"], "exception_expires": str(rule["expires"])})
            continue
        if f["severity"] in fail_on or (fail_on_secrets and f["kind"] == "secret"):
            blocking.append(f)
    return blocking, waived


def summary(findings, reports, blocking, waived, expired, fail_on, problems) -> str:
    out = ["## Security gate", ""]
    verdict = "FAIL" if blocking or problems else "PASS"
    blocks = ", ".join(sorted(fail_on)) or "none"
    out.append(f"**{verdict}**: blocking severities {blocks}; {len(findings)} finding(s) in {len(reports)} report(s).")
    out += ["", "| Report | " + " | ".join(SEVERITIES) + " |", "|---|" + "---|" * len(SEVERITIES)]
    for tool in sorted(set(reports)):
        counts = [sum(1 for f in findings if f["tool"] == tool and f["severity"] == s) for s in SEVERITIES]
        out.append(f"| {tool} | " + " | ".join(str(c) for c in counts) + " |")
    for p in problems:
        out.append(f"\n:x: {p}")
    if blocking:
        out += [
            "",
            f"### Blocking ({len(blocking)})",
            "",
            "| Severity | Tool | ID | Location | Title |",
            "|---|---|---|---|---|",
        ]
        for f in blocking[:100]:
            title = f["title"].replace("|", "\\|")
            out.append(f"| {f['severity']} | {f['tool']} | `{f['id']}` | `{f['location']}` | {title} |")
        if len(blocking) > 100:
            out.append(f"\n... and {len(blocking) - 100} more; see the findings artifact.")
    if waived:
        out += ["", f"### Waived by an exception ({len(waived)})", ""]
        for f in waived[:50]:
            who = f"owner {f['exception_owner']}, expires {f['exception_expires']}"
            out.append(f"- `{f['id']}` ({f['tool']}, {f['severity']}) {who}")
    if expired:
        out += ["", "### Expired exceptions (no longer applied)", ""]
        for e in expired:
            out.append(f"- `{e['id']}` owner {e['owner']}, expired {e['expires']}")
    return "\n".join(out) + "\n"


def main() -> int:
    results_dir = Path(os.environ.get("RESULTS_DIR", "results"))
    fail_on = {sev(s) for s in os.environ.get("FAIL_ON", "CRITICAL,HIGH").replace(" ", ",").split(",") if s.strip()}
    if os.environ.get("FAIL_ON", "").strip().lower() == "none":
        fail_on = set()
    fail_on_secrets = os.environ.get("FAIL_ON_SECRETS", "false").strip().lower() == "true"
    today = dt.date.fromisoformat(os.environ["TODAY"]) if os.environ.get("TODAY") else dt.date.today()

    problems = []
    upstream = os.environ.get("UPSTREAM_RESULTS", "").replace(",", " ").split()
    bad = sorted({r for r in upstream if r not in ("success", "skipped")})
    if bad:
        problems.append(
            f"a scan job ended in {', '.join(bad)}; its report is missing or partial, so the gate cannot pass"
        )

    expected, inventory_errors = expected_names(os.environ.get("EXPECTED_REPORTS", ""))
    problems += inventory_errors
    findings, reports, errors = collect(results_dir, expected) if results_dir.is_dir() else ([], [], [])
    problems += errors
    if not results_dir.is_dir():
        problems += [f"missing expected report {name}.json" for name in expected]
    if not reports and not bad:
        problems.append(f"no scanner report found under {results_dir}")

    try:
        active, expired, exc_errors = load_exceptions(os.environ.get("EXCEPTIONS_JSON"), today)
    except ValueError as exc:
        active, expired, exc_errors = [], [], [f"exceptions file is not valid: {exc}"]
    problems += exc_errors

    blocking, waived = decide(findings, fail_on, fail_on_secrets, active)
    text = summary(findings, reports, blocking, waived, expired, fail_on, problems)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text)
    if os.environ.get("FINDINGS_OUT"):
        Path(os.environ["FINDINGS_OUT"]).write_text(
            json.dumps({"findings": findings, "blocking": blocking, "waived": waived}, indent=2), encoding="utf-8"
        )
    for f in blocking[:50]:
        print(f"::error title={f['tool']} {f['severity']}::{f['id']} at {f['location']}")
    if problems:
        return 2
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
