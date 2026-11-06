<h1 align="center"><img src="assets/justsec/JustSec%20CI_CD%20blueprints%20gradient%20wordmark.png" alt="justsec-cicd-blueprints" width="100%"></h1>

<p align="center"><strong>No shortcuts — Just security.</strong></p>

<p align="center">MIT-licensed code · GitHub-hosted ubuntu-24.04 · CRITICAL/HIGH gate · Commit-SHA pins</p>

Reusable, security-hardened GitHub Actions workflows: a repository pins one
commit SHA and inherits its scanners, their versions and one pass/fail policy
instead of writing CI itself. The scans are report-only, a single gate judges
them, and CRITICAL and HIGH findings fail the pull request.

Public repository; software is MIT-licensed, artwork is not. GitHub Actions jobs
use GitHub-hosted `ubuntu-24.04`, so a scan caller needs no runner, image or
secret. Optional publish workflows can require registry credentials.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/star.svg" width="22" height="22" alt=""> What you get

<table>
  <tr>
    <td align="center" valign="top" width="33%"><img src="assets/icons/radar.svg" width="28" height="28" alt=""><br><strong>Scanners, pinned</strong><br><sub>Secret, code, dependency and infrastructure scans with pinned tools and pinned container digests, in <code>gitleaks</code>, <code>semgrep</code>, <code>trivy</code>, <code>trivy-config</code>, <code>osv-scanner</code>, <code>checkov</code> and <code>hadolint</code>.</sub></td>
    <td align="center" valign="top" width="33%"><img src="assets/icons/shield.svg" width="28" height="28" alt=""><br><strong>One decision</strong><br><sub><code>security-gate.yml</code> maps every report to one severity scale, applies the caller's exceptions and fails on CRITICAL/HIGH.</sub></td>
    <td align="center" valign="top" width="33%"><img src="assets/icons/grid.svg" width="28" height="28" alt=""><br><strong>Profiles that fit</strong><br><sub>Detection picks only what applies: <code>profile-pr-gate.yml</code> per change, <code>profile-full.yml</code> weekly, plus <code>dev</code>, <code>secrets</code>, <code>tf</code> and <code>image</code>.</sub></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="33%"><img src="assets/icons/build-code.svg" width="28" height="28" alt=""><br><strong>CI for real stacks</strong><br><sub><code>python-ci.yml</code>, <code>bash-ci.yml</code>, <code>tofu-ci.yml</code>.</sub></td>
    <td align="center" valign="top" width="33%"><img src="assets/icons/rocket.svg" width="28" height="28" alt=""><br><strong>Release workflows</strong><br><sub><code>container-release.yml</code> builds/tests/scans locally; multi-arch publication is currently disabled pending digest-bound verification. <code>python-package-release.yml</code> publishes from a verified tag via PyPI Trusted Publishing with PEP 740 attestations.</sub></td>
    <td align="center" valign="top" width="33%"><img src="assets/icons/layers.svg" width="28" height="28" alt=""><br><strong>Supply chain</strong><br><sub>Everything pinned by SHA, <code>harden-runner</code> on every job, least privilege per job, dependency review and Scorecard in <code>security.yml</code>, Dependabot bumps queued by <code>dependabot-auto-merge.yml</code>.</sub></td>
  </tr>
</table>

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/sparkle.svg" width="22" height="22" alt=""> Quick start

`.github/workflows/security.yml` in the calling repository:

```yaml
name: Security
on:
  pull_request:
  push:
jobs:
  security:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-pr-gate.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
```

The job detects what the repository contains, runs the matching scans and
fails on CRITICAL or HIGH. Require `security / Security gate / Security gate`
in branch protection.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/shield.svg" width="22" height="22" alt=""> How the gate decides

- CRITICAL and HIGH fail; MEDIUM and LOW are reported.
- Every scanner runs report-only; the gate is the only thing that decides, so
  one tool cannot fail a build by itself.
- An advisory that cannot be fixed yet is an exception in
  `.github/security-exceptions.yml` with an id, a reason, an owner and an
  expiry date. Expired exceptions stop applying on their own.
- Each profile ends in `security-gate.yml`, `if: always()`. Its required
  `expected-reports` list and upstream job results fail closed on missing scan
  reports and crashed scans.

> [!NOTE]
> The gate is the only failure source on purpose. Adding `--exit-code`-style
> behaviour to an individual scanner duplicates the decision and lets one tool's
> severity model override the policy.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/grid.svg" width="22" height="22" alt=""> Workflows

> [!IMPORTANT]
> Pin by the **commit** SHA of a release tag and keep the tag in the comment;
> Dependabot moves the pin, and `ref-version-mismatch` fails a caller whose
> comment and SHA disagree.

| Profile | Use |
|---|---|
| `profile-pr-gate.yml` | Every pull request and branch push |
| `profile-full.yml` | Weekly on the default branch; everything, including the image when named |
| `profile-dev.yml` | gitleaks, Semgrep, Trivy and hadolint, then the gate |
| `profile-secrets.yml` | Full-history `gitleaks` only |
| `profile-tf.yml` | Terraform/OpenTofu: dev scans plus `trivy-config` and `checkov` |
| `profile-image.yml` | A built image through `trivy` and `grype` |

Individual scanners can be called too: `scan-gitleaks.yml`,
`scan-semgrep.yml`, `scan-trivy.yml`, `scan-osv-scanner.yml`,
`scan-checkov.yml`, `scan-hadolint.yml`, `scan-image.yml`. `scan-app.yml`
remains as a compatibility caller for the profiles.

| CI | Use |
|---|---|
| `python-ci.yml` | ruff, pytest matrix, coverage, image build, `CI green` |
| `bash-ci.yml` | shellcheck, shfmt, optional tests and config lint |
| `tofu-ci.yml` | fmt, validate without a backend, tflint, config scan; plan on the default branch |

| Release | Use |
|---|---|
| `container-release.yml` | Build, test, scan locally; `push: true` currently fails closed before publication pending digest-bound per-platform verification |
| `python-package-release.yml` | Build, `twine check`, smoke test, publish to PyPI and the GitHub release |
| `security.yml` | CodeQL, dependency review, Scorecard, optional Snyk |

`dependabot-auto-merge.yml` queues a Dependabot bump to merge once the required
checks pass, up to a size you choose.

Every workflow documents its inputs at the top of its file and in
[docs/USAGE.md](docs/USAGE.md), which also holds a complete caller file for
each kind of application.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/compass.svg" width="22" height="22" alt=""> Example callers

`examples/workflows/` holds archived caller files: a Python service, a
container app, a Terraform stack and the legacy combined pipeline. Copy the
one that resembles your repository and delete the rest.

`apps/` holds the samples this repository's own CI runs the reusable workflows
against, so a change is exercised before a caller pins it.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/server.svg" width="22" height="22" alt=""> Runners

All jobs use GitHub-hosted `ubuntu-24.04`, for every event including fork pull
requests. A fork PR runs on a disposable machine with a read-only token and no
secrets. `Dockerfile.runner` is an optional image if you later move jobs to
your own hardware.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/key.svg" width="22" height="22" alt=""> Security posture

- Third-party actions and scanner images pinned by commit SHA or digest.
- `permissions:` declared per job, `contents: read` at the top of every
  workflow.
- `harden-runner` first on every job, `audit` by default, `block` where the
  endpoint list is measured.
- No secret is required for scan profiles; they use `GITHUB_TOKEN`. Optional
  Doppler fetching uses `.github/actions/doppler-secrets`: OIDC when an identity
  is set, or a service token otherwise. Its `trusted-refs-only` default limits
  fetching to the default branch, tags and schedules. Callers that turn that
  restriction off can expose CI secrets to pull-request code; do not do so
  without a separate threat review.
- `docs/DESIGN.md` explains the rules; `BASELINE.md` lists the repository
  settings that YAML cannot set.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/blocks.svg" width="22" height="22" alt=""> Input reference

Every workflow documents its inputs at the top of its own file; the names
are repeated here so a caller can find them in one place.

| Workflow | Inputs |
|---|---|
| `bash-ci.yml` | `allowed-endpoints`, `config-lint-command`, `config-lint-install-command`, `config-lint-python-version`, `distro-egress-policy`, `distro-runners`, `distro-setup-command`, `distros`, `egress-policy`, `extra-allowed-endpoints`, `paths`, `runners`, `shellcheck-args`, `shellcheck-continue-on-error`, `shellcheck-severity`, `shellcheck-sha256`, `shellcheck-version`, `shfmt`, `shfmt-args`, `shfmt-continue-on-error`, `shfmt-sha256`, `shfmt-version`, `test-command`, `test-install-command`, `timeout-minutes`, `workflow-lint`, `zizmor-persona` |
| `container-release.yml` | `allowed-endpoints`, `context`, `docker-test-command`, `dockerfile`, `dockerhub`, `dockerhub-repository`, `doppler-config`, `doppler-identity-id`, `doppler-project`, `doppler-trusted-refs-only`, `egress-policy`, `extra-allowed-endpoints`, `image-name`, `platforms`, `provenance`, `push`, `sbom`, `sign`, `tags`, `timeout-minutes`, `trivy`, `trivy-exit-code`, `trivy-severity` |
| `dependabot-auto-merge.yml` | `allowed-endpoints`, `egress-policy`, `extra-allowed-endpoints`, `max-update-type`, `merge-method`, `timeout-minutes` |
| `dev-security-scan.yml` | `artifact-prefix`, `working-directory` |
| `image-security-scan.yml` | `artifact-prefix`, `docker-context`, `dockerfile` |
| `pr-security-gate.yml` | `artifact-prefix`, `working-directory` |
| `profile-dev.yml` | `artifact-prefix`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `semgrep-config`, `upload-sarif`, `working-directory` |
| `profile-full.yml` | `artifact-prefix`, `checkov-default-severity`, `docker-context`, `dockerfile`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `image`, `semgrep-config`, `upload-sarif`, `working-directory` |
| `profile-image.yml` | `artifact-prefix`, `docker-context`, `dockerfile`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `ignore-unfixed`, `image`, `upload-sarif` |
| `profile-pr-gate.yml` | `allowed-endpoints`, `artifact-prefix`, `checkov-default-severity`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `semgrep-config`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `profile-secrets.yml` | `artifact-prefix`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `upload-sarif` |
| `profile-tf.yml` | `artifact-prefix`, `checkov-default-severity`, `egress-policy`, `exceptions-file`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `semgrep-config`, `upload-sarif`, `working-directory` |
| `python-ci.yml` | `allowed-endpoints`, `codecov`, `coverage-file`, `coverage-python-version`, `distro-egress-policy`, `distro-runners`, `distro-setup-command`, `distros`, `docker-build`, `docker-context`, `docker-test-command`, `dockerfile`, `doppler-config`, `doppler-identity-id`, `doppler-project`, `doppler-trusted-refs-only`, `egress-policy`, `extra-allowed-endpoints`, `install-command`, `lint-command`, `lint-continue-on-error`, `lint-install-command`, `lint-python-version`, `python-versions`, `runners`, `smoke-command`, `smoke-install-command`, `test-command`, `timeout-minutes`, `workflow-lint`, `zizmor-persona` |
| `python-package-release.yml` | `allowed-endpoints`, `attest`, `build-command`, `build-install-command`, `egress-policy`, `extra-allowed-endpoints`, `github-release`, `package-directory`, `publish`, `pypi`, `pypi-environment`, `python-version`, `release-notes-command`, `release-title`, `smoke-command`, `tag-prefix`, `timeout-minutes`, `verify-command` |
| `scan-app.yml` | `app`, `artifact-prefix`, `context`, `depth`, `dockerfile`, `path` |
| `scan-checkov.yml` | `allowed-endpoints`, `artifact-name`, `checkov-args`, `checkov-frameworks`, `checkov-image`, `checkov-skip-paths`, `egress-policy`, `extra-allowed-endpoints`, `retention-days`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `scan-gitleaks.yml` | `allowed-endpoints`, `artifact-name`, `egress-policy`, `extra-allowed-endpoints`, `gitleaks-args`, `gitleaks-mode`, `gitleaks-sha256`, `gitleaks-version`, `retention-days`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `scan-hadolint.yml` | `allowed-endpoints`, `artifact-name`, `dockerfiles`, `egress-policy`, `extra-allowed-endpoints`, `hadolint-args`, `hadolint-sha256`, `hadolint-version`, `retention-days`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `scan-image.yml` | `allowed-endpoints`, `artifact-name`, `docker-context`, `dockerfile`, `egress-policy`, `extra-allowed-endpoints`, `grype-sha256`, `grype-version`, `ignore-unfixed`, `image`, `retention-days`, `timeout-minutes`, `trivy-sha256`, `trivy-version`, `upload-sarif` |
| `scan-osv-scanner.yml` | `allowed-endpoints`, `artifact-name`, `egress-policy`, `extra-allowed-endpoints`, `osv-scanner-args`, `osv-scanner-sha256`, `osv-scanner-version`, `retention-days`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `scan-semgrep.yml` | `allowed-endpoints`, `artifact-name`, `egress-policy`, `extra-allowed-endpoints`, `retention-days`, `semgrep-args`, `semgrep-config`, `semgrep-image`, `timeout-minutes`, `upload-sarif`, `working-directory` |
| `scan-trivy.yml` | `allowed-endpoints`, `artifact-name`, `egress-policy`, `extra-allowed-endpoints`, `retention-days`, `timeout-minutes`, `trivy-args`, `trivy-ignore-unfixed`, `trivy-mode`, `trivy-scanners`, `trivy-sha256`, `trivy-version`, `upload-sarif`, `working-directory` |
| `secrets-security-scans.yml` | `artifact-prefix` |
| `security-gate.yml` | `allowed-endpoints`, `artifact-prefix`, `checkov-default-severity`, `egress-policy`, `exceptions-file`, `expected-reports`, `extra-allowed-endpoints`, `fail-on`, `fail-on-secrets`, `retention-days`, `timeout-minutes`, `upstream-results` |
| `security.yml` | `allowed-endpoints`, `audit-command`, `audit-continue-on-error`, `audit-install-command`, `codeql`, `codeql-config`, `codeql-languages`, `codeql-queries`, `dependency-review`, `dependency-review-allow-ghsas`, `dependency-review-severity`, `doppler-config`, `doppler-identity-id`, `doppler-project`, `doppler-trusted-refs-only`, `egress-policy`, `extra-allowed-endpoints`, `gitleaks`, `pip-audit-continue-on-error`, `pip-audit-extra-args`, `pip-audit-requirements`, `python-version`, `scorecard`, `snyk`, `timeout-minutes` |
| `tf-security-scans.yml` | `artifact-prefix`, `working-directory` |
| `tofu-ci.yml` | `allowed-endpoints`, `binary`, `directories`, `doppler-config`, `doppler-identity-id`, `doppler-project`, `doppler-trusted-refs-only`, `egress-policy`, `extra-allowed-endpoints`, `plan-command`, `tflint`, `tflint-sha256`, `tflint-version`, `timeout-minutes`, `tofu-sha256`, `tofu-version`, `trivy`, `trivy-exit-code`, `trivy-severity`, `workflow-lint`, `zizmor-persona` |

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/terminal.svg" width="22" height="22" alt=""> Running the workflows locally

`act` runs them in Docker. `.actrc` maps the `runs-on` labels, so no flags are
needed; pull the image once.

```bash
docker pull catthehacker/ubuntu:act-latest
act -l
act -W .github/workflows/ci-repo.yml -j test
make act-test
```

`act` proves the steps, not the platform: it does not enforce `permissions:` or
the egress policy. Every step anchors its paths to `$GITHUB_WORKSPACE` so a
runner that starts a job elsewhere still works.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/build-code.svg" width="22" height="22" alt=""> This repository's own CI

`ci-repo.yml` lints the workflows (actionlint, zizmor) and runs the contract
tests in `tests/` — pins, least privilege, injection, gate policy, profile
wiring. `.github/workflows/ci-*.yml` run the sample apps through the reusable
workflows.

`make ci` runs the local Docker Compose smoke test instead.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/truck.svg" width="22" height="22" alt=""> Publishing this repository

Before the first push to a public remote: confirm rights to the artwork (see
[assets/NOTICE.md](assets/NOTICE.md)), allow GitHub-owned actions plus
`baseline/selected-actions.json`, require approval for outside collaborators,
keep `GITHUB_TOKEN` read-only, protect `main` with the `Security green` and
`Security gate` checks, and turn on secret scanning and push protection. Tag
`v0.1.0` only after a green run, and give callers the tag's commit SHA.
Container publication (`push: true`) is disabled until published platform
digests are scanned/tested and the exact verified manifest is promoted.

<p align="center"><img src="assets/brand/section-divider.svg" width="100%" height="6" alt=""></p>

## <img src="assets/icons/doc.svg" width="22" height="22" alt=""> Licence

MIT, with the provenance notes in [LICENSE](LICENSE). Report vulnerabilities
through [SECURITY.md](SECURITY.md).

Artwork in `assets/` is not covered by the code licence; see
[assets/NOTICE.md](assets/NOTICE.md) for reuse terms.
