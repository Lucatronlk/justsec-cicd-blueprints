# Roadmap

The goal: one repository of centralized, reusable CI/CD building blocks.
A project of any type (Terraform/OpenTofu, Python, Node, Java, .NET, Go,
Bash, Helm/Kubernetes, containers) calls the scans, build, release and deploy
workflows defined here instead of writing its own, and every project gets the
same controls from one pinned reference.

How each phase is meant to be used, per application and per use case, is in
[USAGE.md](USAGE.md). Each item says what it is and where it stands. Move an item to *Done* with
the pull request that did it.

## Decisions

| Topic | Decision |
|---|---|
| Platform | GitHub Actions is the workflow platform |
| Runners | Every job runs on GitHub-hosted `ubuntu-24.04`, including fork PRs: free for public repositories, fresh machine per run, stock Docker/Python/`yq`. `Dockerfile.runner` covers a later move to self-hosted hardware. Pinned tools still verify their hashes |
| Gate policy | CRITICAL and HIGH fail the scan gate on every branch, feature branches included. MEDIUM and LOW are reported only. A verified secret fails. Scan-gate exceptions live in `.github/security-exceptions.yml`; separately ignored advisories belong in `baseline/risk-register.yaml`, each with owner and expiry |
| Languages | Terraform/OpenTofu, Python, Node, Java, .NET, Go, Bash, Helm/Kubernetes, containers |
| Deploy target | AWS over OIDC; no stored cloud credential |
| Home | `Lucatronlk/justsec-cicd-blueprints` |
| Dependency scanning | osv-scanner + Trivy by default, from the lock files |

## Done

| Item | Where |
|---|---|
| Language CI with a single `CI green` gate per workflow: Python, Bash, OpenTofu/Terraform | `python-ci.yml`, `bash-ci.yml`, `tofu-ci.yml` |
| Python package release (tag-verified PyPI Trusted Publishing); local container build, test and scan | `python-package-release.yml`, `container-release.yml` |
| Security workflow: CodeQL, gitleaks, dependency audit, dependency review, optional Snyk and Scorecard | `security.yml` |
| Secrets from Doppler over OIDC, fetched only on trusted refs | `.github/actions/doppler-secrets`, inlined in the workflows |
| Contract tests: SHA pins, least privilege, harden-runner, no script injection, every workflow run against a fixture | `tests/` |
| Repository baseline and audit | `BASELINE.md`, `scripts/audit_baseline.py` |
| Phase 1, centralized scans: seven report-only `scan-*.yml`, the `security-gate.yml` decision (CRITICAL/HIGH fail, exceptions with owner and expiry), six profiles, run against the fixture by `scans-self.yml` | `.github/workflows/scan-*.yml`, `security-gate.yml`, `profile-*.yml`, `scripts/security_gate.py`, `tests/test_security_gate.py` |

## Phase 1 follow-ups

- **Measure the scans' egress and move them to `block`.** They ship in
  `audit` with a best-effort list; the first runs' harden-runner summaries
  are what the `block` defaults are written from, as for every workflow here.
- **Automate scanner pin updates.** Tool versions and SHA-256s are workflow
  inputs, which Dependabot does not read. `pin-check.yml` now detects stale
  version pins weekly; automated version-plus-hash updates and image-digest
  tracking remain future work, with the same review/cooldown as action pins.
- **Cache the vulnerability databases** (Trivy, Grype) between runs to cut
  download time, read-only on pull requests.

## Phase 2: language CI

`node-ci.yml` (npm, pnpm, yarn), `java-ci.yml` (Maven, Gradle),
`dotnet-ci.yml`, `go-ci.yml`, `helm-ci.yml` (helm lint, kubeconform,
rendered-manifest scans). Each ends in `CI green`.

## Phase 3: release and deploy

- Restore container publication only after each platform's exact staged digest
  passes scan and tests, and the published manifest index references only those
  digests. Sign and attest the promoted index; until then `push: true` fails.
- `tofu-deploy.yml`: plan saved as an artifact, apply of exactly that plan
  after GitHub environment approval; AWS login over OIDC.
- `npm-package-release.yml` with npm provenance; Maven/NuGet publishing.
- `helm-deploy.yml` / Kubernetes deploy with environment protection.

## Phase 4: adoption and documentation

- `examples/`: one copy-paste caller set per project type.
- README and DESIGN updated for the scan layers and profiles.
- Complete scheduled baseline-audit coverage: configure a scoped admin-read
  audit credential for the repos in `baseline/repos.txt` and validate its
  permissions; the weekly workflow currently falls back to `GITHUB_TOKEN`
  and reports UNKNOWN for settings that token cannot read.

## Later

- Signed commits and tags required once every committer signs.
- Self-hosted capacity if hosted minutes or hardware stop fitting:
  `Dockerfile.runner` plus a label change, and the runner assertions in
  `tests/test_workflows.py` move with it.
- Consumer-side verification: a scheduled job that runs `cosign verify` and
  checks the SBOM attestation of every published image.
