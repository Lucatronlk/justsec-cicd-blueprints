# Usage guide: phases, applications and use cases

How this repository is meant to be used: what each phase delivers and how a
project consumes it, then the complete set of caller files per kind of
application, then the everyday situations (a new repository, a finding, a
leaked secret, a release, a deploy) and what to do in each.

Status markers used throughout:

- **Available**: the workflow exists, is tested in this repository's own CI
  and can be pinned today.
- **Planned**: on the [roadmap](ROADMAP.md); the shape is described so
  callers can plan for it, but names and inputs may still change. Do not
  pin a planned workflow; it does not exist yet.

Every snippet pins `@<sha> # vX.Y.Z`: a full commit SHA of a release tag of
`Lucatronlk/justsec-cicd-blueprints`, with the tag in the comment, which
Dependabot then moves (see [Calling the workflows](../README.md#calling-the-workflows)).

## Contents

1. [The model in one page](#1-the-model-in-one-page)
2. [Phase by phase](#2-phase-by-phase)
3. [By application](#3-by-application)
4. [Use cases](#4-use-cases)
5. [Rolling it out](#5-rolling-it-out)

---

## 1. The model in one page

A calling repository holds a few short workflow files that say only what is
specific to it. Everything else (the tools, their versions, the
permissions, the policy) lives here and is pinned by commit.

```
calling repository                         secure-cicd-blueprints
.github/workflows/                         .github/workflows/
  security.yml  ── uses ──────────────────▶ profile-pr-gate.yml ─▶ scan-*.yml ─▶ security-gate.yml
  ci.yml        ── uses ──────────────────▶ <lang>-ci.yml           (ends in "CI green")
  release.yml   ── uses ──────────────────▶ *-release.yml           (sign, SBOM, provenance)
  deploy.yml    ── uses ──────────────────▶ deploy-*.yml            (Planned: Phase 3)
.github/security-exceptions.yml  ◀── read by the gate
```

Four kinds of workflow, one question each:

| Kind | Question it answers | Required check in branch protection |
|---|---|---|
| Security (`profile-*.yml`) | Is this change safe to merge? | `<job> / Security gate / Security gate` |
| CI (`<lang>-ci.yml`) | Does it build, lint and pass its tests? | `<job> / CI green` |
| Release (`*-release.yml`) | Is what we publish the thing we built, signed and described? | none (runs on tags/main) |
| Deploy (`deploy-*.yml`, Planned) | Does exactly the reviewed change reach the environment, with approval? | none (environment protection rules gate it) |

Rules every one of them follows, so a caller never has to: actions pinned
by SHA, tools pinned by version and SHA-256, images by digest; `contents:
read` unless a job needs more; no secret on a pull request; harden-runner
egress control in every job; nothing from a branch name or PR title ever
interpolated into a shell.

---

## 2. Phase by phase

### Foundation (done): language CI, releases, Doppler, baseline

**Available.** What existed before the scan family and stays the base:

| Workflow | Use it for |
|---|---|
| `python-ci.yml` | Python: ruff, pytest matrix, coverage, smoke test, single-arch image build |
| `bash-ci.yml` | Shell scripts in any repository: shellcheck, shfmt, tests, yamllint/ansible-lint |
| `tofu-ci.yml` | Terraform/OpenTofu: fmt, validate, tflint, Trivy config; plan on the default branch |
| `container-release.yml` | Any Dockerfile: build, test, Trivy locally; publication is disabled until digest-bound multi-platform verification is implemented |
| `python-package-release.yml` | PyPI via Trusted Publishing plus a GitHub release |
| `security.yml` | CodeQL, dependency review on PRs, OpenSSF Scorecard, optional Snyk |
| `dependabot-auto-merge.yml` | Merge patch/minor Dependabot bumps once checks pass |

How to use it: one caller job per language (`ci:`, `shell:`, `tofu:`), each
required by its `CI green` check; secrets, where a job needs any, come from
Doppler over OIDC (see [Doppler setup](../README.md#doppler-setup)), and
[BASELINE.md](../BASELINE.md) lists the repository settings to apply.

### Phase 1: centralized security scans

**Available.** Seven report-only scanners, one gate, six profiles.

How a project uses it:

1. **Add one security workflow that calls `profile-pr-gate.yml`** on
   `pull_request` and `push` (all branches). It detects what the repository
   holds and runs what applies. Require its gate in branch protection.
2. **Add a weekly `profile-full.yml` run** on the default branch: everything,
   including the image.
3. **Add a specialised profile where it adds depth:** `profile-tf.yml` for an
   infrastructure directory, `profile-image.yml` before an image is pushed.
4. **Keep `security.yml` for what the profiles do not do:** CodeQL,
   dependency review and Scorecard. Pass `gitleaks: false` to it, since the
   profiles already scan secrets.
5. **Handle findings through the code or `.github/security-exceptions.yml`**,
   never by turning the gate off ([use case 4.4](#44-a-finding-blocks-a-pull-request)).

Which profile, when:

| Trigger | Profile | Why |
|---|---|---|
| `pull_request`, `push` to any branch | `profile-pr-gate.yml` | The required check; CRITICAL/HIGH fail even on feature branches |
| Developer wants fast feedback on a branch | `profile-dev.yml` | A smaller set, minutes not tens of minutes |
| `push` to main, weekly schedule | `profile-secrets.yml` | Full-history secret scan with live verification |
| Changes under an IaC directory | `profile-tf.yml` | Four IaC engines on that directory |
| Before `container-release.yml` pushes | `profile-image.yml` | The built image, Trivy and Grype |
| Weekly schedule, main | `profile-full.yml` | Everything; catches CVEs published since the code last changed |

### Phase 2: language CI (Planned)

One CI workflow per remaining language, the same shape as `python-ci.yml`:
lint, build, test (the test job holds no token), an optional container
build, workflow lint, and a final `CI green` job that needs every other one.

| Planned workflow | Intended contents | Until it exists |
|---|---|---|
| `node-ci.yml` | npm / pnpm / yarn detected from the lock file; `npm ci --ignore-scripts` style installs; lint, test, build commands as inputs; Node version matrix | Run your own CI job; use Phase 1 for security (osv-scanner reads `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) |
| `java-ci.yml` | Maven or Gradle (wrapper verified), JDK matrix, test reports, build cache read-only on PRs | Your own CI; osv-scanner in Phase 1 reads the manifests |
| `dotnet-ci.yml` | `dotnet restore --locked-mode`, build, test, SDK matrix | Your own CI; osv-scanner reads `packages.lock.json` |
| `go-ci.yml` | `go vet`, golangci-lint pinned by hash, `go test -race`, govulncheck | Your own CI; osv-scanner reads `go.mod` |
| `helm-ci.yml` | `helm lint`, render, kubeconform against the cluster version, then the rendered manifests through Trivy config and Checkov | `profile-pr-gate.yml` already scans charts as IaC |

How it will be used: exactly like `python-ci.yml`, as one more caller job
whose `CI green` is required, beside the security profile.

### Phase 3: release and deploy (Planned)

| Planned workflow | Intended flow |
|---|---|
| `tofu-deploy.yml` | `plan` on the pull request or main, the plan file uploaded as an artifact and summarised; `apply` of **that same plan file** in a job bound to a GitHub Environment (`dev`, `stage`, `prod`) with required reviewers. AWS login over OIDC using `configure-aws-credentials` with an IAM role per environment; no stored cloud secret |
| `npm-package-release.yml` | Build once, `npm publish --provenance` over the job's OIDC identity, GitHub release with checksums |
| `maven-release.yml`, `nuget-release.yml` | Publish to the package registry with checksums, signatures and provenance |
| `helm-deploy.yml` | `helm upgrade --install` of a chart version pinned by digest into an environment-protected namespace, with a rollback on a failed rollout |

How it will be used: a `deploy.yml` in the calling repository triggers on
main (and manually); each environment is a job calling the deploy workflow
with `environment: dev|stage|prod`; GitHub Environment protection holds the
approval and the deployment branch rule, and the cloud trust policy accepts
only that repository, environment and workflow.

Until then: `container-release.yml` and `python-package-release.yml` cover
publishing; deployment stays in the project's own workflow.

### Phase 4: adoption and documentation (Planned)

- `examples/<type>/`: the files in [section 3](#3-by-application), ready to
  copy.
- `scripts/new-repo.sh` extended to write the security caller as well as CI.
- Baseline audit scheduling is implemented in `.github/workflows/baseline-audit.yml`;
  full cross-repository coverage still requires an admin-read audit token.

---

## 3. By application

Each subsection is the full set of workflow files for that kind of
repository: what to copy today (**Available**) and what will replace a
hand-written part later (**Planned**). The security file is the same for
every application; it is written out once here and referred to below.

### 3.0 The security file every repository has

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
  push:                      # every branch: CRITICAL/HIGH fail on feature branches too
  schedule:
    - cron: '0 5 * * 1'
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  security:
    if: github.event_name != 'schedule'
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-pr-gate.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write

  full:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-full.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
    # with: (per application, below)

  codeql:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/security.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write
    with:
      gitleaks: false                  # the profiles scan secrets
      codeql-languages: actions        # plus the application's languages, below
      pip-audit-requirements: ""       # osv-scanner covers dependencies
```

Branch protection: require `security / Security gate / Security gate` and
the CI gate(s). Add `.github/security-exceptions.yml` with `exceptions: []`.

### 3.1 Terraform / OpenTofu infrastructure (AWS)

| Need | Workflow | Status |
|---|---|---|
| fmt, validate, tflint, plan | `tofu-ci.yml` | Available |
| IaC security | `profile-pr-gate.yml` (detects `.tf`) + `profile-tf.yml` on the module directory | Available |
| Apply with approval | `tofu-deploy.yml` | Planned |

```yaml
# .github/workflows/ci.yml
jobs:
  tofu:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/tofu-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write          # plan credentials, default branch only
    with:
      directories: infra/envs/dev infra/envs/prod
      plan-command: |
        cd infra/envs/dev
        tofu init -input=false && tofu plan -input=false

  iac:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-tf.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
    with:
      working-directory: infra
```

In `security.yml`, `full` needs nothing extra; `codeql-languages: actions`.

Planned `deploy.yml` (shape only):

```yaml
# PLANNED - tofu-deploy.yml does not exist yet
jobs:
  prod:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/tofu-deploy.yml@<sha>
    permissions: { contents: read, id-token: write }
    with:
      environment: prod                 # GitHub Environment with required reviewers
      working-directory: infra/envs/prod
      cloud: aws
```

### 3.2 Python library (published to PyPI)

| Need | Workflow | Status |
|---|---|---|
| Lint, test matrix, coverage | `python-ci.yml` | Available |
| Security | security file (3.0); `codeql-languages: actions,python` | Available |
| Publish | `python-package-release.yml` (Trusted Publishing, no token) | Available |

```yaml
# .github/workflows/ci.yml  -  see README "CI" for every input
jobs:
  ci:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/python-ci.yml@<sha> # vX.Y.Z
    permissions: { contents: read, id-token: write }
    with:
      python-versions: '["3.11", "3.12", "3.13"]'
      install-command: pip install --require-hashes -r requirements-dev.txt && pip install --no-deps .
      test-command: pytest --cov=src --cov-report=xml
      lint-install-command: pip install "$(grep -E '^ruff==' requirements-dev.in)"
      lint-command: ruff check .
      docker-build: false

# .github/workflows/release.yml  (on: push tags v*, pull_request)
jobs:
  package:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/python-package-release.yml@<sha> # vX.Y.Z
    permissions: { contents: write, id-token: write, attestations: write }
    with:
      publish: ${{ startsWith(github.ref, 'refs/tags/v') }}
      smoke-command: my-lib --version
```

### 3.3 Python service in a container

As 3.2 for CI, plus the image:

```yaml
# .github/workflows/release.yml
on:
  push: { branches: [main], tags: ['v*.*.*'] }
  pull_request:
  schedule: [{ cron: '0 5 * * 1' }]     # weekly rebuild picks up base-image fixes
permissions: { contents: read }
jobs:
  image-scan:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-image.yml@<sha> # vX.Y.Z
    permissions: { contents: read, security-events: write }
    with:
      dockerfile: Dockerfile

  container:
    needs: image-scan                   # local build runs only if the image passes the gate
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/container-release.yml@<sha> # vX.Y.Z
    permissions: { contents: read, packages: write, id-token: write, attestations: write, security-events: write }
    with:
      dockerfile: Dockerfile
      push: false                      # true currently fails closed; no image is published
      docker-test-command: |
        docker run --rm "$IMAGE" --version
        test "$(docker run --rm --entrypoint id "$IMAGE" -u)" != "0"
```

In `security.yml`, `full` gets `with: { dockerfile: Dockerfile }`.

### 3.4 Node.js / TypeScript application

| Need | Workflow | Status |
|---|---|---|
| Lint, test, build | `node-ci.yml` | Planned; your own job until then |
| Dependencies | osv-scanner and Trivy in the profiles (lock files) | Available |
| Code | Semgrep `p/default` (add `p/typescript`, `p/react`), CodeQL `javascript-typescript` | Available |
| Image | `profile-image.yml` + `container-release.yml` | Available |
| npm publish | `npm-package-release.yml` | Planned; publish the tarball from your own release job today |

```yaml
# security.yml, the profile job:
    with:
      semgrep-config: p/default p/typescript
# security.yml, the codeql job:
    with:
      gitleaks: false
      codeql-languages: actions,javascript-typescript
      pip-audit-requirements: ""
```

Until `npm-package-release.yml` exists, run `npm pack` in a job with
`contents: write` on a tag and upload the tarball yourself.

### 3.5 Java service (Maven or Gradle)

| Need | Workflow | Status |
|---|---|---|
| Build, test | `java-ci.yml` | Planned; your own job until then |
| Dependencies | osv-scanner (`pom.xml`, `gradle.lockfile`) on every PR | Available |
| Code | Semgrep `p/java`, CodeQL `java-kotlin` | Available |
| Image | `profile-image.yml` + `container-release.yml` | Available |
| JAR on a release | your own release step (`mvn -B package`) | Available |

```yaml
# security.yml, the full job:
  full:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-full.yml@<sha> # vX.Y.Z
    permissions: { contents: read, security-events: write }
    with:
      dockerfile: Dockerfile
      semgrep-config: p/default p/java
```

### 3.6 .NET application

| Need | Workflow | Status |
|---|---|---|
| Build, test | `dotnet-ci.yml` | Planned |
| Dependencies | osv-scanner (`packages.lock.json`; enable `RestorePackagesWithLockFile`), Trivy | Available |
| Code | Semgrep `p/csharp`, CodeQL `csharp` | Available |
| Image / artifacts | `profile-image.yml`, `container-release.yml` | Available |

### 3.7 Go service or CLI

| Need | Workflow | Status |
|---|---|---|
| vet, lint, test, govulncheck | `go-ci.yml` | Planned |
| Dependencies | osv-scanner (`go.mod`), Trivy; `govulncheck` today through `security.yml` `audit-command` | Available |
| Code | Semgrep `p/golang`, CodeQL `go` | Available |
| Binaries on a release | your own release step (`go build` per OS/arch) | Available |

```yaml
# security.yml, the codeql job, runs govulncheck as the dependency audit:
    with:
      gitleaks: false
      codeql-languages: actions,go
      pip-audit-requirements: ""
      audit-install-command: go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
      audit-command: '"$(go env GOPATH)/bin/govulncheck" ./...'
```

### 3.8 Bash scripts and Ansible

```yaml
# .github/workflows/ci.yml
jobs:
  ci:                        # or `shell:` beside another language's `ci:`
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/bash-ci.yml@<sha> # vX.Y.Z
    permissions: { contents: read }
    with:
      shfmt-args: -i 2 -ci
      test-command: bats tests/
      test-install-command: sudo apt-get install -y bats
      config-lint-install-command: pip install yamllint ansible-lint
      config-lint-command: yamllint . && ansible-lint
```

Security: the standard file (3.0). Secrets in scripts are what gitleaks is
for; Semgrep `p/bash` adds shell rules.

### 3.9 Helm charts and Kubernetes manifests

| Need | Workflow | Status |
|---|---|---|
| Manifest security | `profile-pr-gate.yml` detects `Chart.yaml` and `apiVersion:` files and runs Trivy config and Checkov | Available |
| Narrower IaC scan | `scan-checkov.yml` (`checkov-frameworks: kubernetes,helm`) + `security-gate.yml` | Available |
| lint, render, kubeconform | `helm-ci.yml` | Planned |
| Deploy | `helm-deploy.yml` | Planned |

### 3.10 A monorepo with several applications

One caller job per application directory, each with its own
`artifact-prefix` so the gates do not read each other's reports, and each
gate required:

```yaml
jobs:
  api:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-pr-gate.yml@<sha> # vX.Y.Z
    permissions: { contents: read, security-events: write }
    with: { working-directory: services/api, artifact-prefix: api }
  web:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-pr-gate.yml@<sha> # vX.Y.Z
    permissions: { contents: read, security-events: write }
    with: { working-directory: apps/web, artifact-prefix: web }
  infra:
    uses: Lucatronlk/justsec-cicd-blueprints/.github/workflows/profile-tf.yml@<sha> # vX.Y.Z
    permissions: { contents: read, security-events: write }
    with: { working-directory: infra, artifact-prefix: infra }
```

No prefix may be the start of another followed by `-` (`api` and `api-v2`
collide; `api` and `apiv2` do not). The history scan (gitleaks)
covers the whole repository in each; to run them once, give the
directory jobs `profile-dev.yml` / `profile-tf.yml` and one
`profile-secrets.yml` job.

---

## 4. Use cases

### 4.1 Onboarding an existing repository

1. Add `.github/workflows/security.yml` (3.0) with `fail-on: none` on the
   profile job for the first run: it reports everything and blocks nothing.
2. Read the gate's summary. Fix what can be fixed now; for the rest add
   dated entries to `.github/security-exceptions.yml`, each with an owner.
3. Remove `fail-on: none`. The gate now blocks CRITICAL/HIGH.
4. Add the CI caller for the language and the release caller.
5. Apply [BASELINE.md](../BASELINE.md) and require the gates in branch
   protection. Add the repository to `baseline/repos.txt`.

### 4.2 A brand-new repository

Start strict: the security file from 3.0 unchanged, the CI caller, and the
branch protection rule before the first feature branch. Nothing to waive
means nothing to unwind later. `scripts/new-repo.sh` writes the CI caller
files today; the security caller is Phase 4.

### 4.3 Day to day: push, pull request, merge

- **Push to a feature branch**: `profile-pr-gate.yml` runs; a CRITICAL/HIGH
  fails the run on the branch, before a pull request exists.
- **Pull request**: the same gate is the required check; MEDIUM/LOW appear
  in the job summary and the Security tab, without blocking.
- **Merge to main**: the gate runs again on main; the release workflow
  builds and signs.
- **Monday**: `profile-full.yml` re-scans unchanged code against new CVEs.

### 4.4 A finding blocks a pull request

1. Open the gate job's summary: severity, tool, id, file and line.
2. **Fix it**: upgrade the dependency, change the code, harden the IaC.
3. **If it cannot be fixed yet**, add an exception, reviewed in the same
   pull request:
   ```yaml
   exceptions:
     - id: CVE-2026-1234
       tool: osv-scanner
       path: "services/api/*"
       reason: Not reachable; the parser is never called. Upgrade in #123.
       owner: api-team
       expires: 2026-11-30
   ```
4. When `expires` passes, the finding blocks again. That is the reminder;
   extend it only with a new reason.

An exception is reviewed code: protect `.github/security-exceptions.yml`
with a CODEOWNERS entry for the security owner.

### 4.5 A secret is found

- **A secret finding:** assume the credential works. **Rotate it at
  the provider first**, then remove it from the code; deleting the commit
  does not revoke it, and the history keeps it.
- **gitleaks match** (HIGH): treat as real until shown otherwise. If it is
  a test fixture, exclude the path in `.gitleaks.toml` (gitleaks reads it
  from the repository) rather than adding an exception.
- **History rewrite** only after rotation, and only if the repository is
  public or widely cloned; coordinate it, since it changes every SHA.

### 4.6 Releasing a container image

`profile-image.yml` gates an image build; `container-release.yml` can build,
test and scan locally (`push: false`), as in 3.3. Publishing is deliberately
disabled: a second multi-arch build would not be the bytes that passed local
tests. Do not use `push: true` until each published platform digest is scanned
and tested and the exact verified index is promoted.

### 4.7 Deploying infrastructure (Planned)

`tofu-ci.yml` + `profile-tf.yml` on the pull request → merge →
`tofu-deploy.yml` plans per environment, a reviewer approves the
`prod` environment, and apply runs the reviewed plan file. Until it
exists, keep applies in the project's own workflow, bound to a GitHub
Environment with required reviewers and OIDC cloud login.

### 4.8 Private repository without GitHub Advanced Security

Pass `upload-sarif: false` to every profile. The gate, its job summary and
the report artifacts work the same; only the Security tab view is lost.
`security.yml`'s CodeQL needs Advanced Security on a private repository:
pass `codeql: false` there.

### 4.9 Locking down egress

Every workflow ships `egress-policy: audit`. After a few runs, read the
harden-runner summary, then pass `egress-policy: block` (and
`extra-allowed-endpoints` for hosts only your project reaches, such as a
private registry). A new outbound host then fails loudly as `domain not
allowed` instead of passing silently.

### 4.10 Only some scanners, or one directory

Call the `scan-*.yml` you want and `security-gate.yml` after them (README,
"Calling them"). Each scan's `artifact-name` must start with the gate's
`artifact-prefix`.

### 4.11 Stricter or softer policy for one repository

`fail-on: CRITICAL,HIGH,MEDIUM` for a regulated service; `fail-on-secrets:
true` to block unverified secrets too; `checkov-default-severity: HIGH` to
make Checkov block. Softening below the default is what exceptions are
for, one finding at a time with an expiry, not a lower `fail-on`.

### 4.12 Updating

- Callers move their `@<sha>` pin through Dependabot (`github-actions`
  ecosystem): one reviewed pull request per release of this repository.
- Here, actions move by Dependabot; scanner versions, hashes and digests are
  workflow inputs and move by hand for now (ROADMAP, Phase 1 follow-ups).
- A caller can pin a newer scanner itself, e.g. `trivy-version` and
  `trivy-sha256`, without waiting for a release here.

---

## 5. Rolling it out

| Step | Scope | Gate mode |
|---|---|---|
| 1 | One pilot repository per application type | `fail-on: none`, read the findings |
| 2 | Pilots fixed or excepted | default policy, gate required |
| 3 | All repositories, security file only | `fail-on: none` for a week, then default |
| 4 | CI callers per language (Phase 2 as it lands) | `CI green` required |
| 5 | Release callers; then deploy callers (Phase 3) | Environments with reviewers |
| 6 | `egress-policy: block` everywhere, measured lists | |
| 7 | Baseline audit on a schedule (Phase 4) | drift is a red job |
