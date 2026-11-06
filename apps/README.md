# Scan target applications

Standalone, intentionally **non-vulnerable** samples for exercising scanners before publishing changes. These are test targets, not supported production applications; do not put credentials, tokens, private keys, malicious payloads or intentionally exploitable code here. Security findings can still appear as dependencies and scanner databases change. Run locally first, inspect scanner output, then fix or document any unexpected finding. No sample requires a cloud account for static scanning.

| Directory | Target | Typical checks |
| --- | --- | --- |
| `python-api/` | Python HTTP API | unit tests, Semgrep, Trivy filesystem, image scan |
| `typescript-web/` | Node.js TypeScript API + browser page | tests/build, dependency audits, Semgrep, image scan |
| `dotnet-api/` | C# ASP.NET Core API | build, smoke test, NuGet/OSV, image scan |
| `container-web/` | Static containerized web page | Hadolint, Trivy/Grype image scan, SBOM |
| `infrastructure/` | Terraform AWS S3 configuration | `terraform fmt`, validate, Checkov, Trivy config, KICS, tflint |
| `k8s/` | Kubernetes YAML manifests | YAML lint, schema validation, Checkov, Trivy config, KICS |
| `fixture/` | Existing clean workflow contract fixture | existing self-test CI |
| `sample-app/` | Existing minimal legacy example | Docker scan |

From the repository root, target an individual subtree with your locally installed scanner; for example:

```sh
semgrep scan --config p/default apps/python-api
trivy fs --scanners vuln,secret apps/typescript-web
trivy config apps/k8s
checkov -d apps/infrastructure
hadolint apps/container-web/Dockerfile
# Optional: builds locally, never pushes an image
docker build -t container-web:scan apps/container-web
trivy image container-web:scan
```

The sample entrypoints are `.github/workflows/ci-python-api.yml`, `ci-typescript-web.yml`, `ci-dotnet-api.yml`, `ci-container-web.yml`, `ci-infrastructure.yml` and `ci-k8s.yml`. Each runs a matching scan profile on relevant pushes and pull requests; manual dispatch selects a profile (including image or full scans where offered). `ci-fixture.yml` and `ci-sample-app.yml` are manual-only. The repository's own `ci-repo.yml` tests the reusable workflows. None of these sample entrypoints deploys a cluster or publishes an image.

Run builds/tests from each sample directory following its README. Keep scanners report-only when exploring; never weaken the security gate or add broad exceptions to accommodate a sample. A green scan does not demonstrate scanner effectiveness against unsafe code. For detection sensitivity, use isolated, synthetic fixtures outside this repository with no real secrets, reviewed scanner rules, and known expected findings.

Rollback: delete only the newly introduced sample directory; neither `fixture/` nor `sample-app/` needs changing. Do not apply the infrastructure or cluster manifests just to run static scans.
