# Infrastructure scan sample

An optional AWS Terraform configuration for testing static IaC scanners (Checkov, Trivy config, KICS, tflint). It defines a private, versioned S3 bucket with public access blocked and default encryption through a rotating customer-managed KMS key. The optional CLI image runs as UID/GID 65532. **Do not apply it just to run scans**: scanning and formatting require no AWS account. Applying creates billable S3 and KMS resources and needs an explicitly supplied globally unique `bucket_name` and AWS credentials obtained outside source control. Review KMS key policy, access grants, and key deletion protection before deploying outside a sandbox.

```sh
terraform fmt -check
terraform init -backend=false
terraform validate
```

`terraform init` downloads the provider version pinned in `.terraform.lock.hcl` within the declared major version. After an intentional sandbox apply, plan teardown separately: remove bucket objects, review the destroy plan, then run `terraform destroy -var 'bucket_name=<your-test-bucket>'` only with approval. KMS key deletion is scheduled, not immediate; retain the key while any encrypted objects or backups still need decryption. No state files or credentials belong in Git.
