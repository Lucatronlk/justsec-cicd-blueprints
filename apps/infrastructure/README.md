# Infrastructure scan sample

An optional AWS Terraform configuration for testing static IaC scanners (Checkov, Trivy config, KICS, tflint). It defines a private, versioned, encrypted S3 bucket with public access blocked. **Do not apply it just to run scans**: scanning and formatting require no AWS account. Applying creates a billable cloud resource and needs an explicitly supplied globally unique `bucket_name` and AWS credentials obtained outside source control.

```sh
terraform fmt -check
terraform init -backend=false
terraform validate
```

`terraform init` downloads the provider version pinned in `.terraform.lock.hcl` within the declared major version. Run `terraform destroy -var 'bucket_name=<your-test-bucket>'` after any intentional apply; remove objects first if necessary. No state files or credentials belong in Git.
