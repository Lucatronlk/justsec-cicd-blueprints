terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "bucket_name" {
  description = "Globally unique name for a private test bucket."
  type        = string
}

variable "aws_region" {
  description = "AWS region for the sample resources."
  type        = string
  default     = "us-east-1"
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "sample" {
  bucket = var.bucket_name
  tags = {
    owner               = "security-scans"
    service             = "sample-infrastructure"
    environment         = "test"
    data-classification = "public"
    cost-center         = "demo"
    managed-by          = "terraform"
    incident-contact    = "repository-maintainer"
  }
}

resource "aws_s3_bucket_public_access_block" "sample" {
  bucket                  = aws_s3_bucket.sample.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "sample" {
  bucket = aws_s3_bucket.sample.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "sample" {
  description         = "Encryption key for the sample S3 bucket"
  enable_key_rotation = true
  tags = {
    owner               = "security-scans"
    service             = "sample-infrastructure"
    environment         = "test"
    data-classification = "public"
    cost-center         = "demo"
    managed-by          = "terraform"
    incident-contact    = "repository-maintainer"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sample" {
  bucket = aws_s3_bucket.sample.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sample.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "sample" {
  bucket = aws_s3_bucket.sample.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
