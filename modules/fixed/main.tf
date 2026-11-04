# The remediation of every misconfiguration in the vuln module, plus the two
# CIS AWS Benchmark account-level items the vuln module left out on purpose:
# a multi-region CloudTrail trail and a strong IAM password policy. Resource
# addresses match the vuln module, so `make apply MODE=fixed` updates the same
# resources in place and the plan diff reads as the fix list.
#
# This module is applied over the vuln state (`make before`, then
# `make after`). On a fresh account the ACL reset below fails, because a new
# bucket already has ACLs disabled.

variable "region" {
  type = string
}

variable "lab_name" {
  type = string
}

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

locals {
  bucket_name = "${var.lab_name}-${data.aws_caller_identity.current.account_id}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = var.region
}

# --- S3: the same bucket, closed ---

resource "aws_s3_bucket" "lab" {
  bucket        = local.bucket_name
  force_destroy = true
}

# Account-level public access block on. AWS turns Block Public Access on by
# default for each new bucket, not for the account; the vuln module set the
# account-level block to off, and this sets it to on.

resource "aws_s3_account_public_access_block" "lab" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Per-bucket public access block on as well, so the bucket stays private even
# if the account-level setting is ever loosened.

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# The order of these two resources is the remediation. The vuln bucket has a
# public-read ACL grant. Removing an aws_s3_bucket_acl resource from the code
# does not change the bucket (the provider only forgets it), and S3 refuses to
# switch a bucket to BucketOwnerEnforced while a grant to anyone outside the
# account exists (InvalidBucketAclWithObjectOwnership). So the ACL is reset to
# private first, and only then are ACLs disabled.

resource "aws_s3_bucket_acl" "lab" {
  bucket = aws_s3_bucket.lab.id
  acl    = "private"
}

# BucketOwnerEnforced disables ACLs entirely, so a public-read ACL cannot be
# attached again. The vuln module needed ObjectWriter for its public ACL.

resource "aws_s3_bucket_ownership_controls" "lab" {
  depends_on = [aws_s3_bucket_acl.lab]
  bucket     = aws_s3_bucket.lab.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Default encryption at rest with AES256 (S3-managed keys; a KMS customer
# managed key costs $1 per month and is out of scope for a throwaway lab).

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "lab" {
  bucket = aws_s3_bucket.lab.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Deny every request that is not HTTPS.

data "aws_iam_policy_document" "deny_insecure_transport" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.lab.arn,
      "${aws_s3_bucket.lab.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "lab" {
  bucket = aws_s3_bucket.lab.id
  policy = data.aws_iam_policy_document.deny_insecure_transport.json
}

# --- EC2: the same security group, with no inbound and no outbound rules ---
#
# The description matches the vuln module: a changed description forces
# Terraform to replace the group instead of repairing it. Leaving out the
# ingress and egress blocks would not remove the old rules (Terraform stops
# managing them), so both are set to empty lists.

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-ssh"
  description = "SecEng week 10 lab security group"
  vpc_id      = data.aws_vpc.default.id

  ingress = []
  egress  = []

  tags = {
    Name = "${var.lab_name}-ssh"
  }
}

# --- CloudTrail: one multi-region trail, free management-event copy ---

resource "aws_s3_bucket" "audit" {
  bucket        = "${var.lab_name}-audit-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

# The audit bucket is scanned too, so it meets the same bar as the lab bucket:
# ACLs disabled and plain HTTP refused. CloudTrail delivers over HTTPS.

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "cloudtrail_audit" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.audit.arn,
      "${aws_s3_bucket.audit.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "CloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.lab_name}-trail"]
    }
  }

  statement {
    sid    = "CloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.lab_name}-trail"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  depends_on = [aws_s3_bucket_public_access_block.audit]
  bucket     = aws_s3_bucket.audit.id
  policy     = data.aws_iam_policy_document.cloudtrail_audit.json
}

resource "aws_cloudtrail" "lab" {
  depends_on = [aws_s3_bucket_policy.audit]

  name                          = "${var.lab_name}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

# --- IAM: the password policy the CIS AWS Benchmark asks for ---

resource "aws_iam_account_password_policy" "lab" {
  minimum_password_length        = 14
  require_numbers                = true
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}