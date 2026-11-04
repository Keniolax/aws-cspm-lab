# Deliberately misconfigured, on purpose. This module exists so Prowler and
# ScoutSuite have real findings to find, and so the "fixed" module has an exact
# before-state to repair. Never deploy it to a real account.

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
}

# --- S3: a bucket with its doors open ---

resource "aws_s3_bucket" "lab" {
  bucket        = local.bucket_name
  force_destroy = true
}

# The public-read ACL below needs both the account-level public access block
# off and object ownership set to ObjectWriter, so all three are flipped here.
# Every one of these is itself a posture finding, which is the point.

resource "aws_s3_account_public_access_block" "lab" {
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_acl" "lab" {
  depends_on = [
    aws_s3_account_public_access_block.lab,
    aws_s3_bucket_ownership_controls.lab,
  ]
  bucket = aws_s3_bucket.lab.id
  acl    = "public-read"
}

# No aws_s3_bucket_public_access_block resource: per-bucket public access
# block is absent.
#
# No aws_s3_bucket_server_side_encryption_configuration resource: objects
# land unencrypted.
#
# No aws_s3_bucket_policy resource: requests over plain HTTP are accepted.

resource "aws_s3_bucket_versioning" "lab" {
  bucket = aws_s3_bucket.lab.id
  versioning_configuration {
    status = "Disabled"
  }
}

# --- EC2: a security group that lets the whole internet administer SSH ---

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-ssh"
  description = "Deliberately open: SSH from 0.0.0.0/0"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from anywhere, including the entire internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-ssh"
  }
}

# --- IAM: the weakest password policy the API accepts ---

resource "aws_iam_account_password_policy" "lab" {
  minimum_password_length      = 6
  require_numbers              = false
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_symbols              = false
}