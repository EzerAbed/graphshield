# ============================================================
# SCENARIO S34: Unused Admin Role
# Label: LOW RISK
# AdministratorAccess role exists but not attached to anything
# Dormant — no direct exploit path
# ============================================================

provider "aws" {
  region = var.region
}

# MISCONFIGURATION: Admin role created but never attached
resource "aws_iam_role" "unused_admin" {
  name = "graphshield-s34-unused-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S34" }
}

# MISCONFIGURATION: full admin attached but role never used
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.unused_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# SECURE S3 bucket — private and encrypted
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s34-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s34-bucket", Scenario = "S34" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No EC2 — role exists but is attached to nothing
# No open ports, no public S3
# Role is dormant — dangerous only if someone attaches it