# ============================================================
# SCENARIO S08: No MFA + Admin User
# Label: MEDIUM RISK
# ============================================================

provider "aws" {
  region = var.region
}

# MISCONFIGURATION 1: IAM user with AdministratorAccess
resource "aws_iam_user" "admin_user" {
  name = "graphshield-s08-admin-user"
  tags = { Scenario = "S08", Project = "graphshield" }
}

# MISCONFIGURATION 2: Admin policy attached directly to user
resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Console access enabled — user can log in with just a password
# No MFA device is attached — single factor only
resource "aws_iam_user_login_profile" "login" {
  user                    = aws_iam_user.admin_user.name
  password_reset_required = false
}

# SECURE S3 Bucket — not the focus of this scenario
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s08-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s08-bucket", Scenario = "S08" }
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

# No EC2, no open ports, no public S3
# The risk is entirely in the IAM user with no MFA
# An attacker who steals the password gets full admin access immediately
