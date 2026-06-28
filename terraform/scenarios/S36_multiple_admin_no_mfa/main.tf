# ============================================================
# SCENARIO S36: Multiple Admin Users No MFA
# Label: HIGH RISK
# Three IAM users with AdministratorAccess, none with MFA
# Wider attack surface than S08 (single admin user)
# ============================================================

provider "aws" {
  region = var.region
}

# IAM User 1 — Admin, no MFA
resource "aws_iam_user" "admin_user_1" {
  name = "graphshield-s36-admin-1"
  tags = { Scenario = "S36", Project = "graphshield" }
}

resource "aws_iam_user_policy_attachment" "admin_1" {
  user       = aws_iam_user.admin_user_1.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_login_profile" "login_1" {
  user                    = aws_iam_user.admin_user_1.name
  password_reset_required = false
}

# IAM User 2 — Admin, no MFA
resource "aws_iam_user" "admin_user_2" {
  name = "graphshield-s36-admin-2"
  tags = { Scenario = "S36", Project = "graphshield" }
}

resource "aws_iam_user_policy_attachment" "admin_2" {
  user       = aws_iam_user.admin_user_2.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_login_profile" "login_2" {
  user                    = aws_iam_user.admin_user_2.name
  password_reset_required = false
}

# IAM User 3 — Admin, no MFA
resource "aws_iam_user" "admin_user_3" {
  name = "graphshield-s36-admin-3"
  tags = { Scenario = "S36", Project = "graphshield" }
}

resource "aws_iam_user_policy_attachment" "admin_3" {
  user       = aws_iam_user.admin_user_3.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_login_profile" "login_3" {
  user                    = aws_iam_user.admin_user_3.name
  password_reset_required = false
}

# SECURE S3 bucket — not the focus of this scenario
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s36-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s36-bucket", Scenario = "S36" }
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

# No EC2, no open ports
# Risk is entirely in three admin users with no MFA
# Any of the three passwords stolen = full account takeover
# No CloudTrail — credential theft undetected