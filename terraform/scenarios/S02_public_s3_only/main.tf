# ============================================================
# SCENARIO S02: Public S3 Only
# Label: LOW RISK
# ============================================================

provider "aws" {
  region = var.region
}

# S3 bucket — intentionally PUBLIC, no encryption, no versioning
resource "aws_s3_bucket" "public_bucket" {
  bucket        = "graphshield-s02-public-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s02-bucket", Scenario = "S02" }
}

# All 4 blocks set to FALSE — bucket is fully public
resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false  # MISCONFIGURATION
  block_public_policy     = false  # MISCONFIGURATION
  ignore_public_acls      = false  # MISCONFIGURATION
  restrict_public_buckets = false  # MISCONFIGURATION
}

# No encryption — data stored in plaintext
# No versioning — no recovery if files deleted
# No EC2, no IAM role — isolated finding only
