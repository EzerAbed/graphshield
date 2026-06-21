# ============================================================
# SCENARIO S16: Public S3 + No Encryption + No Versioning
# Label: MEDIUM RISK — Data exposure without active attack chain
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "exposed" {
  bucket        = "graphshield-s16-exposed-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S16" }
}

resource "aws_s3_bucket_public_access_block" "exposed" {
  bucket                  = aws_s3_bucket.exposed.id
  block_public_acls       = false # MISCONFIGURATION
  block_public_policy     = false # MISCONFIGURATION
  ignore_public_acls      = false # MISCONFIGURATION
  restrict_public_buckets = false # MISCONFIGURATION
}

resource "aws_s3_bucket_versioning" "exposed" {
  bucket = aws_s3_bucket.exposed.id
  versioning_configuration {
    status = "Disabled" # MISCONFIGURATION
  }
}
# Note: no aws_s3_bucket_server_side_encryption_configuration resource —
# bucket is left without default encryption (MISCONFIGURATION)