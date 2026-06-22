# ============================================================
# SCENARIO S21: Public S3 Bucket, CloudTrail Enabled
# Label: MEDIUM RISK — Logging present but exposure remains
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "exposed" {
  bucket        = "graphshield-s21-exposed-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S21" }
}

resource "aws_s3_bucket_public_access_block" "exposed" {
  bucket                  = aws_s3_bucket.exposed.id
  block_public_acls       = false # MISCONFIGURATION
  block_public_policy     = false # MISCONFIGURATION
  ignore_public_acls      = false # MISCONFIGURATION
  restrict_public_buckets = false # MISCONFIGURATION
}

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "graphshield-s21-trail-${var.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail_logs_policy" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::graphshield-s21-trail-${var.bucket_suffix}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::graphshield-s21-trail-${var.bucket_suffix}/*"
      }
    ]
  })
}

resource "aws_cloudtrail" "enabled" {
  name                          = "graphshield-s21-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.trail_logs_policy]
}
