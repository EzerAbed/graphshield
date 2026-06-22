# ============================================================
# SCENARIO S01: Baseline Secure — everything correctly configured
# Label: SAFE
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s01" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s01", Scenario = "S01", Project = "graphshield" }
}

resource "aws_internet_gateway" "s01" {
  vpc_id = aws_vpc.s01.id
  tags   = { Name = "graphshield-s01-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s01.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false  # SECURE: no auto public IP
  tags = { Name = "graphshield-s01-public" }
}

# SECURE Security Group — only HTTPS from internal IPs
resource "aws_security_group" "tight" {
  name        = "graphshield-s01-sg"
  description = "SECURE: only internal HTTPS allowed"
  vpc_id      = aws_vpc.s01.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # SECURE: internal only, not 0.0.0.0/0
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s01-sg", Scenario = "S01" }
}

# SECURE IAM Role — least privilege, scoped to specific bucket
resource "aws_iam_role" "ec2_minimal" {
  name = "graphshield-s01-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S01" }
}

resource "aws_iam_role_policy" "minimal" {
  name = "graphshield-s01-minimal"
  role = aws_iam_role.ec2_minimal.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]  # SECURE: only what's needed
      Resource = "arn:aws:s3:::graphshield-s01-*/*"  # SECURE: specific bucket only
    }]
  })
}

resource "aws_iam_instance_profile" "s01" {
  name = "graphshield-s01-profile"
  role = aws_iam_role.ec2_minimal.name
}

# SECURE S3 Bucket — private, encrypted with KMS, versioned
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s01-secure-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s01-bucket", Scenario = "S01" }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true   # SECURE
  block_public_policy     = true   # SECURE
  ignore_public_acls      = true   # SECURE
  restrict_public_buckets = true   # SECURE
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"  # SECURE: KMS encryption
    }
  }
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SECURE: CloudTrail enabled — all activity logged
resource "aws_cloudtrail" "enabled" {
  name                          = "graphshield-s01-trail"
  s3_bucket_name                = aws_s3_bucket.secure.bucket
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail_policy]
}

# CloudTrail needs a bucket policy to allow it to write logs
resource "aws_s3_bucket_policy" "trail_policy" {
  bucket = aws_s3_bucket.secure.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${aws_s3_bucket.secure.bucket}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${aws_s3_bucket.secure.bucket}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}
