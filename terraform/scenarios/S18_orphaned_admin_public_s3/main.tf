# ============================================================
# SCENARIO S18: Standalone Admin IAM Role + Public S3 Bucket
# Label: CRITICAL — Two independent severe misconfigurations
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_iam_role" "orphan_admin" {
  name = "graphshield-s18-orphan-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Scenario = "S18" }
}

resource "aws_iam_role_policy_attachment" "orphan_admin_attach" {
  role       = aws_iam_role.orphan_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # MISCONFIGURATION
}

resource "aws_s3_bucket" "exposed" {
  bucket        = "graphshield-s18-exposed-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S18" }
}

resource "aws_s3_bucket_public_access_block" "exposed" {
  bucket                  = aws_s3_bucket.exposed.id
  block_public_acls       = false # MISCONFIGURATION
  block_public_policy     = false # MISCONFIGURATION
  ignore_public_acls      = false # MISCONFIGURATION
  restrict_public_buckets = false # MISCONFIGURATION
}
