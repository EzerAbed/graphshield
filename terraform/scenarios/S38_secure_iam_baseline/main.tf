# ============================================================
# SCENARIO S38: Secure IAM Baseline
# Label: SAFE
# All IAM roles scoped, least privilege, no wildcards
# Second IAM-focused safe scenario
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s38" {
  cidr_block           = "10.38.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s38", Scenario = "S38", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id            = aws_vpc.s38.id
  cidr_block        = "10.38.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s38-subnet" }
}

# SECURE Security Group — no public inbound
resource "aws_security_group" "sg" {
  name        = "graphshield-s38-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s38.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s38-sg", Scenario = "S38" }
}

# SECURE IAM Role — scoped to specific bucket and actions only
resource "aws_iam_role" "scoped_role" {
  name = "graphshield-s38-scoped-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S38" }
}

# SECURE: scoped to specific actions and specific bucket only
resource "aws_iam_role_policy" "scoped_policy" {
  name = "graphshield-s38-scoped-policy"
  role = aws_iam_role.scoped_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",    # SECURE: only read
        "s3:ListBucket"    # SECURE: only list
      ]
      Resource = [
        "arn:aws:s3:::graphshield-s38-bucket-${var.bucket_suffix}",
        "arn:aws:s3:::graphshield-s38-bucket-${var.bucket_suffix}/*"
      ]  # SECURE: scoped to specific bucket only
    }]
  })
}

resource "aws_iam_instance_profile" "s38" {
  name = "graphshield-s38-profile"
  role = aws_iam_role.scoped_role.name
}

# SECURE S3 bucket — private, encrypted, versioned
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s38-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s38-bucket", Scenario = "S38" }
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
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# SECURE EC2 — no public IP, IMDSv2 required, encrypted disk
resource