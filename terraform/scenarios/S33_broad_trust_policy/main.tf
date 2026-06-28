# ============================================================
# SCENARIO S33: Overly Broad Trust Policy
# Label: CRITICAL
# IAM role assumable by ANY AWS account (Principal: *)
# No condition, no restriction — world-readable role
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s33" {
  cidr_block           = "10.33.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s33", Scenario = "S33", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id            = aws_vpc.s33.id
  cidr_block        = "10.33.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s33-subnet" }
}

resource "aws_security_group" "sg" {
  name        = "graphshield-s33-sg"
  description = "SECURE: no public inbound"
  vpc_id      = aws_vpc.s33.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s33-sg", Scenario = "S33" }
}

# MISCONFIGURATION: trust policy allows ANY principal
# Any AWS account worldwide can assume this role
resource "aws_iam_role" "world_assumable" {
  name = "graphshield-s33-world-assumable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = "*"  # CRITICAL MISCONFIGURATION: any account can assume
    }]
  })

  tags = { Scenario = "S33" }
}

# MISCONFIGURATION: role has s3:* on all resources
resource "aws_iam_role_policy" "s3_full" {
  name = "graphshield-s33-s3-full"
  role = aws_iam_role.world_assumable.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"   # MISCONFIGURATION: full S3 access
      Resource = "*"      # MISCONFIGURATION: on all resources
    }]
  })
}

# S3 bucket — accessible to anyone who assumes the role
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s33-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s33-bucket", Scenario = "S33" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No EC2 needed — any external AWS account can assume this role directly
# No CloudTrail — cross-account assumption leaves no trace