# ============================================================
# SCENARIO S06: Public S3 + Weak IAM
# Label: MEDIUM RISK
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s06" {
  cidr_block           = "10.6.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s06", Scenario = "S06", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s06.id
  cidr_block              = "10.6.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s06-subnet" }
}

# SECURE Security Group — no dangerous ports
resource "aws_security_group" "secure_sg" {
  name        = "graphshield-s06-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s06.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s06-sg", Scenario = "S06" }
}

# MISCONFIGURATION 1: IAM role with s3:* wildcard on all resources
resource "aws_iam_role" "weak_role" {
  name = "graphshield-s06-weak-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S06" }
}

resource "aws_iam_role_policy" "s3_wildcard" {
  name = "graphshield-s06-s3-wildcard"
  role = aws_iam_role.weak_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"   # MISCONFIGURATION: full S3 access
      Resource = "*"      # MISCONFIGURATION: on ALL resources
    }]
  })
}

resource "aws_iam_instance_profile" "s06" {
  name = "graphshield-s06-profile"
  role = aws_iam_role.weak_role.name
}

# MISCONFIGURATION 2: S3 bucket fully public
resource "aws_s3_bucket" "public_bucket" {
  bucket        = "graphshield-s06-public-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s06-bucket", Scenario = "S06" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false  # MISCONFIGURATION
  block_public_policy     = false  # MISCONFIGURATION
  ignore_public_acls      = false  # MISCONFIGURATION
  restrict_public_buckets = false  # MISCONFIGURATION
}

# No encryption — data stored in plaintext
# No versioning — no recovery possible

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 — no public IP but has weak IAM role attached
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.secure_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s06.name
  associate_public_ip_address = false  # SECURE: no internet exposure yet

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s06-ec2", Scenario = "S06" }
}

# No CloudTrail