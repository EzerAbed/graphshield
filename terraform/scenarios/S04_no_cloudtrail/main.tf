# ============================================================
# SCENARIO S04: No CloudTrail — all logging disabled
# Label: LOW RISK
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s04" {
  cidr_block           = "10.4.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s04", Scenario = "S04", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s04.id
  cidr_block              = "10.4.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s04-subnet" }
}

# SECURE Security Group — no dangerous ports open
resource "aws_security_group" "secure_sg" {
  name        = "graphshield-s04-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s04.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s04-sg", Scenario = "S04" }
}

# SECURE IAM Role — least privilege
resource "aws_iam_role" "minimal" {
  name = "graphshield-s04-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S04" }
}

resource "aws_iam_role_policy" "minimal" {
  name = "graphshield-s04-minimal"
  role = aws_iam_role.minimal.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s04-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s04" {
  name = "graphshield-s04-profile"
  role = aws_iam_role.minimal.name
}

# SECURE S3 Bucket — private and encrypted
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s04-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s04-bucket", Scenario = "S04" }
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

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# SECURE EC2 — no public IP, encrypted disk, IMDSv2
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.secure_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s04.name
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s04-ec2", Scenario = "S04" }
}

# MISCONFIGURATION: No CloudTrail resource defined here
# In a secure setup you would have aws_cloudtrail enabled
# The absence of CloudTrail is what the scanner detects as a finding