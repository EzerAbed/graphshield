# ============================================================
# SCENARIO S40: All Ports Open Security Group
# Label: LOW RISK
# SG opens all traffic to 0.0.0.0/0 but EC2 has no public IP
# Port open but machine unreachable — chain broken
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s40" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s40", Scenario = "S40", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s40.id
  cidr_block              = "10.40.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s40-subnet" }
}

# MISCONFIGURATION: all traffic open to entire internet
resource "aws_security_group" "all_open_sg" {
  name        = "graphshield-s40-all-open-sg"
  description = "INTENTIONALLY INSECURE: all traffic open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s40.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"          # MISCONFIGURATION: all protocols
    cidr_blocks = ["0.0.0.0/0"] # MISCONFIGURATION: entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s40-sg", Scenario = "S40" }
}

# SECURE IAM role — least privilege
resource "aws_iam_role" "minimal_role" {
  name = "graphshield-s40-minimal-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S40" }
}

resource "aws_iam_role_policy" "minimal_policy" {
  name = "graphshield-s40-minimal-policy"
  role = aws_iam_role.minimal_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s40-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s40" {
  name = "graphshield-s40-profile"
  role = aws_iam_role.minimal_role.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 — no public IP so all-open SG is unreachable
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.all_open_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s40.name
  associate_public_ip_address = false  # SECURE: no public IP breaks the chain

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s40-ec2", Scenario = "S40" }
}

# SECURE S3 bucket
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s40-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s40-bucket", Scenario = "S40" }
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