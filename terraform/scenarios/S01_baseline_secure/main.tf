terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# --- Networking: a simple secure VPC ---
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "graphshield-s01-vpc" }
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  tags = { Name = "graphshield-s01-subnet" }
}

# --- Security Group: locked down, no public SSH/HTTP ---
resource "aws_security_group" "secure_sg" {
  name        = "graphshield-s01-sg"
  description = "Secure SG - no public access"
  vpc_id      = aws_vpc.main.id

  # No inbound rules open to the internet
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s01-sg" }
}

# --- IAM Role: minimal, least-privilege ---
resource "aws_iam_role" "minimal_role" {
  name = "graphshield-s01-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "graphshield-s01-role" }
}

resource "aws_iam_role_policy" "minimal_policy" {
  name = "graphshield-s01-minimal-policy"
  role = aws_iam_role.minimal_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s01-bucket-${random_id.suffix.hex}/*"
    }]
  })
}

resource "aws_iam_instance_profile" "minimal_profile" {
  name = "graphshield-s01-profile"
  role = aws_iam_role.minimal_role.name
}

resource "random_id" "suffix" {
  byte_length = 4
}

# --- S3 Bucket: fully private, encrypted ---
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "graphshield-s01-bucket-${random_id.suffix.hex}"
  tags   = { Name = "graphshield-s01-bucket" }
}

resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "secure_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- EC2 Instance: no public IP, encrypted volume, IMDSv2 required ---
resource "aws_instance" "secure_instance" {
  ami                    = "ami-0c02fb55956c7d316" # Amazon Linux 2, us-east-1
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.minimal_profile.name
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s01-instance" }
}