# ============================================================
# SCENARIO S43: Multiple Open Ports
# Label: MEDIUM RISK
# SSH + RDP + HTTP + HTTPS all open to internet
# No public IP — wide SG attack surface but unreachable
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s43" {
  cidr_block           = "10.43.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s43", Scenario = "S43", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s43.id
  cidr_block              = "10.43.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s43-subnet" }
}

# MISCONFIGURATION: multiple ports open to entire internet
resource "aws_security_group" "multi_open_sg" {
  name        = "graphshield-s43-multi-open-sg"
  description = "INTENTIONALLY INSECURE: multiple ports open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s43.id

  # MISCONFIGURATION 1: SSH open
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION 2: RDP open
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION 3: HTTP open
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION 4: HTTPS open
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s43-sg", Scenario = "S43" }
}

# SECURE IAM role — minimal permissions
resource "aws_iam_role" "minimal_role" {
  name = "graphshield-s43-minimal-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S43" }
}

resource "aws_iam_role_policy" "minimal_policy" {
  name = "graphshield-s43-minimal-policy"
  role = aws_iam_role.minimal_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s43-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s43" {
  name = "graphshield-s43-profile"
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

# EC2 — no public IP breaks the chain
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.multi_open_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s43.name
  associate_public_ip_address = false  # SECURE: no public IP

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s43-ec2", Scenario = "S43" }
}

# SECURE S3 bucket
resource "aws_s3_bucket" "secure" {
  bucket