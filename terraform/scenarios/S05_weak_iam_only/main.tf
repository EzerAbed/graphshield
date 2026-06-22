# ============================================================
# SCENARIO S05: Weak IAM Only — AdministratorAccess on EC2 role
# Label: MEDIUM RISK
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s05" {
  cidr_block           = "10.5.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s05", Scenario = "S05", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s05.id
  cidr_block              = "10.5.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s05-subnet" }
}

# SECURE Security Group — no dangerous ports
resource "aws_security_group" "secure_sg" {
  name        = "graphshield-s05-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s05.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s05-sg", Scenario = "S05" }
}

# MISCONFIGURATION: AdministratorAccess on EC2 role
# This gives full AWS account control to anything running on the EC2
resource "aws_iam_role" "admin_role" {
  name = "graphshield-s05-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S05" }
}

# MISCONFIGURATION: full AdministratorAccess attached
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "s05" {
  name = "graphshield-s05-profile"
  role = aws_iam_role.admin_role.name
}

# SECURE S3 Bucket — private and encrypted
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s05-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s05-bucket", Scenario = "S05" }
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

# EC2 — no public IP but has dangerous admin IAM role attached
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.secure_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s05.name
  associate_public_ip_address = false  # SECURE: not internet facing

  metadata_options {
    http_tokens = "required"  # SECURE: IMDSv2 enforced
  }

  root_block_device {
    encrypted = true  # SECURE
  }

  tags = { Name = "graphshield-s05-ec2", Scenario = "S05" }
}

# No CloudTrail — not the focus of this scenario