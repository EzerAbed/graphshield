# ============================================================
# SCENARIO S32: Role Hopping Chain
# Label: CRITICAL
# EC2 Role A -> assumes Role B -> assumes Role C (Admin)
# Three hops to full administrator access
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s32" {
  cidr_block           = "10.32.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s32", Scenario = "S32", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id            = aws_vpc.s32.id
  cidr_block        = "10.32.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s32-subnet" }
}

# SECURE Security Group — no open ports
resource "aws_security_group" "sg" {
  name        = "graphshield-s32-sg"
  description = "SECURE: no public inbound"
  vpc_id      = aws_vpc.s32.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s32-sg", Scenario = "S32" }
}

# ROLE A — attached to EC2, can assume Role B
# MISCONFIGURATION: sts:AssumeRole too broadly granted
resource "aws_iam_role" "role_a" {
  name = "graphshield-s32-role-a"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S32" }
}

resource "aws_iam_role_policy" "role_a_policy" {
  name = "graphshield-s32-role-a-policy"
  role = aws_iam_role.role_a.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.role_b.arn  # MISCONFIGURATION: can hop to Role B
    }]
  })
}

resource "aws_iam_instance_profile" "s32" {
  name = "graphshield-s32-profile"
  role = aws_iam_role.role_a.name
}

# ROLE B — intermediate hop, can assume Role C
resource "aws_iam_role" "role_b" {
  name = "graphshield-s32-role-b"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.role_a.arn }  # Role A can assume Role B
    }]
  })

  tags = { Scenario = "S32" }
}

resource "aws_iam_role_policy" "role_b_policy" {
  name = "graphshield-s32-role-b-policy"
  role = aws_iam_role.role_b.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.role_c.arn  # MISCONFIGURATION: can hop to Role C
    }]
  })
}

# ROLE C — final hop, full AdministratorAccess
resource "aws_iam_role" "role_c" {
  name = "graphshield-s32-role-c-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.role_b.arn }  # Role B can assume Role C
    }]
  })

  tags = { Scenario = "S32" }
}

# MISCONFIGURATION: full admin at the end of the chain
resource "aws_iam_role_policy_attachment" "role_c_admin" {
  role       = aws_iam_role.role_c.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# S3 bucket — target of the attack chain
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s32-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s32-bucket", Scenario = "S32" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 — no public IP but has role hopping capability
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s32.name
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s32-ec2", Scenario = "S32" }
}

# No CloudTrail — role hopping leaves no trace