# ============================================================
# SCENARIO S35: IAM PassRole Misconfiguration
# Label: HIGH RISK
# EC2 with iam:PassRole on * — can escalate to any role
# Privilege escalation without direct admin access
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s35" {
  cidr_block           = "10.35.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s35", Scenario = "S35", Project = "graphshield" }
}

resource "aws_internet_gateway" "s35" {
  vpc_id = aws_vpc.s35.id
  tags   = { Name = "graphshield-s35-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s35.id
  cidr_block              = "10.35.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s35-subnet" }
}

resource "aws_route_table" "s35" {
  vpc_id = aws_vpc.s35.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s35.id
  }
  tags = { Name = "graphshield-s35-rt" }
}

resource "aws_route_table_association" "s35" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s35.id
}

# MISCONFIGURATION: SSH open to internet
resource "aws_security_group" "sg" {
  name        = "graphshield-s35-sg"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s35.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s35-sg", Scenario = "S35" }
}

# MISCONFIGURATION: EC2 role with iam:PassRole on all resources
resource "aws_iam_role" "passrole_role" {
  name = "graphshield-s35-passrole-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S35" }
}

resource "aws_iam_role_policy" "passrole_policy" {
  name = "graphshield-s35-passrole-policy"
  role = aws_iam_role.passrole_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"  # MISCONFIGURATION: can pass any role
        Resource = "*"             # MISCONFIGURATION: to any service
      },
      {
        Effect   = "Allow"
        Action   = [
          "iam:ListRoles",
          "iam:GetRole",
          "ec2:RunInstances",
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "s35" {
  name = "graphshield-s35-profile"
  role = aws_iam_role.passrole_role.name
}

# High privilege role that can be passed
resource "aws_iam_role" "high_priv_role" {
  name = "graphshield-s35-high-priv-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S35" }
}

resource "aws_iam_role_policy" "high_priv_policy" {
  name = "graphshield-s35-high-priv-policy"
  role = aws_iam_role.high_priv_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 with public IP and PassRole capability
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s35.name
  associate_public_ip_address = true  # MISCONFIGURATION

  metadata_options {
    http_tokens = "optional"  # MISCONFIGURATION
  }

  root_block_device {
    encrypted = false  # MISCONFIGURATION
  }

  tags = { Name = "graphshield-s35-ec2", Scenario = "S35", InternetFacing = "true" }
}

# S3 bucket — reachable via PassRole escalation
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s35-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s35-bucket", Scenario = "S35" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No CloudTrail