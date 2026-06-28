# ============================================================
# SCENARIO S37: Inline Policy Wildcard
# Label: HIGH RISK
# EC2 role with Action:* Resource:* via inline policy
# Full AWS access — harder to detect than managed policies
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s37" {
  cidr_block           = "10.37.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s37", Scenario = "S37", Project = "graphshield" }
}

resource "aws_internet_gateway" "s37" {
  vpc_id = aws_vpc.s37.id
  tags   = { Name = "graphshield-s37-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s37.id
  cidr_block              = "10.37.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s37-subnet" }
}

resource "aws_route_table" "s37" {
  vpc_id = aws_vpc.s37.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s37.id
  }
  tags = { Name = "graphshield-s37-rt" }
}

resource "aws_route_table_association" "s37" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s37.id
}

# MISCONFIGURATION: SSH open to internet
resource "aws_security_group" "sg" {
  name        = "graphshield-s37-sg"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s37.id

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

  tags = { Name = "graphshield-s37-sg", Scenario = "S37" }
}

# EC2 role with inline wildcard policy
resource "aws_iam_role" "wildcard_role" {
  name = "graphshield-s37-wildcard-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S37" }
}

# MISCONFIGURATION: inline policy with full wildcard access
# Action:* Resource:* = full AWS control via inline policy
resource "aws_iam_role_policy" "wildcard_inline" {
  name = "graphshield-s37-wildcard-inline"
  role = aws_iam_role.wildcard_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"   # MISCONFIGURATION: all AWS actions
      Resource = "*"   # MISCONFIGURATION: on all resources
    }]
  })
}

resource "aws_iam_instance_profile" "s37" {
  name = "graphshield-s37-profile"
  role = aws_iam_role.wildcard_role.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 with public IP and full wildcard inline policy
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s37.name
  associate_public_ip_address = true  # MISCONFIGURATION

  metadata_options {
    http_tokens = "optional"  # MISCONFIGURATION
  }

  root_block_device {
    encrypted = false  # MISCONFIGURATION
  }

  tags = { Name = "graphshield-s37-ec2", Scenario = "S37", InternetFacing = "true" }
}

# S3 bucket — accessible via wildcard inline policy
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s37-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s37-bucket", Scenario = "S37" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No CloudTrail