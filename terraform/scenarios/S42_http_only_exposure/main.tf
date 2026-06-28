# ============================================================
# SCENARIO S42: HTTP Only Exposure
# Label: LOW RISK
# Port 80 open to world + public IP but no SSH/RDP
# HTTP exposure without shell access = lower risk
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s42" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s42", Scenario = "S42", Project = "graphshield" }
}

resource "aws_internet_gateway" "s42" {
  vpc_id = aws_vpc.s42.id
  tags   = { Name = "graphshield-s42-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s42.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s42-subnet" }
}

resource "aws_route_table" "s42" {
  vpc_id = aws_vpc.s42.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s42.id
  }
  tags = { Name = "graphshield-s42-rt" }
}

resource "aws_route_table_association" "s42" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s42.id
}

# MISCONFIGURATION: HTTP open to world but no SSH/RDP
resource "aws_security_group" "http_sg" {
  name        = "graphshield-s42-http-sg"
  description = "HTTP open to world — no SSH or RDP"
  vpc_id      = aws_vpc.s42.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION: HTTP open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s42-sg", Scenario = "S42" }
}

# SECURE IAM role — minimal permissions
resource "aws_iam_role" "minimal_role" {
  name = "graphshield-s42-minimal-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S42" }
}

resource "aws_iam_role_policy" "minimal_policy" {
  name = "graphshield-s42-minimal-policy"
  role = aws_iam_role.minimal_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s42-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s42" {
  name = "graphshield-s42-profile"
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

# EC2 with public IP but only HTTP exposed
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.http_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s42.name
  associate_public_ip_address = true  # public but only HTTP exposed

  metadata_options {
    http_tokens = "required"  # SECURE: IMDSv2 enforced
  }

  root_block_device {
    encrypted = true  # SECURE
  }

  tags = { Name = "graphshield-s42-ec2", Scenario = "S42", InternetFacing = "true" }
}

# SECURE S3 bucket
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s42-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s42-bucket", Scenario = "S42" }
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