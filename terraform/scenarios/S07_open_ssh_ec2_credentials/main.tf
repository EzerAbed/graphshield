# ============================================================
# SCENARIO S07: Open SSH + EC2 Credentials
# Label: MEDIUM RISK
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s07" {
  cidr_block           = "10.7.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s07", Scenario = "S07", Project = "graphshield" }
}

resource "aws_internet_gateway" "s07" {
  vpc_id = aws_vpc.s07.id
  tags   = { Name = "graphshield-s07-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s07.id
  cidr_block              = "10.7.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "graphshield-s07-subnet" }
}

resource "aws_route_table" "s07" {
  vpc_id = aws_vpc.s07.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s07.id
  }
  tags = { Name = "graphshield-s07-rt" }
}

resource "aws_route_table_association" "s07" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s07.id
}

# MISCONFIGURATION 1: SSH open to entire internet
resource "aws_security_group" "open_ssh" {
  name        = "graphshield-s07-open-ssh"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s07.id

  ingress {
    description = "SSH open to entire internet"
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

  tags = { Name = "graphshield-s07-sg", Scenario = "S07" }
}

# MISCONFIGURATION 2: EC2 instance profile with S3 read access
# Limited permissions but still a credential exposure risk via SSH
resource "aws_iam_role" "s3_read_role" {
  name = "graphshield-s07-s3-read-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S07" }
}

resource "aws_iam_role_policy" "s3_read" {
  name = "graphshield-s07-s3-read"
  role = aws_iam_role.s3_read_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]  # Limited but exposed via SSH
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "s07" {
  name = "graphshield-s07-profile"
  role = aws_iam_role.s3_read_role.name
}

# SECURE S3 Bucket — private and encrypted
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s07-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s07-bucket", Scenario = "S07" }
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

# EC2 — no public IP but SSH open and has S3 credentials
# Missing public IP is what keeps this Medium instead of High
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.open_ssh.id]
  iam_instance_profile        = aws_iam_instance_profile.s07.name
  associate_public_ip_address = false  # No public IP — chain incomplete

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s07-ec2", Scenario = "S07" }
}

# No CloudTrail