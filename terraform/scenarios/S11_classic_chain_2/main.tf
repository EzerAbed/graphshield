# ============================================================
# SCENARIO S11: Public S3 + IAM Role on EC2 + S3 Contains Creds
# Label: CRITICAL — Public bucket reachable directly AND via EC2
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s11" {
  cidr_block = "10.11.0.0/16"
  tags = { Name = "graphshield-s11", Scenario = "S11" }
}

resource "aws_internet_gateway" "s11" {
  vpc_id = aws_vpc.s11.id
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.s11.id
  cidr_block              = "10.11.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
}

# EC2 has no public IP, but its IAM role can still reach the bucket
resource "aws_security_group" "internal_only" {
  name   = "graphshield-s11-internal"
  vpc_id = aws_vpc.s11.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ec2_s3_read" {
  name = "graphshield-s11-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "s3_read" {
  name = "graphshield-s11-s3-read"
  role = aws_iam_role.ec2_s3_read.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::graphshield-s11-creds-${var.bucket_suffix}",
        "arn:aws:s3:::graphshield-s11-creds-${var.bucket_suffix}/*"
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "s11" {
  name = "graphshield-s11-profile"
  role = aws_iam_role.ec2_s3_read.name
}

# --- THE MISCONFIGURATION: bucket is public despite "sensitive" contents ---
resource "aws_s3_bucket" "creds" {
  bucket        = "graphshield-s11-creds-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S11", Sensitivity = "Critical" }
}

resource "aws_s3_bucket_public_access_block" "creds" {
  bucket                  = aws_s3_bucket.creds.id
  block_public_acls       = false # MISCONFIGURATION
  block_public_policy     = false # MISCONFIGURATION
  ignore_public_acls      = false # MISCONFIGURATION
  restrict_public_buckets = false # MISCONFIGURATION
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "private_ec2" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.private.id
  vpc_security_group_ids       = [aws_security_group.internal_only.id]
  iam_instance_profile         = aws_iam_instance_profile.s11.name
  associate_public_ip_address  = false

  root_block_device {
    encrypted = false
  }

  tags = { Name = "graphshield-s11-ec2", Scenario = "S11", InternetFacing = "false" }
}
