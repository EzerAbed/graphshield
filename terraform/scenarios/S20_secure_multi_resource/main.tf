# ============================================================
# SCENARIO S20: Secure Multi-Resource Deployment
# Label: SAFE — Second clean baseline, broader resource mix
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s20" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s20", Scenario = "S20" }
}

resource "aws_internet_gateway" "s20" {
  vpc_id = aws_vpc.s20.id
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.s20.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
}

resource "aws_security_group" "locked_down" {
  name   = "graphshield-s20-sg"
  vpc_id = aws_vpc.s20.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ec2_minimal" {
  name = "graphshield-s20-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "minimal" {
  name = "graphshield-s20-minimal"
  role = aws_iam_role.ec2_minimal.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::graphshield-s20-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s20" {
  name = "graphshield-s20-profile"
  role = aws_iam_role.ec2_minimal.name
}

resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s20-secure-${var.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudtrail" "enabled" {
  name                          = "graphshield-s20-trail"
  depends_on                    = [aws_s3_bucket_policy.s20_trail_policy]
  s3_bucket_name                = aws_s3_bucket.secure.bucket
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
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
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.private.id
  vpc_security_group_ids       = [aws_security_group.locked_down.id]
  iam_instance_profile         = aws_iam_instance_profile.s20.name
  associate_public_ip_address  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s20-ec2", Scenario = "S20", InternetFacing = "false" }
}

resource "aws_s3_bucket_policy" "s20_trail_policy" {
  bucket = aws_s3_bucket.secure.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::graphshield-s20-secure-${var.bucket_suffix}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::graphshield-s20-secure-${var.bucket_suffix}/*"
      }
    ]
  })
}