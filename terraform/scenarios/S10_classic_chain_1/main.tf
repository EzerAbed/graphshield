# ============================================================
# SCENARIO S10: Public EC2 + Open SSH + IAM Role with S3:*
# Label: HIGH RISK — Complete attack chain
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s10" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s10", Scenario = "S10", Project = "graphshield" }
}

resource "aws_internet_gateway" "s10" {
  vpc_id = aws_vpc.s10.id
  tags   = { Name = "graphshield-s10-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s10.id
  cidr_block              = "10.10.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s10-public" }
}

resource "aws_route_table" "s10" {
  vpc_id = aws_vpc.s10.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s10.id
  }
  tags = { Name = "graphshield-s10-rt" }
}

resource "aws_route_table_association" "s10" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s10.id
}

resource "aws_security_group" "open_ssh" {
  name        = "graphshield-s10-open-ssh"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s10.id

  ingress {
    description = "SSH open to entire internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP open"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s10-sg", Scenario = "S10" }
}

resource "aws_iam_role" "ec2_s3_full" {
  name = "graphshield-s10-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Scenario = "S10" }
}

resource "aws_iam_role_policy" "s3_full_access" {
  name = "graphshield-s10-s3-full"
  role = aws_iam_role.ec2_s3_full.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "s10" {
  name = "graphshield-s10-profile"
  role = aws_iam_role.ec2_s3_full.name
}

resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s10-target-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S10", Sensitivity = "High" }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "public_ec2" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.open_ssh.id]
  iam_instance_profile         = aws_iam_instance_profile.s10.name
  associate_public_ip_address  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    encrypted = false
  }

  tags = { Name = "graphshield-s10-ec2", Scenario = "S10", InternetFacing = "true" }
}
