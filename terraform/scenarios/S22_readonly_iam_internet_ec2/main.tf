# ============================================================
# SCENARIO S22: Internet EC2 With Scoped Read-Only IAM Role
# Label: LOW RISK — Exposure present, IAM properly scoped
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s22" {
  cidr_block = "10.22.0.0/16"
  tags = { Name = "graphshield-s22", Scenario = "S22" }
}

resource "aws_internet_gateway" "s22" {
  vpc_id = aws_vpc.s22.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s22.id
  cidr_block              = "10.22.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s22" {
  vpc_id = aws_vpc.s22.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s22.id
  }
}

resource "aws_route_table_association" "s22" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s22.id
}

resource "aws_security_group" "https_only" {
  name   = "graphshield-s22-https-only"
  vpc_id = aws_vpc.s22.id

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
}

resource "aws_iam_role" "ec2_readonly" {
  name = "graphshield-s22-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "readonly" {
  name = "graphshield-s22-readonly"
  role = aws_iam_role.ec2_readonly.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"] # SCOPED — not a wildcard
      Resource = "arn:aws:s3:::graphshield-s22-*/*"
    }]
  })
}

resource "aws_iam_instance_profile" "s22" {
  name = "graphshield-s22-profile"
  role = aws_iam_role.ec2_readonly.name
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
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.https_only.id]
  iam_instance_profile         = aws_iam_instance_profile.s22.name
  associate_public_ip_address  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "graphshield-s22-ec2", Scenario = "S22", InternetFacing = "true" }
}
