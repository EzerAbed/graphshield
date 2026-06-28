# ============================================================
# SCENARIO S41: All Ports Open + Public EC2
# Label: CRITICAL
# Every port exposed to internet + public IP + admin IAM
# Maximum network exposure scenario
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s41" {
  cidr_block           = "10.41.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s41", Scenario = "S41", Project = "graphshield" }
}

resource "aws_internet_gateway" "s41" {
  vpc_id = aws_vpc.s41.id
  tags   = { Name = "graphshield-s41-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s41.id
  cidr_block              = "10.41.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s41-subnet" }
}

resource "aws_route_table" "s41" {
  vpc_id = aws_vpc.s41.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s41.id
  }
  tags = { Name = "graphshield-s41-rt" }
}

resource "aws_route_table_association" "s41" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s41.id
}

# MISCONFIGURATION: all traffic open to entire internet
resource "aws_security_group" "all_open_sg" {
  name        = "graphshield-s41-all-open-sg"
  description = "INTENTIONALLY INSECURE: all traffic open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s41.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"           # MISCONFIGURATION: all protocols
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION: entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s41-sg", Scenario = "S41" }
}

# MISCONFIGURATION: AdministratorAccess on EC2 role
resource "aws_iam_role" "admin_role" {
  name = "graphshield-s41-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S41" }
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "s41" {
  name = "graphshield-s41-profile"
  role = aws_iam_role.admin_role.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# MISCONFIGURATION: public IP + all ports open + admin IAM
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.all_open_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s41.name
  associate_public_ip_address = true  # MISCONFIGURATION

  metadata_options {
    http_tokens = "optional"  # MISCONFIGURATION
  }

  root_block_device {
    encrypted = false  # MISCONFIGURATION
  }

  tags = { Name = "graphshield-s41-ec2", Scenario = "S41", InternetFacing = "true" }
}

# S3 bucket — accessible via admin IAM role
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s41-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s41-bucket", Scenario = "S41" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No CloudTrail — attack completely undetected