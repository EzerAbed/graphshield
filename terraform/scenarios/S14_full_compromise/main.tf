# ============================================================
# SCENARIO S14: Full Compromise Chain
# Label: CRITICAL — All misconfigurations combined
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s14" {
  cidr_block = "10.14.0.0/16"
  tags = { Name = "graphshield-s14", Scenario = "S14" }
}

resource "aws_internet_gateway" "s14" {
  vpc_id = aws_vpc.s14.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s14.id
  cidr_block              = "10.14.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s14" {
  vpc_id = aws_vpc.s14.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s14.id
  }
}

resource "aws_route_table_association" "s14" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s14.id
}

resource "aws_security_group" "wide_open" {
  name   = "graphshield-s14-wide-open"
  vpc_id = aws_vpc.s14.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "admin_role" {
  name = "graphshield-s14-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "s14" {
  name = "graphshield-s14-profile"
  role = aws_iam_role.admin_role.name
}

resource "aws_s3_bucket" "public" {
  bucket        = "graphshield-s14-public-${var.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "s14" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

data "aws_ami" "al" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "worst_case" {
  ami                          = data.aws_ami.al.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.wide_open.id]
  iam_instance_profile         = aws_iam_instance_profile.s14.name
  associate_public_ip_address  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    encrypted = false
  }

  tags = { Scenario = "S14", InternetFacing = "true" }
}
