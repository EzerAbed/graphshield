# ============================================================
# SCENARIO S13: EC2 With IAM PassRole Permission
# Label: CRITICAL — Privilege escalation vector
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s13" {
  cidr_block = "10.13.0.0/16"
  tags = { Name = "graphshield-s13", Scenario = "S13" }
}

resource "aws_internet_gateway" "s13" {
  vpc_id = aws_vpc.s13.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s13.id
  cidr_block              = "10.13.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s13" {
  vpc_id = aws_vpc.s13.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s13.id
  }
}

resource "aws_route_table_association" "s13" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s13.id
}

resource "aws_security_group" "open_ssh" {
  name   = "graphshield-s13-open-ssh"
  vpc_id = aws_vpc.s13.id

  ingress {
    from_port   = 22
    to_port     = 22
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

resource "aws_iam_role" "ec2_escalate" {
  name = "graphshield-s13-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# --- THE MISCONFIGURATION: PassRole + role creation = escalation path ---
resource "aws_iam_role_policy" "escalation_policy" {
  name = "graphshield-s13-escalation"
  role = aws_iam_role.ec2_escalate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:PassRole",          # MISCONFIGURATION
        "iam:CreateRole",        # MISCONFIGURATION
        "iam:AttachRolePolicy",  # MISCONFIGURATION
        "ec2:RunInstances",
        "lambda:CreateFunction"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "s13" {
  name = "graphshield-s13-profile"
  role = aws_iam_role.ec2_escalate.name
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
  iam_instance_profile         = aws_iam_instance_profile.s13.name
  associate_public_ip_address  = true

  tags = { Name = "graphshield-s13-ec2", Scenario = "S13", InternetFacing = "true" }
}
