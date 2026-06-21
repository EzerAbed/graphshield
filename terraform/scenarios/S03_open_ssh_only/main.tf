# ============================================================
# SCENARIO S03: Open SSH Only
# Label: LOW RISK
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s03" {
  cidr_block           = "10.3.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s03", Scenario = "S03", Project = "graphshield" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.s03.id
  cidr_block              = "10.3.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false  # SECURE: no public IP
  tags = { Name = "graphshield-s03-subnet" }
}

# MISCONFIGURATION: SSH open to entire internet
resource "aws_security_group" "open_ssh" {
  name        = "graphshield-s03-open-ssh"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s03.id

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

  tags = { Name = "graphshield-s03-sg", Scenario = "S03" }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# EC2 — no public IP, no dangerous IAM role
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main.id
  vpc_security_group_ids      = [aws_security_group.open_ssh.id]
  associate_public_ip_address = false  # SECURE: not reachable from internet

  metadata_options {
    http_tokens = "required"  # SECURE: IMDSv2 enforced
  }

  root_block_device {
    encrypted = true  # SECURE
  }

  tags = { Name = "graphshield-s03-ec2", Scenario = "S03" }
}