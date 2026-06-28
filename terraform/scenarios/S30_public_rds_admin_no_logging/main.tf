# ============================================================
# SCENARIO S30: Public RDS + Admin IAM + No Logging
# Label: CRITICAL
# Full chain: Internet -> EC2 (SSH) -> Admin IAM -> RDS (public)
# No CloudTrail — attack completely undetected
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s30" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s30", Scenario = "S30", Project = "graphshield" }
}

resource "aws_internet_gateway" "s30" {
  vpc_id = aws_vpc.s30.id
  tags   = { Name = "graphshield-s30-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s30.id
  cidr_block              = "10.30.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s30-public" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.s30.id
  cidr_block        = "10.30.2.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s30-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.s30.id
  cidr_block        = "10.30.3.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s30-private-b" }
}

resource "aws_route_table" "s30" {
  vpc_id = aws_vpc.s30.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s30.id
  }
  tags = { Name = "graphshield-s30-rt" }
}

resource "aws_route_table_association" "s30" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s30.id
}

resource "aws_db_subnet_group" "s30" {
  name       = "graphshield-s30-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags = { Name = "graphshield-s30-subnet-group", Scenario = "S30" }
}

# MISCONFIGURATION 1: SSH open to entire internet
resource "aws_security_group" "ec2_sg" {
  name        = "graphshield-s30-ec2-sg"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s30.id

  ingress {
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

  tags = { Name = "graphshield-s30-ec2-sg", Scenario = "S30" }
}

# RDS security group — MySQL open to internet
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s30-rds-sg"
  description = "INTENTIONALLY INSECURE: MySQL open to world"
  vpc_id      = aws_vpc.s30.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s30-rds-sg", Scenario = "S30" }
}

# MISCONFIGURATION 2: AdministratorAccess on EC2 role
resource "aws_iam_role" "admin_role" {
  name = "graphshield-s30-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S30" }
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "s30" {
  name = "graphshield-s30-profile"
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

# MISCONFIGURATION 3: Public EC2 with admin IAM
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s30.name
  associate_public_ip_address = true  # MISCONFIGURATION

  metadata_options {
    http_tokens = "optional"  # MISCONFIGURATION
  }

  root_block_device {
    encrypted = false  # MISCONFIGURATION
  }

  tags = { Name = "graphshield-s30-ec2", Scenario = "S30", InternetFacing = "true" }
}

# MISCONFIGURATION 4: RDS publicly accessible + no encryption
resource "aws_db_instance" "s30" {
  identifier        = "graphshield-s30-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.s30.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]