# ============================================================
# SCENARIO S29: EC2 to RDS Attack Chain
# Label: HIGH RISK
# Full chain: Internet -> EC2 (SSH open) -> IAM role (rds:*)
# -> RDS instance (lateral movement to database)
# ============================================================

provider "aws" {
  region = var.region
}

# VPC with internet gateway for public EC2
resource "aws_vpc" "s29" {
  cidr_block           = "10.29.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s29", Scenario = "S29", Project = "graphshield" }
}

resource "aws_internet_gateway" "s29" {
  vpc_id = aws_vpc.s29.id
  tags   = { Name = "graphshield-s29-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s29.id
  cidr_block              = "10.29.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "graphshield-s29-public" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.s29.id
  cidr_block        = "10.29.2.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s29-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.s29.id
  cidr_block        = "10.29.3.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s29-private-b" }
}

resource "aws_route_table" "s29" {
  vpc_id = aws_vpc.s29.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s29.id
  }
  tags = { Name = "graphshield-s29-rt" }
}

resource "aws_route_table_association" "s29" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s29.id
}

resource "aws_db_subnet_group" "s29" {
  name       = "graphshield-s29-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags = { Name = "graphshield-s29-subnet-group", Scenario = "S29" }
}

# MISCONFIGURATION 1: SSH open to entire internet
resource "aws_security_group" "ec2_sg" {
  name        = "graphshield-s29-ec2-sg"
  description = "INTENTIONALLY INSECURE: SSH open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s29.id

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

  tags = { Name = "graphshield-s29-ec2-sg", Scenario = "S29" }
}

# RDS security group — allows access from EC2
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s29-rds-sg"
  description = "RDS accessible from EC2"
  vpc_id      = aws_vpc.s29.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s29-rds-sg", Scenario = "S29" }
}

# MISCONFIGURATION 2: IAM role with rds:* wildcard
resource "aws_iam_role" "ec2_rds_role" {
  name = "graphshield-s29-ec2-rds-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S29" }
}

resource "aws_iam_role_policy" "rds_full" {
  name = "graphshield-s29-rds-full"
  role = aws_iam_role.ec2_rds_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "rds:*"   # MISCONFIGURATION: full RDS access
      Resource = "*"       # MISCONFIGURATION: on all resources
    }]
  })
}

resource "aws_iam_instance_profile" "s29" {
  name = "graphshield-s29-profile"
  role = aws_iam_role.ec2_rds_role.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# MISCONFIGURATION 3: EC2 with public IP + dangerous IAM role
resource "aws_instance" "instance" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.s29.name
  associate_public_ip_address = true  # MISCONFIGURATION: internet facing

  metadata_options {
    http_tokens = "optional"  # MISCONFIGURATION: IMDSv2 not enforced
  }

  root_block_device {
    encrypted = false  # MISCONFIGURATION: unencrypted disk
  }

  tags = { Name = "graphshield-s29-ec2", Scenario = "S29", InternetFacing = "true" }
}

# RDS instance — private but accessible via EC2 IAM role
resource "aws_db_instance" "s29" {
  identifier        = "graphshield-s29-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.s29.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  publicly_accessible = false  # private but reachable via EC2
  storage_encrypted   = false
  skip_final_snapshot = true

  tags = { Name = "graphshield-s29-rds", Scenario = "S29" }
}

# No CloudTrail — attack leaves no trace