# ============================================================
# SCENARIO S26: Public RDS Only
# Label: LOW RISK
# One misconfiguration: RDS instance publicly accessible
# No EC2, no IAM issues — isolated finding
# ============================================================

provider "aws" {
  region = var.region
}

# VPC and networking
resource "aws_vpc" "s26" {
  cidr_block           = "10.26.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s26", Scenario = "S26", Project = "graphshield" }
}

resource "aws_subnet" "s26_a" {
  vpc_id            = aws_vpc.s26.id
  cidr_block        = "10.26.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s26-subnet-a" }
}

resource "aws_subnet" "s26_b" {
  vpc_id            = aws_vpc.s26.id
  cidr_block        = "10.26.2.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s26-subnet-b" }
}

# RDS requires a subnet group with at least 2 AZs
resource "aws_db_subnet_group" "s26" {
  name       = "graphshield-s26-subnet-group"
  subnet_ids = [aws_subnet.s26_a.id, aws_subnet.s26_b.id]
  tags = { Name = "graphshield-s26-subnet-group", Scenario = "S26" }
}

# Security group — allow MySQL from anywhere
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s26-rds-sg"
  description = "INTENTIONALLY INSECURE: MySQL open to world"
  vpc_id      = aws_vpc.s26.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION: open to entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s26-rds-sg", Scenario = "S26" }
}

# RDS instance — publicly accessible, no encryption
resource "aws_db_instance" "s26" {
  identifier        = "graphshield-s26-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.s26.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  publicly_accessible = true   # MISCONFIGURATION: exposed to internet
  storage_encrypted   = false  # MISCONFIGURATION: no encryption at rest
  skip_final_snapshot = true

  tags = { Name = "graphshield-s26-rds", Scenario = "S26" }
}