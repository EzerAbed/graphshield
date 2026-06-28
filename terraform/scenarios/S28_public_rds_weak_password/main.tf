# ============================================================
# SCENARIO S28: Public RDS + Weak Password Policy
# Label: MEDIUM RISK
# Two misconfigurations: publicly accessible + weak auth
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s28" {
  cidr_block           = "10.28.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s28", Scenario = "S28", Project = "graphshield" }
}

resource "aws_subnet" "s28_a" {
  vpc_id            = aws_vpc.s28.id
  cidr_block        = "10.28.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s28-subnet-a" }
}

resource "aws_subnet" "s28_b" {
  vpc_id            = aws_vpc.s28.id
  cidr_block        = "10.28.2.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s28-subnet-b" }
}

resource "aws_db_subnet_group" "s28" {
  name       = "graphshield-s28-subnet-group"
  subnet_ids = [aws_subnet.s28_a.id, aws_subnet.s28_b.id]
  tags = { Name = "graphshield-s28-subnet-group", Scenario = "S28" }
}

# Security group — MySQL open to internet
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s28-rds-sg"
  description = "INTENTIONALLY INSECURE: MySQL open to world"
  vpc_id      = aws_vpc.s28.id

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

  tags = { Name = "graphshield-s28-rds-sg", Scenario = "S28" }
}

# RDS instance — public + weak auth + no encryption
resource "aws_db_instance" "s28" {
  identifier        = "graphshield-s28-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "admin"          # MISCONFIGURATION: default username
  password = var.db_password  # MISCONFIGURATION: weak password

  db_subnet_group_name   = aws_db_subnet_group.s28.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  publicly_accessible    = true   # MISCONFIGURATION: internet exposed
  storage_encrypted      = false  # MISCONFIGURATION: no encryption
  iam_database_authentication_enabled = false  # MISCONFIGURATION: no IAM auth
  skip_final_snapshot    = true

  tags = { Name = "graphshield-s28-rds", Scenario = "S28" }
}