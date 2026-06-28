# ============================================================
# SCENARIO S27: RDS No Encryption
# Label: LOW RISK
# One misconfiguration: storage_encrypted=false
# Private access only — isolated finding
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s27" {
  cidr_block           = "10.27.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s27", Scenario = "S27", Project = "graphshield" }
}

resource "aws_subnet" "s27_a" {
  vpc_id            = aws_vpc.s27.id
  cidr_block        = "10.27.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s27-subnet-a" }
}

resource "aws_subnet" "s27_b" {
  vpc_id            = aws_vpc.s27.id
  cidr_block        = "10.27.2.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s27-subnet-b" }
}

resource "aws_db_subnet_group" "s27" {
  name       = "graphshield-s27-subnet-group"
  subnet_ids = [aws_subnet.s27_a.id, aws_subnet.s27_b.id]
  tags = { Name = "graphshield-s27-subnet-group", Scenario = "S27" }
}

# SECURE Security Group — no public access
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s27-rds-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s27.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s27-rds-sg", Scenario = "S27" }
}

# RDS instance — private but unencrypted
resource "aws_db_instance" "s27" {
  identifier        = "graphshield-s27-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.s27.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  publicly_accessible = false  # SECURE: private only
  storage_encrypted   = false  # MISCONFIGURATION: no encryption at rest
  skip_final_snapshot = true

  tags = { Name = "graphshield-s27-rds", Scenario = "S27" }
}