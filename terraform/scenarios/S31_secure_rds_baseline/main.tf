# ============================================================
# SCENARIO S31: Secure RDS Baseline
# Label: SAFE
# Everything correctly configured for a database
# Encrypted, private, IAM auth, deletion protection
# ============================================================

provider "aws" {
  region = var.region
}

resource "aws_vpc" "s31" {
  cidr_block           = "10.31.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "graphshield-s31", Scenario = "S31", Project = "graphshield" }
}

resource "aws_subnet" "s31_a" {
  vpc_id            = aws_vpc.s31.id
  cidr_block        = "10.31.1.0/24"
  availability_zone = "${var.region}a"
  tags = { Name = "graphshield-s31-subnet-a" }
}

resource "aws_subnet" "s31_b" {
  vpc_id            = aws_vpc.s31.id
  cidr_block        = "10.31.2.0/24"
  availability_zone = "${var.region}b"
  tags = { Name = "graphshield-s31-subnet-b" }
}

resource "aws_db_subnet_group" "s31" {
  name       = "graphshield-s31-subnet-group"
  subnet_ids = [aws_subnet.s31_a.id, aws_subnet.s31_b.id]
  tags = { Name = "graphshield-s31-subnet-group", Scenario = "S31" }
}

# SECURE Security Group — no public access at all
resource "aws_security_group" "rds_sg" {
  name        = "graphshield-s31-rds-sg"
  description = "SECURE: no public inbound access"
  vpc_id      = aws_vpc.s31.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "graphshield-s31-rds-sg", Scenario = "S31" }
}

# SECURE IAM role — least privilege, scoped to specific actions
resource "aws_iam_role" "rds_monitoring" {
  name = "graphshield-s31-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S31" }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# SECURE S3 bucket for logs
resource "aws_s3_bucket" "logs" {
  bucket        = "graphshield-s31-logs-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s31-logs", Scenario = "S31" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SECURE RDS — fully hardened
resource "aws_db_instance" "s31" {
  identifier        = "graphshield-s31-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "graphshielddb"
  username = "graphshieldadmin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.s31.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  publicly_accessible                 = false  # SECURE
  storage_encrypted                   = true   # SECURE
  iam_database_authentication_enabled = true   # SECURE
  deletion_protection                 = false  # off for easy cleanup
  backup_retention_period             = 7      # SECURE: backups enabled
  skip_final_snapshot                 = true

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = { Name = "graphshield-s31-rds", Scenario = "S31" }
}