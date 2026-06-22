# ============================================================
# SCENARIO S12: EC2 Can Assume Role That Accesses RDS
# Label: HIGH RISK — Lateral movement path into database tier
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s12" {
  cidr_block = "10.12.0.0/16"
  tags = { Name = "graphshield-s12", Scenario = "S12" }
}

resource "aws_internet_gateway" "s12" {
  vpc_id = aws_vpc.s12.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s12.id
  cidr_block              = "10.12.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "db_a" {
  vpc_id            = aws_vpc.s12.id
  cidr_block        = "10.12.2.0/24"
  availability_zone = "${var.region}a"
}

resource "aws_subnet" "db_b" {
  vpc_id            = aws_vpc.s12.id
  cidr_block        = "10.12.3.0/24"
  availability_zone = "${var.region}b"
}

resource "aws_route_table" "s12" {
  vpc_id = aws_vpc.s12.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s12.id
  }
}

resource "aws_route_table_association" "s12" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s12.id
}

resource "aws_db_subnet_group" "s12" {
  name       = "graphshield-s12-dbsubnets"
  subnet_ids = [aws_subnet.db_a.id, aws_subnet.db_b.id]
}

resource "aws_security_group" "open_ssh" {
  name   = "graphshield-s12-open-ssh"
  vpc_id = aws_vpc.s12.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # MISCONFIGURATION
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds_sg" {
  name   = "graphshield-s12-rds-sg"
  vpc_id = aws_vpc.s12.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.open_ssh.id] # EC2 -> RDS path
  }
}

resource "aws_iam_role" "ec2_rds_access" {
  name = "graphshield-s12-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "rds_connect" {
  name = "graphshield-s12-rds-connect"
  role = aws_iam_role.ec2_rds_access.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["rds-db:connect", "rds:DescribeDBInstances"]
      Resource = "*" # MISCONFIGURATION: should be scoped to specific DB resource ARN
    }]
  })
}

resource "aws_iam_instance_profile" "s12" {
  name = "graphshield-s12-profile"
  role = aws_iam_role.ec2_rds_access.name
}

resource "aws_db_instance" "target" {
  identifier             = "graphshield-s12-db-${var.bucket_suffix}"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "TempPassword123!" # demo only — never reuse in production
  db_subnet_group_name   = aws_db_subnet_group.s12.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible    = false
  skip_final_snapshot    = true
  tags = { Scenario = "S12" }
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
  iam_instance_profile         = aws_iam_instance_profile.s12.name
  associate_public_ip_address  = true

  tags = { Name = "graphshield-s12-ec2", Scenario = "S12", InternetFacing = "true" }
}
