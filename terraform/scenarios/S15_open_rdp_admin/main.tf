# ============================================================
# SCENARIO S15: Open RDP + Admin IAM Role on Internet-Facing EC2
# Label: CRITICAL
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s15" {
  cidr_block = "10.15.0.0/16"
  tags = { Name = "graphshield-s15", Scenario = "S15" }
}

resource "aws_internet_gateway" "s15" {
  vpc_id = aws_vpc.s15.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s15.id
  cidr_block              = "10.15.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s15" {
  vpc_id = aws_vpc.s15.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s15.id
  }
}

resource "aws_route_table_association" "s15" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s15.id
}

resource "aws_security_group" "open_rdp" {
  name        = "graphshield-s15-open-rdp"
  description = "INTENTIONALLY INSECURE: RDP open to 0.0.0.0/0"
  vpc_id      = aws_vpc.s15.id

  ingress {
    from_port   = 3389
    to_port     = 3389
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

resource "aws_iam_role" "admin_role" {
  name = "graphshield-s15-admin"
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
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # MISCONFIGURATION
}

resource "aws_iam_instance_profile" "s15" {
  name = "graphshield-s15-profile"
  role = aws_iam_role.admin_role.name
}

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "rdp_ec2" {
  ami                          = data.aws_ami.windows.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.open_rdp.id]
  iam_instance_profile         = aws_iam_instance_profile.s15.name
  associate_public_ip_address  = true

  tags = { Name = "graphshield-s15-ec2", Scenario = "S15", InternetFacing = "true" }
}
