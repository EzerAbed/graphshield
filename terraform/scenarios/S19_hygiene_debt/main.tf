# ============================================================
# SCENARIO S19: Hygiene Issues Only — No Active Attack Chain
# Label: LOW RISK
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s19" {
  cidr_block = "10.19.0.0/16"
  tags = { Name = "graphshield-s19", Scenario = "S19" }
}

resource "aws_internet_gateway" "s19" {
  vpc_id = aws_vpc.s19.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s19.id
  cidr_block              = "10.19.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s19" {
  vpc_id = aws_vpc.s19.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s19.id
  }
}

resource "aws_route_table_association" "s19" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s19.id
}

# Only HTTPS open — no SSH/RDP
resource "aws_security_group" "https_only" {
  name   = "graphshield-s19-https-only"
  vpc_id = aws_vpc.s19.id

  ingress {
    from_port   = 443
    to_port     = 443
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

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "hygiene_debt_ec2" {
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.https_only.id]
  associate_public_ip_address  = true
  # NO iam_instance_profile — no escalation path

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # MISCONFIGURATION: IMDSv1 still allowed
  }

  root_block_device {
    encrypted = false # MISCONFIGURATION
  }

  tags = { Name = "graphshield-s19-ec2", Scenario = "S19", InternetFacing = "true" }
}
# No aws_cloudtrail resource — logging intentionally disabled (MISCONFIGURATION)
