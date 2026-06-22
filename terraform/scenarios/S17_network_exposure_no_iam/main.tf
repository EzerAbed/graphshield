# ============================================================
# SCENARIO S17: Multiple Internet-Facing EC2, Open SSH+RDP, No IAM
# Label: MEDIUM RISK — Exposure present, no escalation path
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s17" {
  cidr_block = "10.17.0.0/16"
  tags = { Name = "graphshield-s17", Scenario = "S17" }
}

resource "aws_internet_gateway" "s17" {
  vpc_id = aws_vpc.s17.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s17.id
  cidr_block              = "10.17.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s17" {
  vpc_id = aws_vpc.s17.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s17.id
  }
}

resource "aws_route_table_association" "s17" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s17.id
}

resource "aws_security_group" "open_ports" {
  name   = "graphshield-s17-open-ports"
  vpc_id = aws_vpc.s17.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
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

# Two instances, NO iam_instance_profile attached to either — that's the point
resource "aws_instance" "ec2_a" {
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.open_ports.id]
  associate_public_ip_address  = true
  tags = { Name = "graphshield-s17-ec2-a", Scenario = "S17", InternetFacing = "true" }
}

resource "aws_instance" "ec2_b" {
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.open_ports.id]
  associate_public_ip_address  = true
  tags = { Name = "graphshield-s17-ec2-b", Scenario = "S17", InternetFacing = "true" }
}
