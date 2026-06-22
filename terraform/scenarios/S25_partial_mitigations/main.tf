# ============================================================
# SCENARIO S25: Open SSH + Admin IAM, But Encrypted Disk + Logging On
# Label: HIGH RISK — Severe misconfig, partial mitigations present
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_vpc" "s25" {
  cidr_block = "10.25.0.0/16"
  tags = { Name = "graphshield-s25", Scenario = "S25" }
}

resource "aws_internet_gateway" "s25" {
  vpc_id = aws_vpc.s25.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.s25.id
  cidr_block              = "10.25.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "s25" {
  vpc_id = aws_vpc.s25.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.s25.id
  }
}

resource "aws_route_table_association" "s25" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.s25.id
}

resource "aws_security_group" "open_ssh" {
  name   = "graphshield-s25-open-ssh"
  vpc_id = aws_vpc.s25.id

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

resource "aws_iam_role" "admin_role" {
  name = "graphshield-s25-admin"
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

resource "aws_iam_instance_profile" "s25" {
  name = "graphshield-s25-profile"
  role = aws_iam_role.admin_role.name
}

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "graphshield-s25-trail-${var.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail_logs_policy" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::graphshield-s25-trail-${var.bucket_suffix}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::graphshield-s25-trail-${var.bucket_suffix}/*"
      }
    ]
  })
}

# MITIGATION: logging IS enabled here (unlike S14/S15)
resource "aws_cloudtrail" "enabled" {
  name                          = "graphshield-s25-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.trail_logs_policy]
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
  ami                          = data.aws_ami.amazon_linux.id
  instance_type                = "t3.micro"
  subnet_id                    = aws_subnet.public.id
  vpc_security_group_ids       = [aws_security_group.open_ssh.id]
  iam_instance_profile         = aws_iam_instance_profile.s25.name
  associate_public_ip_address  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # MITIGATION
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true # MITIGATION
  }

  tags = { Name = "graphshield-s25-ec2", Scenario = "S25", InternetFacing = "true" }
}
