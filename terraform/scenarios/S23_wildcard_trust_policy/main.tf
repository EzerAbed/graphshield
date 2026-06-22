# ============================================================
# SCENARIO S23: IAM Role With Wildcard Trust Policy
# Label: CRITICAL — Any AWS account can assume this role
# ============================================================
provider "aws" {
  region = var.region
}

resource "aws_iam_role" "open_trust" {
  name = "graphshield-s23-open-trust"
  # MISCONFIGURATION: Principal is a wildcard — ANY account can assume this role,
  # not just your own. This is one of the most dangerous IAM misconfigurations.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "*" }
    }]
  })
  tags = { Scenario = "S23" }
}

resource "aws_iam_role_policy" "s3_full" {
  name = "graphshield-s23-s3-full"
  role = aws_iam_role.open_trust.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s23-target-${var.bucket_suffix}"
  force_destroy = true
  tags = { Scenario = "S23", Sensitivity = "Critical" }
}
