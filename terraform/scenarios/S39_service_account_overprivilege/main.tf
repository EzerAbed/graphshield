# ============================================================
# SCENARIO S39: Service Account Over-Privilege
# Label: MEDIUM RISK
# Lambda execution role with AdministratorAccess
# Lambda not public but role is excessively powerful
# ============================================================

provider "aws" {
  region = var.region
}

# MISCONFIGURATION: Lambda role with AdministratorAccess
resource "aws_iam_role" "lambda_admin_role" {
  name = "graphshield-s39-lambda-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S39", Project = "graphshield" }
}

# MISCONFIGURATION: full admin on a Lambda role
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Basic execution for logs
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function — private, no public URL
resource "local_file" "lambda_code" {
  filename = "${path.module}/lambda/index.js"
  content  = <<-EOF
    exports.handler = async (event) => {
      return {
        statusCode: 200,
        body: JSON.stringify({ message: "graphshield-s39" })
      };
    };
  EOF
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda.zip"
  depends_on  = [local_file.lambda_code]
}

resource "aws_lambda_function" "private_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "graphshield-s39-lambda"
  role             = aws_iam_role.lambda_admin_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # SECURE: no public URL — Lambda not directly invocable from internet
  tags = { Scenario = "S39", Project = "graphshield" }
}

# SECURE S3 bucket
resource "aws_s3_bucket" "secure" {
  bucket        = "graphshield-s39-bucket-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s39-bucket", Scenario = "S39" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No public URL on Lambda — not directly exploitable from internet
# Risk: if Lambda is triggered via internal event, runs with full admin