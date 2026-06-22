# ============================================================
# SCENARIO S24: Public Lambda Function URL, Scoped Permissions
# Label: LOW/MEDIUM RISK — Exposed, but minimal IAM blast radius
# ============================================================
terraform {
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_iam_role" "lambda_exec" {
  name = "graphshield-s24-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
# Note: NO additional S3/admin permissions attached — scoped to logging only

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"
  source {
    content  = "exports.handler = async () => ({ statusCode: 200, body: 'ok' });"
    filename = "index.js"
  }
}

resource "aws_lambda_function" "public_fn" {
  function_name    = "graphshield-s24-fn"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  tags = { Scenario = "S24" }
}

# MISCONFIGURATION: Function URL with no auth, exposed to the internet
resource "aws_lambda_function_url" "public_url" {
  function_name      = aws_lambda_function.public_fn.function_name
  authorization_type  = "NONE"
}
