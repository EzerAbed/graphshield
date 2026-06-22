# ============================================================
# SCENARIO S09: Exposed Lambda + Wide Permissions
# Label: HIGH RISK
# ============================================================

provider "aws" {
  region = var.region
}

# MISCONFIGURATION 1: Lambda IAM role with s3:* wildcard
resource "aws_iam_role" "lambda_role" {
  name = "graphshield-s09-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Scenario = "S09", Project = "graphshield" }
}

# MISCONFIGURATION 2: s3:* on all resources
resource "aws_iam_role_policy" "lambda_s3_full" {
  name = "graphshield-s09-lambda-s3-full"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"   # MISCONFIGURATION: full S3 access
      Resource = "*"      # MISCONFIGURATION: on ALL resources
    }]
  })
}

# Basic Lambda execution policy for logs
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function — minimal code, the misconfiguration is in permissions + URL
resource "aws_lambda_function" "exposed_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "graphshield-s09-lambda"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  tags = { Scenario = "S09", Project = "graphshield" }
}

# Minimal Lambda code — just returns a response
resource "local_file" "lambda_code" {
  filename = "${path.module}/lambda/index.js"
  content  = <<-EOF
    exports.handler = async (event) => {
      return {
        statusCode: 200,
        body: JSON.stringify({ message: "graphshield-s09-lambda" })
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

# MISCONFIGURATION 3: Public Lambda URL — anyone can invoke this function
resource "aws_lambda_function_url" "public_url" {
  function_name      = aws_lambda_function.exposed_lambda.function_name
  authorization_type = "NONE"  # MISCONFIGURATION: no auth required
}

# Permission allowing public invocation
resource "aws_lambda_permission" "public_invoke" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.exposed_lambda.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# S3 bucket — the target the Lambda can fully access
resource "aws_s3_bucket" "target" {
  bucket        = "graphshield-s09-target-${var.bucket_suffix}"
  force_destroy = true
  tags          = { Name = "graphshield-s09-bucket", Scenario = "S09" }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No CloudTrail — attacker activity undetected
