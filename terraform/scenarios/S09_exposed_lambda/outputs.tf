output "lambda_function_name" {
  value = aws_lambda_function.exposed_lambda.function_name
}

output "lambda_public_url" {
  value = aws_lambda_function_url.public_url.function_url
}

output "iam_role_arn" {
  value = aws_iam_role.lambda_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "Public Lambda URL + s3:* permissions — internet can invoke Lambda to access all S3"
}