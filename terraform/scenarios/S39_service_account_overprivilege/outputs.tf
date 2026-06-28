output "lambda_function_name" {
  value = aws_lambda_function.private_lambda.function_name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda_admin_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "Lambda with AdministratorAccess but no public URL — over-privileged service account = Medium risk"
}