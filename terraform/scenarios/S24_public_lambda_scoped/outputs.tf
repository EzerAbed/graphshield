output "function_url" { value = aws_lambda_function_url.public_url.function_url }
output "iam_role_arn" { value = aws_iam_role.lambda_exec.arn }