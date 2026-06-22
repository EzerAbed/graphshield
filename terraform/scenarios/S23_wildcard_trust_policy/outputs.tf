output "iam_role_arn" { value = aws_iam_role.open_trust.arn }
output "s3_bucket_name" { value = aws_s3_bucket.target.bucket }