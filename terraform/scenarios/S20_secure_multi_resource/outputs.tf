output "iam_role_arn" { value = aws_iam_role.ec2_minimal.arn }
output "s3_bucket_name" { value = aws_s3_bucket.secure.bucket }