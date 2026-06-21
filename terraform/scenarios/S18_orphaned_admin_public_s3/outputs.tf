output "iam_role_arn" { value = aws_iam_role.orphan_admin.arn }
output "s3_bucket_name" { value = aws_s3_bucket.exposed.bucket }