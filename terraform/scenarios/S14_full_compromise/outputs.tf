output "ec2_public_ip" { value = aws_instance.worst_case.public_ip }
output "iam_role_arn" { value = aws_iam_role.admin_role.arn }
output "s3_bucket_name" { value = aws_s3_bucket.public.bucket }