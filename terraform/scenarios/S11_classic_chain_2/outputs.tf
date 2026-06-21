output "ec2_instance_id" { value = aws_instance.private_ec2.id }
output "iam_role_arn" { value = aws_iam_role.ec2_s3_read.arn }
output "s3_bucket_name" { value = aws_s3_bucket.creds.bucket }