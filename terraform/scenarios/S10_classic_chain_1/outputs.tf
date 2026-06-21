output "ec2_public_ip" { value = aws_instance.public_ec2.public_ip }
output "ec2_instance_id" { value = aws_instance.public_ec2.id }
output "iam_role_arn" { value = aws_iam_role.ec2_s3_full.arn }
output "s3_bucket_name" { value = aws_s3_bucket.target.bucket }
output "security_group_id" { value = aws_security_group.open_ssh.id }