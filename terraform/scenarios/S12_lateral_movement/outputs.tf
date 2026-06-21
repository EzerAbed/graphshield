output "ec2_public_ip" { value = aws_instance.public_ec2.public_ip }
output "iam_role_arn" { value = aws_iam_role.ec2_rds_access.arn }
output "rds_endpoint" { value = aws_db_instance.target.endpoint }