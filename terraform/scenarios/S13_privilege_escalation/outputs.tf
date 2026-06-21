output "ec2_public_ip" { value = aws_instance.public_ec2.public_ip }
output "iam_role_arn" { value = aws_iam_role.ec2_escalate.arn }