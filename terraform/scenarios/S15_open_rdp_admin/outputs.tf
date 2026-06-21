output "ec2_public_ip" { value = aws_instance.rdp_ec2.public_ip }
output "iam_role_arn" { value = aws_iam_role.admin_role.arn }
output "security_group_id" { value = aws_security_group.open_rdp.id }