output "ec2_public_ip" { value = aws_instance.hygiene_debt_ec2.public_ip }
output "security_group_id" { value = aws_security_group.https_only.id }