output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "ec2_public_ip" {
  value = aws_instance.instance.public_ip
}

output "security_group_id" {
  value = aws_security_group.http_sg.id
}

output "risk_note" {
  value = "HTTP open to world + public IP but no SSH/RDP — web exposure without shell access = Low risk"
}