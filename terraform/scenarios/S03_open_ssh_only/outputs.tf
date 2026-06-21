output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "security_group_id" {
  value = aws_security_group.open_ssh.id
}

output "ssh_open_to_world" {
  value = "true — port 22 open to 0.0.0.0/0"
}