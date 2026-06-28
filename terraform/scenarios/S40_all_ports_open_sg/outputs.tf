output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "security_group_id" {
  value = aws_security_group.all_open_sg.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "All ports open SG but no public IP — dangerous firewall rule but chain broken = Low risk"
}