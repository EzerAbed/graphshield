output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "security_group_id" {
  value = aws_security_group.multi_open_sg.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "SSH + RDP + HTTP + HTTPS open but no public IP — wide SG surface but unreachable = Medium risk"
}