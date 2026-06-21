output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "iam_role_arn" {
  value = aws_iam_role.s3_read_role.arn
}

output "security_group_id" {
  value = aws_security_group.open_ssh.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "SSH open + S3 credentials on EC2 — chain incomplete without public IP"
}