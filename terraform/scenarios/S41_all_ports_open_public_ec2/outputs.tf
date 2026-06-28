output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "ec2_public_ip" {
  value = aws_instance.instance.public_ip
}

output "security_group_id" {
  value = aws_security_group.all_open_sg.id
}

output "iam_role_arn" {
  value = aws_iam_role.admin_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "All ports open + public IP + admin IAM + no logging = Critical — maximum network exposure"
}