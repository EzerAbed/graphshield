output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "ec2_public_ip" {
  value = aws_instance.instance.public_ip
}

output "rds_endpoint" {
  value = aws_db_instance.s30.endpoint
}

output "iam_role_arn" {
  value = aws_iam_role.admin_role.arn
}

output "risk_note" {
  value = "Public EC2 + Admin IAM + Public RDS + No logging = Critical — full database compromise undetected"
}