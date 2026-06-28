output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "ec2_public_ip" {
  value = aws_instance.instance.public_ip
}

output "rds_endpoint" {
  value = aws_db_instance.s29.endpoint
}

output "iam_role_arn" {
  value = aws_iam_role.ec2_rds_role.arn
}

output "risk_note" {
  value = "Internet -> EC2 (SSH) -> IAM rds:* -> RDS — full lateral movement chain = High risk"
}