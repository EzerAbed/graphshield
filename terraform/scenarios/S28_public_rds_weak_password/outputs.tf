output "rds_endpoint" {
  value = aws_db_instance.s28.endpoint
}

output "rds_publicly_accessible" {
  value = aws_db_instance.s28.publicly_accessible
}

output "iam_auth_enabled" {
  value = aws_db_instance.s28.iam_database_authentication_enabled
}

output "risk_note" {
  value = "Public RDS + weak password + no IAM auth — two issues combining = Medium risk"
}