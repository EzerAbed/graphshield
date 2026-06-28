output "rds_endpoint" {
  value = aws_db_instance.s31.endpoint
}

output "rds_encrypted" {
  value = aws_db_instance.s31.storage_encrypted
}

output "rds_publicly_accessible" {
  value = aws_db_instance.s31.publicly_accessible
}

output "iam_auth_enabled" {
  value = aws_db_instance.s31.iam_database_authentication_enabled
}

output "risk_note" {
  value = "Fully hardened RDS — encrypted, private, IAM auth, monitoring enabled = Safe"
}