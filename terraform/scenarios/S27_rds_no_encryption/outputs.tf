output "rds_endpoint" {
  value = aws_db_instance.s27.endpoint
}

output "rds_encrypted" {
  value = aws_db_instance.s27.storage_encrypted
}

output "risk_note" {
  value = "RDS private but unencrypted — isolated Low risk finding"
}