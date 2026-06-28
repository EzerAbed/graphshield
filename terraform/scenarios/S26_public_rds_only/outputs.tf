output "rds_endpoint" {
  value = aws_db_instance.s26.endpoint
}

output "rds_publicly_accessible" {
  value = aws_db_instance.s26.publicly_accessible
}

output "risk_note" {
  value = "RDS publicly accessible + no encryption — isolated Low risk finding"
}