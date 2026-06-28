variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "db_password" {
  description = "RDS master password"
  default     = "GraphShield2024!"
  sensitive   = true
}