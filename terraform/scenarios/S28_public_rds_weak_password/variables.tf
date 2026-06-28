variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "db_password" {
  description = "RDS master password — intentionally weak"
  default     = "password123"
  sensitive   = true
}