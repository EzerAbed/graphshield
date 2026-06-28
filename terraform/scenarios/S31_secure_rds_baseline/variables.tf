variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "db_password" {
  description = "RDS master password"
  default     = "GraphShield2024!Secure"
  sensitive   = true
}

variable "bucket_suffix" {
  description = "Random suffix for bucket name"
  default     = "s31abc"
}