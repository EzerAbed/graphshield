variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "bucket_suffix" {
  description = "Random suffix to make bucket name globally unique"
  default     = "s02abc"
}