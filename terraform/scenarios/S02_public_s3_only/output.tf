output "s3_bucket_name" {
  value = aws_s3_bucket.public_bucket.bucket
}

output "is_public" {
  value = "true — all public access blocks disabled"
}