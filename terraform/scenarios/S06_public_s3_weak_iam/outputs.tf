output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "iam_role_arn" {
  value = aws_iam_role.weak_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.public_bucket.bucket
}

output "risk_note" {
  value = "Public S3 + s3:* IAM role — two issues combining toward Medium risk"
}