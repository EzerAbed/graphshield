output "world_assumable_role_arn" {
  value = aws_iam_role.world_assumable.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "IAM role assumable by ANY AWS account (Principal:*) + s3:* = Critical cross-account exposure"
}