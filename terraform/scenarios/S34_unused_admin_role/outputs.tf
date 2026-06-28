output "unused_role_arn" {
  value = aws_iam_role.unused_admin.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "Admin role exists but not attached to any resource — dormant Low risk"
}