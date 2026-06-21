output "iam_user_name" {
  value = aws_iam_user.admin_user.name
}

output "iam_user_arn" {
  value = aws_iam_user.admin_user.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "Admin IAM user with no MFA — password theft = full account takeover"
}