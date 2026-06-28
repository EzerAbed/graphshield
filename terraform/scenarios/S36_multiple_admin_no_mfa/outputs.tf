output "admin_user_1_arn" {
  value = aws_iam_user.admin_user_1.arn
}

output "admin_user_2_arn" {
  value = aws_iam_user.admin_user_2.arn
}

output "admin_user_3_arn" {
  value = aws_iam_user.admin_user_3.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "3 admin IAM users with no MFA — three credential theft vectors = High risk"
}