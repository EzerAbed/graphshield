output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "iam_role_arn" {
  value = aws_iam_role.ec2_minimal.arn
}

output "security_group_id" {
  value = aws_security_group.tight.id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.enabled.name
}