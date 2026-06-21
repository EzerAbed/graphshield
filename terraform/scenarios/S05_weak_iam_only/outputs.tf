output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "iam_role_arn" {
  value = aws_iam_role.admin_role.arn
}

output "iam_risk" {
  value = "AdministratorAccess attached — full AWS account control possible"
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}