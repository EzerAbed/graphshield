output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "iam_role_arn" {
  value = aws_iam_role.scoped_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "risk_note" {
  value = "Fully scoped IAM, no wildcards, private EC2, encrypted S3 = Safe"
}