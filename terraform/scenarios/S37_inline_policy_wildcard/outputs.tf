output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "iam_role_arn" {
  value = aws_iam_role.wildcard_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "EC2 with inline Action:* Resource:* policy — full AWS access via inline policy = High risk"
}