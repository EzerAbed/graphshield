output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.secure.bucket
}

output "cloudtrail_status" {
  value = "DISABLED — no CloudTrail configured for this scenario"
}