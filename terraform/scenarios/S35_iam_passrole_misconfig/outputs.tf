output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "passrole_role_arn" {
  value = aws_iam_role.passrole_role.arn
}

output "high_priv_role_arn" {
  value = aws_iam_role.high_priv_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "EC2 with iam:PassRole on * — attacker can escalate to any role = High risk"
}