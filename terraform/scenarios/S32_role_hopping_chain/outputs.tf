output "ec2_instance_id" {
  value = aws_instance.instance.id
}

output "role_a_arn" {
  value = aws_iam_role.role_a.arn
}

output "role_b_arn" {
  value = aws_iam_role.role_b.arn
}

output "role_c_arn" {
  value = aws_iam_role.role_c.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "risk_note" {
  value = "EC2 -> Role A -> Role B -> Role C (Admin) — three hop privilege escalation = Critical"
}