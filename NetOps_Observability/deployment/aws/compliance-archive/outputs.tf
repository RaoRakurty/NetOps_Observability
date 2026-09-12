##############################################################################
# What the workflows and `source-archive.py` need. None of these is a secret:
# a bucket name and a role ARN are useless without a trust relationship, and the
# trust relationship is scoped to one repository and one environment.
##############################################################################

output "bucket_name" {
  description = "CORRELIX_SOURCE_ARCHIVE_BUCKET for scripts/source-archive.py."
  value       = aws_s3_bucket.archive.id
}

output "bucket_arn" {
  value = aws_s3_bucket.archive.arn
}

output "region" {
  description = "CORRELIX_SOURCE_ARCHIVE_REGION."
  value       = var.aws_region
}

output "ci_read_role_arn" {
  description = "role-to-assume for the release/read workflows (publish-images.yml, supply-chain.yml)."
  value       = aws_iam_role.ci_read.arn
}

output "source_ingest_role_arn" {
  description = "role-to-assume for source-ingest.yml. Nothing else may use it."
  value       = aws_iam_role.source_ingest.arn
}

output "object_lock_mode" {
  description = "Keep scripts/source-retention-policy.json in step with this."
  value       = var.object_lock_mode
}

output "administrators" {
  description = "The named human administrators of the archive (>= 2)."
  value       = var.admin_principal_arns
}
