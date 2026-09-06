##############################################################################
# GitHub Actions OIDC + the two roles.
#
# NO LONG-LIVED AWS KEY EXISTS ANYWHERE IN THIS DESIGN. GitHub mints a
# short-lived OIDC token for a workflow run; STS exchanges it for credentials
# that expire within the hour. There is no repository secret holding an access
# key, so there is nothing to rotate, nothing to leak in a log, and nothing that
# still works after the workflow that used it was deleted.
#
# SEPARATION OF DUTIES — three principals, none of which can do another's job:
#
#   ci-read        every release build. GetObject/HeadObject/limited ListBucket.
#                  No write, no delete, no retention change, no bypass.
#   source-ingest  only source-ingest.yml, only inside a reviewer-gated GitHub
#                  Environment. PutObject + PutObjectRetention (extend only) +
#                  read-back. No delete, no bypass, no bucket administration.
#   administrators >= 2 NAMED HUMANS (var.admin_principal_arns). The only
#                  principals that may bypass GOVERNANCE retention or touch the
#                  bucket's lock/versioning configuration, and the only ones who
#                  can place or release a legal hold. Not created here: they are
#                  existing human identities in the company account, and this
#                  repository does not invent people.
##############################################################################

# The GitHub OIDC provider. Many accounts already have one; set
# var.create_oidc_provider = false and pass var.existing_oidc_provider_arn then,
# because two providers for the same issuer is an error AWS reports late.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # AWS validates the GitHub OIDC certificate chain against its own trust store
  # for this issuer, so the thumbprint is no longer load-bearing; it is still
  # required by the API. This is GitHub's documented value.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

locals {
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_oidc_provider_arn
}

# ── CI read role ────────────────────────────────────────────────────────────
resource "aws_iam_role" "ci_read" {
  name        = "${var.role_name_prefix}-ci-read"
  description = "Correlix release builds read corresponding source from the compliance archive. Read only."

  assume_role_policy = templatefile("${path.module}/policies/trust-ci-read.json", {
    oidc_provider_arn = local.oidc_provider_arn
    github_org        = var.github_org
    github_repo       = var.github_repo
    ci_environment    = var.ci_environment
  })

  # An hour is longer than any release build. The credential should expire
  # before anyone could reuse one scraped from a log.
  max_session_duration = 3600

  # No policy attached to this role later can exceed the boundary below.
  permissions_boundary = aws_iam_policy.archive_boundary.arn

  tags = var.tags
}

resource "aws_iam_role_policy" "ci_read" {
  name = "${var.role_name_prefix}-ci-read"
  role = aws_iam_role.ci_read.id
  policy = templatefile("${path.module}/policies/ci-read.json", {
    bucket_arn = aws_s3_bucket.archive.arn
  })
}

# ── source-ingest role ──────────────────────────────────────────────────────
resource "aws_iam_role" "source_ingest" {
  name        = "${var.role_name_prefix}-source-ingest"
  description = "Adds corresponding-source artifacts to the compliance archive under Object Lock. Write-once; no delete, no bypass."

  assume_role_policy = templatefile("${path.module}/policies/trust-source-ingest.json", {
    oidc_provider_arn   = local.oidc_provider_arn
    github_org          = var.github_org
    github_repo         = var.github_repo
    ingest_environment  = var.ingest_environment
    ingest_workflow_ref = "repo:${var.github_org}/${var.github_repo}/.github/workflows/source-ingest.yml@*"
  })

  max_session_duration = 3600

  permissions_boundary = aws_iam_policy.archive_boundary.arn

  tags = var.tags
}

resource "aws_iam_role_policy" "source_ingest" {
  name = "${var.role_name_prefix}-source-ingest"
  role = aws_iam_role.source_ingest.id
  policy = templatefile("${path.module}/policies/source-ingest.json", {
    bucket_arn = aws_s3_bucket.archive.arn
  })
}

# A permissions boundary neither CI role can exceed, whatever policy is attached
# to it later. Defence in depth against the most likely future mistake: someone
# broadening a role to "fix" a failing job.
resource "aws_iam_policy" "archive_boundary" {
  name        = "${var.role_name_prefix}-boundary"
  description = "Nothing outside the corresponding-source archive bucket, ever."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OnlyThisBucket"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
          "s3:GetObjectVersionAttributes", "s3:GetObjectRetention",
          "s3:PutObject", "s3:PutObjectRetention", "s3:ListBucket",
        "s3:ListBucketVersions"]
        Resource = [aws_s3_bucket.archive.arn, "${aws_s3_bucket.archive.arn}/*"]
      },
      {
        Sid    = "NeverDeleteNeverBypassNeverAdminister"
        Effect = "Deny"
        Action = ["s3:DeleteObject", "s3:DeleteObjectVersion",
          "s3:BypassGovernanceRetention", "s3:PutBucketVersioning",
          "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration",
        "s3:PutBucketPolicy", "s3:DeleteBucket", "iam:*", "kms:ScheduleKeyDeletion"]
        Resource = "*"
      }
    ]
  })
  tags = var.tags
}
