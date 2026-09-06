##############################################################################
# Correlix corresponding-source archive — the S3 bucket.
#
# Tracker 262 (owner decision, 2026-09-05). This is the authoritative long-term
# store for the source Correlix owes under the GPL/LGPL. It is NOT APPLIED: the
# company AWS account, the bucket and the administrators do not exist yet, and
# this repository will not invent them. `terraform plan` against a real account
# is the first step whoever creates it takes.
#
# Three properties are non-negotiable and are the reason this is IaC rather than
# a console click:
#
#   * OBJECT LOCK IS ENABLED AT CREATION AND CANNOT BE ADDED LATER. A bucket
#     created without it must be recreated, and re-uploading compliance
#     evidence into a second bucket is exactly the kind of "we'll fix it later"
#     that turns into "the bytes are gone". `object_lock_enabled = true` on the
#     bucket resource is therefore a create-time property with a lifecycle
#     guard below.
#   * VERSIONING IS REQUIRED BY OBJECT LOCK and is what makes an overwrite
#     additive rather than destructive.
#   * THE BUCKET IS PRIVATE. Corresponding source is published in release
#     bundles and on GitHub Releases; the archive is the RECORD, not a
#     distribution channel, and it is never world-readable.
##############################################################################

resource "aws_s3_bucket" "archive" {
  bucket = var.bucket_name

  # CREATE-TIME ONLY. AWS cannot enable Object Lock on an existing bucket.
  object_lock_enabled = true

  tags = merge(var.tags, {
    Name    = var.bucket_name
    Purpose = "GPL/LGPL corresponding-source retention (Correlix tracker 262)"
  })

  lifecycle {
    # Deleting this bucket deletes Correlix's proof that it honoured a licence
    # obligation. Terraform will refuse; removing the archive is a deliberate,
    # counsel-approved act performed by a named administrator, never a `destroy`.
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    default_retention {
      # GOVERNANCE while the process is validated; COMPLIANCE afterwards, by an
      # explicit owner decision recorded in scripts/source-retention-policy.json.
      #
      # COMPLIANCE IS IRREVERSIBLE FOR THE RETENTION PERIOD: under it, no
      # principal — not this role, not an administrator, not the account root
      # user, not AWS Support — can shorten a retention or delete a locked
      # version before it expires. Objects written with a wrong 10-year
      # COMPLIANCE lock occupy paid storage for 10 years with no appeal. That is
      # the point of the mode and the reason the switch is deliberate.
      mode = var.object_lock_mode
      # A floor, not the answer. `source-archive.py` stamps a per-object
      # retain-until computed from scripts/source-retention-policy.json, which
      # is where the owner-owned period lives. This default only ensures an
      # object written by some other path is never written unprotected.
      years = var.default_retention_years
    }
  }

  depends_on = [aws_s3_bucket_versioning.archive]
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3 by default. A customer-managed KMS key is supported (set
      # var.kms_key_arn) but is NOT the default: a KMS key whose deletion is
      # scheduled would make a decade of retained compliance evidence
      # unreadable while Object Lock still refuses to let anyone delete it —
      # retention without readability is the worst of both.
      sse_algorithm     = var.kms_key_arn == "" ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn == "" ? null : var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != ""
  }
}

resource "aws_s3_bucket_policy" "archive" {
  bucket = aws_s3_bucket.archive.id
  policy = templatefile("${path.module}/policies/bucket-policy.json", {
    bucket_arn = aws_s3_bucket.archive.arn
    account_id = data.aws_caller_identity.current.account_id
    # AT LEAST TWO named human administrators (var.admin_principal_arns is
    # validated for that in variables.tf). No name is invented here.
    admin_principals = jsonencode(var.admin_principal_arns)
  })

  depends_on = [aws_s3_bucket_public_access_block.archive]
}

# CloudTrail data events for this bucket. Who read, wrote or attempted to alter
# a retention, with the principal and the time — the visibility half of
# administrator separation. Off by default only because an account may already
# have an organisation trail covering it; set var.create_cloudtrail = true if
# not, and never leave both false.
resource "aws_cloudtrail" "archive" {
  count                         = var.create_cloudtrail ? 1 : 0
  name                          = "${var.bucket_name}-trail"
  s3_bucket_name                = var.cloudtrail_log_bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "Every object operation on the corresponding-source archive"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.archive.arn}/"]
    }
  }

  tags = var.tags
}

data "aws_caller_identity" "current" {}
