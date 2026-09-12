##############################################################################
# Inputs. Everything an operator must decide, with no default that could be
# wrong quietly: the bucket name, the GitHub coordinates and the administrators
# have NO defaults, so `terraform plan` refuses to run until a human supplies
# them. A default administrator list would be an invented one.
##############################################################################

variable "bucket_name" {
  description = "S3 bucket for the corresponding-source archive. Global namespace: pick something unmistakable, e.g. correlix-corresponding-source-archive."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{2,62}$", var.bucket_name))
    error_message = "bucket_name must be a valid S3 bucket name (lowercase, 3-63 chars)."
  }
}

variable "aws_region" {
  description = "Region for the archive. One region; the archive is a record, not a latency-sensitive service."
  type        = string
}

variable "admin_principal_arns" {
  description = <<-EOT
    ARNs of the AUTHORISED HUMAN ADMINISTRATORS of the archive — the only
    principals allowed to bypass GOVERNANCE retention or change the bucket's
    lock/versioning configuration.

    AT LEAST TWO. A single-employee dependency on compliance evidence is the
    failure this requirement exists to prevent: one person leaving, losing
    access, or being unavailable must never make the archive unmanageable.

    This repository deliberately supplies NO default and NAMES NO ONE. Invented
    administrators are worse than missing ones, because they read as a decision
    somebody made.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.admin_principal_arns) >= 2
    error_message = "At least two human administrators are required: no single-employee dependency on compliance evidence."
  }
}

variable "object_lock_mode" {
  description = <<-EOT
    GOVERNANCE while the ingest/verify/release process is being validated;
    COMPLIANCE afterwards, by an explicit owner decision.

    COMPLIANCE cannot be overridden by ANY principal for the retention period —
    not this role, not an administrator, not the account root user, not AWS
    Support. Switch it only when scripts/source-retention-policy.json records
    the same decision.
  EOT
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "default_retention_years" {
  description = "Bucket DEFAULT retention floor. Keep it in step with scripts/source-retention-policy.json, which is the owner-owned period the tooling actually stamps per object."
  type        = number
  default     = 10

  validation {
    condition     = var.default_retention_years >= 3
    error_message = "GPL-2.0 §3(b) alone names three years; a shorter default retention is never correct here."
  }
}

variable "github_org" {
  description = "GitHub organisation that owns the Correlix repository."
  type        = string
}

variable "github_repo" {
  description = "Repository name. The OIDC trust is scoped to this repository — never to the whole org."
  type        = string
}

variable "ci_environment" {
  description = "GitHub Environment the READ role is scoped to. A fork PR cannot reach a protected environment, which is what keeps the read role out of untrusted runs."
  type        = string
  default     = "release"
}

variable "ingest_environment" {
  description = "GitHub Environment the INGEST role is scoped to. Give it required reviewers: a write to the compliance archive waits for a human."
  type        = string
  default     = "source-ingest"
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider. False when the account already has one (two providers for the same issuer is an error AWS reports late)."
  type        = bool
  default     = true
}

variable "existing_oidc_provider_arn" {
  description = "ARN of an existing GitHub OIDC provider, when create_oidc_provider is false."
  type        = string
  default     = ""
}

variable "role_name_prefix" {
  description = "Prefix for the two IAM role names."
  type        = string
  default     = "correlix-source-archive"
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key for SSE-KMS. EMPTY means SSE-S3 (the default). Read the note in main.tf before setting this: a scheduled key deletion makes a decade of locked, undeletable evidence unreadable."
  type        = string
  default     = ""
}

variable "create_cloudtrail" {
  description = "Create a data-event trail for this bucket. Set false ONLY when an organisation trail already covers it — never leave the archive without CloudTrail visibility."
  type        = bool
  default     = true
}

variable "cloudtrail_log_bucket" {
  description = "Existing bucket that receives the CloudTrail logs. Must NOT be the archive bucket itself: log delivery writes constantly, and every one of those writes would land under Object Lock."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    Project    = "correlix"
    Purpose    = "corresponding-source-retention"
    Tracker    = "262"
    ManagedBy  = "terraform"
    Compliance = "gpl-lgpl-corresponding-source"
  }
}
