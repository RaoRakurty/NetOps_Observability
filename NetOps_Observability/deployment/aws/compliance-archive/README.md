# Correlix corresponding-source archive — infrastructure

Terraform for the AWS S3 bucket, Object Lock configuration and the two OIDC
roles behind `scripts/source-archive.py`. Owner decision 2026-09-05, tracker 262.

> **NOT APPLIED.** The company AWS account does not exist yet, and no part of
> this has ever run against a real account. It is written to be applied as-is by
> whoever creates that account — not as a sketch. The tooling it configures was
> proven end to end against a local S3-compatible stand-in (MinIO with Object
> Lock); see `docs/compliance/SOURCE_ARCHIVE.md` §"Proving it without an
> account".
>
> **Never apply this from a personal AWS account.** Production compliance
> evidence lives in a Correlix company-controlled account. A personal account
> ends when the person does.

## What it creates

| Resource | Why |
|---|---|
| `aws_s3_bucket.archive` with `object_lock_enabled = true` | The authoritative store. **Object Lock can only be enabled when the bucket is created** — a bucket made without it must be replaced. |
| `aws_s3_bucket_versioning` (Enabled) | Required by Object Lock; makes an overwrite additive rather than destructive. |
| `aws_s3_bucket_object_lock_configuration` | Default retention floor, GOVERNANCE while validating. Per-object retention is stamped by `source-archive.py` from `scripts/source-retention-policy.json`. |
| `aws_s3_bucket_public_access_block`, SSE, bucket policy | Private, encrypted, TLS-only, and only named humans may bypass governance retention. |
| `aws_iam_openid_connect_provider.github` | Short-lived credentials for CI. No static AWS key exists anywhere in this design. |
| `aws_iam_role.ci_read` | Every release build. `GetObject`/`HeadObject`/prefix-scoped `ListBucket`. Explicitly denied every mutation. |
| `aws_iam_role.source_ingest` | Only `source-ingest.yml`, only inside a reviewer-gated GitHub Environment. `PutObject` + `PutObjectRetention` + read-back. No delete, no bypass. |
| `aws_iam_policy.archive_boundary` | A permissions boundary neither role can exceed, whatever policy someone attaches later. |
| `aws_cloudtrail.archive` | Data-event visibility: who read, wrote or attempted a retention change. |

The IAM documents live in `policies/*.json` rather than inline HCL **so they can
be tested as data**: `tests/test_source_archive.py` parses them and asserts what
the read role does *not* allow. A permission model that is only asserted in a
README is a permission model nobody checks.

## The three principals

```
ci-read          release builds        read only, no mutation of any kind
source-ingest    source-ingest.yml     write-once under Object Lock, no delete
administrators   >= 2 NAMED HUMANS     the only bypass/legal-hold/config path
```

`var.admin_principal_arns` has **no default and is validated to require at least
two entries**. This repository names nobody: an invented administrator reads as
a decision someone made. Filling it in is part of standing the archive up.

## Applying it (the first time)

```bash
cd deployment/aws/compliance-archive
cp terraform.tfvars.example terraform.tfvars     # then fill it in
# credentials come from your SSO profile / environment — never from a file here
terraform init
terraform plan -out=archive.plan                 # READ THIS PLAN
terraform apply archive.plan
```

Then, once, from the outputs:

```bash
export CORRELIX_SOURCE_ARCHIVE_BUCKET="$(terraform output -raw bucket_name)"
export CORRELIX_SOURCE_ARCHIVE_REGION="$(terraform output -raw region)"
cd ../../..                                       # back to NetOps_Observability/
python3 scripts/source-archive.py ingest --all    # the first real ingest
python3 scripts/source-archive.py verify --all
git add docs/compliance/source-archive-index.json # the git-side record
```

Finally, put the two role ARNs into the repository's Actions variables
(`AWS_SOURCE_ARCHIVE_READ_ROLE`, `AWS_SOURCE_ARCHIVE_INGEST_ROLE`,
`AWS_SOURCE_ARCHIVE_BUCKET`, `AWS_SOURCE_ARCHIVE_REGION`) and remove the
`if: false` guards described in `docs/compliance/SOURCE_ARCHIVE.md`.

## Things that will bite

* **`object_lock_enabled` is create-time.** Forgetting it means recreating the
  bucket and re-ingesting everything.
* **`prevent_destroy = true` is on the bucket.** `terraform destroy` will fail,
  by design. Removing an archive of licence-compliance evidence is a
  counsel-approved act, not a Terraform run.
* **COMPLIANCE mode is irreversible for the retention period.** Nobody — not
  the roles, not the administrators, not the account root user, not AWS
  Support — can shorten a retention or delete a locked version under it. Objects
  written with a wrong 10-year COMPLIANCE lock stay for ten years. Validate in
  GOVERNANCE first.
* **`cloudtrail_log_bucket` must not be the archive bucket.** Log delivery
  writes constantly and every write would land under Object Lock.
* **SSE-KMS is not the default on purpose.** A scheduled KMS key deletion makes
  a decade of undeletable evidence unreadable — retention without readability is
  the worst of both.
