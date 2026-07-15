# AWS SigV4 official test-vector suite (vendored)

Source: the official AWS Signature Version 4 test suite, vendored from the
`aws-signing-test-suite/v4` copy maintained in `smithy-lang/smithy-rs`
(aws/rust-runtime/aws-sigv4, Apache-2.0). One directory per vector:

- `request.txt` — the raw request to sign
- `context.json` — credentials/region/service/timestamp/normalize flags
- `header-canonical-request.txt` / `header-string-to-sign.txt` /
  `header-signature.txt` / `header-signed-request.txt` — expected outputs for
  header-based (Authorization) signing

Excluded: `double-encode-path`, `double-url-encode` (smithy-added extras with
no `context.json`; not part of the official AWS suite) and the `query-*`
presigned-URL artifacts (query signing is intentionally not implemented).

Exercised by `sigv4_test.go`. Do not edit these files.
