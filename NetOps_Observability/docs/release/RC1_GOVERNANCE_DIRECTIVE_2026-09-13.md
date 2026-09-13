# RC1 release-governance directive — owner, 2026-09-13

**Status: RECEIVED, NOT YET STARTED.** Captured verbatim in intent so the next
session begins with the whole brief rather than a summary of it. Nothing in this
document has been implemented.

## Governing principle

> A Correlix production/RC release must **fail closed** if any release-integrity,
> licensing, provenance, signing, dependency, or branch-governance requirement is
> missing.

And the final principle the owner set: distinguish **code that builds** from
**code that is legally, cryptographically, operationally and procedurally
releasable**. `v0.9.0-rc1` is permitted only when both are true.

## The standing decision

**DO NOT create `v0.9.0-rc1` yet.** Six blockers, A–F below.

| ID | Blocker |
|---|---|
| A | Final counsel-approved Correlix Enterprise licence text is missing |
| B | CLA enforcement mechanism is missing |
| C | Authorized signed release tag has not been created |
| D | Artifact signing is optional instead of mandatory for release builds |
| E | Release-critical `main` branch protection is not enforced |
| F | Production licence-signing custody incomplete, if rc1 ships externally with the commercial path enabled |

## The eleven architectural decisions

1. **Enterprise licence.** `LicenseRef-Correlix-Enterprise` stays the SPDX id.
   Engineering MUST NOT draft, paraphrase, copy or adapt commercial licence
   language — it comes from counsel. Canonical path
   `LICENSES/LicenseRef-Correlix-Enterprise.txt`. The gate must reject a missing
   file, placeholder text, an empty file, a commercial file without the id, and
   a core/Apache file wrongly carrying it. If counsel's text is absent, leave
   the gate FAILING and report `BLOCKED: final Correlix Enterprise licence text
   required from counsel.`
2. **CLA.** A statement is insufficient; implement automated enforcement (CLA
   Assistant or equivalent GitHub app). Do not write the legal terms. Do NOT
   treat `Signed-off-by`/DCO as equivalent unless counsel changes the policy.
   Build all non-legal plumbing; leave the required check failing for external
   contributors until the agreement exists.
3. **THREE SEPARATE SIGNING TRUST DOMAINS — never one key.**
   **A. Source/tag signing** — annotated signed git tag on the exact reviewed
   SHA; verify the signature before artifacts are built; CI must not pick a
   different commit. **B. Distribution/artifact signing** — a DIFFERENT key;
   make signing MANDATORY in release mode (e.g. `CORRELIX_RELEASE_BUILD=1`):
   missing credentials must FAIL the build, `SHA256SUMS` generated, signed, and
   the signature verified before publish; never upload unsigned or partially
   signed bundles. GPG is acceptable for rc1 to minimise risk; document future
   hardening (Sigstore/cosign, OIDC keyless, KMS, HSM) separately.
   **C. Production licence signing** — the most sensitive. Do NOT put the raw
   private key in GitHub Actions secrets. Prefer HSM > cloud KMS > isolated
   offline host > controlled offline key. CI should send a constrained signing
   REQUEST, not receive the key. Never in source, images, fixtures, logs,
   support bundles or CI artifacts.
4. **Custody (tracker 259).** Primary and Backup Custodian required; ideally a
   Security Owner and a Release Engineering Owner too. Do not invent names — use
   `HUMAN ACTION REQUIRED` placeholders. Runbook must cover generation, storage,
   permitted signing environment, access approval, issuance, auditing,
   backup/recovery, rotation, revocation, suspected and confirmed compromise,
   customer impact, public-key rollover, previously issued licences, emergency
   replacement. A release blocker for an externally distributed RC.
5. **Branch protection — apply BEFORE tagging,** so the release SHA itself passed
   through the protected process. Require PRs, block force-push and deletion,
   require the five real release-critical checks (use the repository's actual
   names, do not invent), up-to-date branches where practical, conversation
   resolution, no direct pushes, minimal bypass.
6. **CODEOWNERS** for `LICENSES/`, `LICENSING.md`, `scripts/licensing-gate.py`,
   `.github/workflows/`, release and installer scripts, licence
   verification/signing code, authn/authz policy, and the core/commercial
   boundary. Do not invent personnel; leave explicit TODOs for admins. Consider
   two approvals on the most sensitive signing paths.
7. **Provenance.** Every release traceable to ONE immutable commit: version, tag,
   full SHA, build timestamp, build environment, dependency lock state, SHA256
   manifest, artifact signature, signer fingerprint, SBOM, gate results. Prefer
   existing SBOM tooling (SPDX JSON / CycloneDX JSON); do not add overlapping
   tools. Document movement toward SLSA — do not claim compliance not held.
8. **Fail-closed release gate.** One entry point (e.g. `make release-gate`)
   aggregating: tests, build, offline build, dependency lock, copyleft gate,
   SPDX gate, enterprise licence validity, generated-code cleanliness, security
   scans, SBOM, checksums, signature, signature verification, release metadata,
   source/tag consistency. Any failure fails the release.
9. **Release workflow builds FROM THE TAG.** `tag → exact commit → build →
   package → checksum → sign → verify → publish`. No branch HEAD, no rebase, no
   cherry-pick, no post-approval revision. Embed version and SHA in metadata.
10. **No secret leakage.** Audit for `set -x`, echoing, debug logs, env dumps,
    docker build args/history, artifact metadata, support bundles. Default
    workflow permissions read-only, elevate per job. Pin third-party actions to
    immutable SHAs; no floating `@main` on release-critical workflows.
11. **Dependency licence gate fails closed for production.** Do not blanket-ban
    GPL/AGPL without establishing whether it is linked, a separate
    process/container, modified, optional, or redistributed. Preserve the
    established architecture where separately distributed optional components
    carry different obligations. Never silently add copyleft to Correlix-owned
    binaries.

## Required implementation order

1. **Analysis** — inspect licensing structure, SPDX headers, `LICENSING.md`,
   `CONTRIBUTING.md`, CLA config, release workflows, workflow permissions,
   `make-installer.sh`, release make targets, dependency gates, branch/check
   docs, CODEOWNERS, SBOM tooling, signing logic, licence-signing
   implementation, tracker/runbooks. **Do not modify code until the existing
   implementation is understood.**
2. **Engineering-safe fixes** — everything not needing legal text, private keys,
   production secrets, human identities or human signatures.
3. **Fail-closed gate** — missing human-controlled requirements must not be able
   to produce a valid-looking public release.
4. **Tests** — missing/placeholder/valid enterprise licence; missing signing
   credential; signing failure; verification failure; release vs developer mode;
   wrong SPDX ids; core/commercial boundary violations; source/tag mismatch.
5. **Documentation** — another authorized release engineer can run the process
   with no tribal knowledge.

## Non-goals (explicit)

Do not write the commercial licence or CLA terms; manufacture signatures;
generate fake custodians; commit secrets; create production private keys; put
licence private keys in Actions; weaken checks to make rc1 green; mark
incomplete controls complete; bypass branch protection; sign on behalf of the
release owner; or change the Apache-2.0/open-core boundary without approval.

## Required output

One report: (1) `GO`/`NO-GO` — never GO while human blockers remain; (2) a
blocker matrix with id, issue, state, severity, engineering fix, human action,
validation command, blocking yes/no; (3) exact files/workflows/scripts/tests/
gates/docs changed; (4) human actions remaining, separated, not claimed complete
unless independently verifiable; (5) the exact ordered release procedure from
protected `main` to publication; (6) verification evidence from every safe local
command, with no fabricated results where secrets or human action are missing;
(7) residual risk.
