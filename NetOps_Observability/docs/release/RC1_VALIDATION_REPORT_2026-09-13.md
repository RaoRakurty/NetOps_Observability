# RC1 validation report — 2026-09-13 (owner's requested format)

Companion to `RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`, `RC1_PENDING_2026-09-13.md` and the live board
`RC1_RUN_STATUS_2026-09-13.md`. Every line below is a reading from a command run tonight; nothing is inferred.
Fields marked **PENDING-MERGE** are filled in when PR #5 merges under the ruleset.

## Licence reviews (Decision 1)

```
remaining unsigned before:   4 of 29  (xz-libs 5.6.3-r1 · .python-rundeps 20260901.001029 · Simple Launcher ×2)
signed after validation:     0        (python3 scripts/verify-source-reviews.py --check — same result as the morning run)
still unsigned:              4
reason:
  xz-libs 5.6.3-r1        C7 — the apk record is 'GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later';
                          the review narrows to 0BSD without naming the dropped LGPL-2.1-or-later. Not rewritten.
  .python-rundeps         C3 — `governing_licences` is empty; the entry states no licence for the shipped artifact.
  Simple Launcher (×2)    needs_human/unclear; the six PE stubs are now STRIPPED from the image (238b, 20ece8a3) and
                          both rows become dischargeable-by-removal on the next `--emit-inventory` re-scan.
```
`python3 scripts/oci-compliance.py --reviews` → 29 entries, 4 awaiting sign-off, 27 eligible; `--release` still
refuses while any relied-on review is unsigned (correct).

## Tracker 300 — identity namespacing (Decision 2)

Migration is **deterministic/backfilled**, not globally lazy:
- boot-time `users.BackfillIdentities` (idempotent, both backends): `local|''` → bound (`backfilled-local`, 0050 + file load);
  `ldap` → `(tenant, ldap:host:port, lower(login))` bound; `tacacs` → `(tenant, tacacs:host:port, lower(login))` bound;
  `oidc|saml` → explicit **unresolved** (`provenance-unreconstructable`); door not configured → unresolved
  (`issuer-unavailable`, resolved by a later boot); tuple already claimed → **ambiguous** (never merged).
- the lazy path is a REPAIR only for `unresolved` oidc/saml accounts, all §2.6 conditions + 5b, audited
  (`identity.legacy_bound` / `identity.ambiguous`), idempotent, rejects ambiguity.
- metrics: `netops_identity_migration_accounts{state=bound-deterministic|bound-legacy-lazy|unresolved|ambiguous}`,
  `netops_identity_legacy_bind_total{result=bound|ambiguous|refused}`; one boot census line.
- DB invariants: `user_identities` PK `(tenant_id, issuer, subject)` + `UNIQUE(user_id)` + CHECKs, FORCE-RLS (0049);
  `user_identity_state` (0051). `TestPgIdentityConstraintsAreInTheDatabase` proves them with raw SQL.

Counts:
```
mixed test fixture (3 local + 2 ldap + 1 tacacs + 2 oidc + 1 colliding ldap + 1 asserted holder):
  deterministically migrated 6 · unresolved 2 · ambiguous 1   (second boot: 0 moved, `since` preserved)
lab (real data, c7b08be7 deployed 20:12 UTC, schema 0047 → 0051):
  deterministically migrated 1 · unresolved 0 · ambiguous 0   (boot line: "deterministic identity migration complete")
```
Username and email are attributes; `User.ID` is the principal key everywhere (JWT sub, sessions, bindings, audit,
API handle). Residual: issuer strings are key material (operator note in `docs/runbooks/okta-sso-setup.md`).

## Enterprise licence (Blocker A / Decision 3)

```
canonical path:      LICENSES/LicenseRef-Correlix-Enterprise.txt   (both roots; `git mv`, 100% rename, blob unchanged)
SPDX id:             LicenseRef-Correlix-Enterprise               (unchanged; gate binds id → path as a rule)
counsel content:     NOT PRESENT — file is the CORRELIX-ENTERPRISE-TEXT-PLACEHOLDER
gate:                licensing-gate.py → PASS (eight checks); --release → FAIL:
                     "LICENSES/LicenseRef-Correlix-Enterprise.txt: BLOCKED: final Correlix Enterprise licence text
                      required from counsel."  (absent / empty / placeholder / id-mismatch / old-name-only all FAIL,
                      16 tests; the gate was FAIL-OPEN on absent+empty before today)
```
**Blocker A is NOT resolved.**

## Distribution signing (Blocker D)

```
release mode without CORRELIX_SIGNING_KEY:   FATAL BLOCKED before the 20-min build   (tests/test_release_signing.py, 13 tests)
release mode with ephemeral test key:        signed SHA256SUMS.asc, self-verified, MANIFEST carries signer + provenance
corrupted SHA256SUMS after signing:          verification FAILS
developer mode, no key:                      unsigned, loud NOTE, byte-identical to before
workflow (release-bundle.yml, tag only):     import from secrets.CORRELIX_DIST_SIGNING_KEY into a mode-700 temp keyring
                                             (absent secret → job FAILS, never skips) → build → SHA256SUMS → sign →
                                             verify → publish; keyring wiped always(); no set -x / env dumps
secret material exposed:                     none (grep for armored headers over the diff: only a test asserting a prefix)
owner action:                                create repo secret CORRELIX_DIST_SIGNING_KEY (distribution key ONLY)
```
Until the secret exists every tag build fails closed — by design.

## Container signing (Decision 4 / tracker 313)

```
conventional bundles:   GPG, CORRELIX_DIST_SIGNING_KEY            (kept; fail-closed in release mode)
OCI images:             Cosign keyless (GitHub Actions OIDC)       (implemented in publish-images.yml, 6782dd1c)
flow:                   build → push BY DIGEST only → cosign sign IMAGE@sha256:<digest> → cosign verify
                        --certificate-oidc-issuer https://token.actions.githubusercontent.com
                        --certificate-identity https://github.com/RaoRakurty/NetOps_Observability/.github/workflows/publish-images.yml@refs/tags/<tag>
                        (exact, no regexp) → attest-build-provenance on the digest → SBOM (separate) → oci-compliance
                        --release → ONLY THEN the release tags are applied
status:                 keyless/OIDC signing IMPLEMENTED and contract-tested (21 tests, 17 mutations) — UNEXERCISED:
                        needs the Actions OIDC token, so the first real run is the first v* tag
future:                 Cosign KMS-backed key mode documented as the private trust option (RELEASE_CHECKLIST §4.16)
```
Four trust domains stay separate (tag → human; bundles → GPG; images → Cosign; licence issuance → separate authority).

## Release provenance chain

```
protected main (Decision 5, applied 2026-09-13; 21 checks, strict, enforce_admins, tag ruleset)
  -> PR #5 (feat/observability-platform → main), branch tip 1fe6f618, gated 16/16 locally incl. Postgres leg
  -> FINAL_RC1_SHA: 78e82c54ff0e96847555c2e6f5c503e46cd02611   (PR #5 merged 2026-09-13 23:27 UTC as a two-parent merge commit; 31/31 checks green)
  -> release-only gates on that SHA: release-gate.yml ALL 24 JOBS GREEN on main (incl. install.py --tls=yes two-phase boot,
     Postgres integration, OCI compliance, licence gate, SBOM, Playwright, helm) — run 34789741432, 2026-09-14 00:14 UTC.
     The `bundle` job (developer-mode CI bundle) got past the docs-portal defect and then FAILED fetching the busybox
     aports packaging archive: gitlab.alpinelinux.org answers HTTP 418 to GitHub runners. Live-fetch dependency in the
     release path (the 238 'obligation decays' class) — being fixed by retaining the archive in the repo mirror.
  -> signed v0.9.0-rc1 tag: BLOCKER C (release owner)
```
Lab: c7b08be7 deployed and QUALIFIED 12/12 (twice; the one load-shaped Q3 miss re-ran clean).

## Final release state

**NO-GO FOR v0.9.0-rc1**

Genuinely unresolved blockers:
1. **A** — counsel-approved Correlix Enterprise licence text (file is a placeholder).
2. **B** — counsel-approved CLA terms + enabling the prepared `cla-check.yml`.
3. **C** — the release owner's signed tag on FINAL_RC1_SHA (after the release-only gates).
4. **D** — repository secret `CORRELIX_DIST_SIGNING_KEY` (the mechanism is built and fail-closed; the key is not).
5. **F** — Primary and Backup Custodian names for the licence-signing ceremony (tracker 259).
6. Customer bundle rebuild — blocked on an owner-run command this session may not execute
   (`APK_REPO_SCHEME=http bash scripts/make-installer.sh`); frontend dist and docs portal already rebuilt.
7. Two licence reviews unsigned (xz-libs 5.6.3-r1 C7; .python-rundeps C3) — `oci-compliance --release` refuses until
   they are corrected and signed or the components are removed.
