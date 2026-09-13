# Decision 5 — `main` branch protection: the exact change to apply

Owner directive 2026-09-13. **NOT YET APPLIED.** Everything below was verified
against the live repository and the live GitHub API; the numbers are readings,
not estimates.

## Live state at time of writing

| Setting | State |
|---|---|
| default branch | `main` ✅ |
| PR required | yes ✅ |
| approvals | 0 — **keep** (a single authorized maintainer; requiring 1 would deadlock) |
| force pushes | disabled ✅ |
| branch deletion | disabled ✅ |
| required checks | **16** |
| `strict` (up to date) | **false** ❌ |
| conversation resolution | **false** ❌ |
| `enforce_admins` | **false** ❌ ← the most serious gap |

## The five missing checks — EXACT names, confirmed from the API

The owner's brief listed five bullets, but `ingest contracts` and `storage
contracts` are ONE check, and `Third-party licence gate` was not listed while
being one of the five core §1.1 checks. The real five:

```
offline vendor build (blocking)
Postgres integration (blocking)
OCI image compliance (inherited layers, blocking)
ingest + storage contracts (blocking)
Third-party licence gate (blocking)
```

All five pass on `origin/main` today, so there is no cost to requiring them.

## HAZARD — two naming forms. Get this wrong and every PR deadlocks.

Every check reports under **two** names:

```
offline vendor build (blocking)                       <- standalone workflow, fires on PR
gate / backend / offline vendor build (blocking)      <- release-gate.yml calling it as a reusable workflow
```

`release-gate.yml`, `release-bundle.yml` and `publish-images.yml` call the CI
workflows via `uses: ./.github/workflows/...`, which prefixes the job name.

**Required checks must use the BARE form**, matching the existing 16. A required
name that never reports leaves the PR stuck at "Expected" for ever — the exact
pitfall `ci-branch-protection.md` §2 already records for `renovate-config-validator`.
If the standalone workflows are ever folded into the composite, the required
list must be migrated in the same change.

## Tier A / Tier B (owner §7)

- **Tier A — required on every PR:** the 16 + the 5 above = **21**.
- **Tier B — release qualification only:** `install.py --tls=yes two-phase boot
  (blocking)` (~45 min), `helm chart lint · template · kubeconform (blocking)`,
  `SBOM (CycloneDX)`. **`release-gate.yml` already exists and is the mechanism**
  — use it rather than creating parallel CI.
- Deliberately NOT required, per `ci-branch-protection.md`:
  `renovate-config-validator (blocking)` — its `paths:` filter means it never
  reports on most PRs.

## Also found

- **A check named `bundle` is FAILING on `origin/main`.** It is not required and
  will not block, but it is red right now — it is the customer-bundle staleness
  signal (~210 commits stale). Do not require it until the bundle is rebuilt, or
  `main` becomes unmergeable.
- **`cla-check.yml` already exists.** Blocker B's plumbing may be further along
  than the tracker suggests — inspect before building anything new.

## To apply

1. Read the current protection; build the payload from it rather than from
   memory, so nothing already set is dropped.
2. `required_status_checks`: the 21 bare names, `strict: true`.
3. `enforce_admins: true`.
4. `required_conversation_resolution: true`.
5. Preserve: `allow_force_pushes: false`, `allow_deletions: false`,
   `required_approving_review_count: 0`.
6. **Enumerate bypass actors** — `enforce_admins` alone is not sufficient if a
   ruleset grants broad bypass. Check `/rulesets` as well as `/protection`.
   Report every actor; do not remove an operationally necessary bot bypass
   without understanding it, but flag it.
7. **Tag protection (owner §9):** branch protection does NOT protect tags. Add a
   ruleset for the release tag pattern so an official tag cannot be moved,
   overwritten, deleted, or recreated against another commit. Scope it to
   release versions; do not block development tags.
8. **Re-read the live state afterwards.** A 200 from the API is not proof.

## RC1 consequence (owner §8, §11)

`fc937aa4` merged before the full ruleset existed. **Do not rewrite history.**
Instead the final RC1 source SHA must come from a PR merged AFTER this ruleset
is active, passing the full required set against current `main`:

```
fc937aa4 + existing history
  -> enable complete protection
  -> remaining RC fixes
  -> final RC1 preparation PR (current with main)
  -> all required checks
  -> protected merge
  -> FINAL_RC1_SHA
  -> release-only gates incl. the long boot test
  -> signed v0.9.0-rc1 tag
```

## Governance hardening (not an RC1 blocker)

Keep approvals at 0 while there is one authorized maintainer. Once two
independent maintainers exist, require at least one approving review, and
consider CODEOWNER review on release/signing/licensing paths.
