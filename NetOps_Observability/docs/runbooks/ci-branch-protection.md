# Runbook: make the CI gates enforce on `main`

The CI workflows run on every PR, but a green workflow does **not** block a merge
until `main` is configured to *require* the blocking jobs. This runbook does that.
It must be run by a repo **admin** (branch-protection is an admin setting; it can't
be set from the CI token or from this agent).

**Corrected 2026-09-03.** Two defects in the previous version of this page:

1. It named a required check `build · vet · test · race · fuzz`. **No job has
   that name** — live fuzzing left the per-PR gate for `fuzz-nightly.yml`, and the
   job is `build · vet · test · race`. A required check whose name matches no
   real job pins every PR at *"Expected — Waiting for status to be reported"*
   forever, so this was worse than listing nothing.
2. It listed **five** checks while the gate had grown to sixteen. Everything the
   list omits is a gate that runs, goes green, and enforces nothing — including
   the whole `supply-chain` workflow. This is also the precondition for Renovate
   automerge (`docs/design/PATCH_AUTOMATION_PLAN_2026-09-03.md` §4.3: automerge is
   exactly as strong as this list).

**Extended 2026-09-04** (pre-`v0.9.0-rc1`). Three changes: the required list grew
to **eighteen** (`ingest-contract-ci` and `telemetry-catalog-ci` were blocking
gates that nothing enforced); §2.1 documents the **tag** gate
(`.github/workflows/release-gate.yml`), because branch protection does not cover
tags and the two publishing workflows had no test gate at all; and the whole page
is now machine-checked against the workflows by
`NetOps_Observability/tests/test_required_checks_consistency.py` (§5).

## 1. Required status checks (the blocking jobs)

Use exactly these check names — they are the `name:` of each blocking job (or the
job **id**, where a job declares no `name:`). Every one of them runs `pull_request`
**unfiltered**, so all eighteen report on every PR to `main` (see §2).

These three tables are the **single list**. `.github/workflows/release-gate.yml`
(the tag gate, §2.1) calls exactly the workflows named in §1.1 + §1.2, and
`NetOps_Observability/tests/test_required_checks_consistency.py` fails the build if
this page, the `gh api` payload in §4 and the workflows' real `name:` fields ever
disagree — including if a new blocking job appears in none of the three tables.
Keep the rows in the machine-readable shape they are in: a workflow name, then the
check name in backticks.

### 1.1 Required — put every one of these in the ruleset

| Workflow | Required check name |
|---|---|
| backend-ci | `build · vet · test · race` |
| backend-ci | `offline vendor build (blocking)` |
| backend-ci | `Postgres integration (blocking)` |
| backend-ci | `govulncheck (blocking)` |
| backend-ci | `staticcheck + gosec (crypto/trust packages, blocking)` |
| backend-ci | `golangci-lint (repo-wide, blocking)` |
| correlation-ci | `pytest (blocking)` |
| correlation-ci | `ruff · bandit · mypy · pip-audit (blocking)` |
| frontend-ci | `tsc -b && vite build (blocking)` |
| frontend-ci | `npm audit (blocking)` |
| frontend-ci | `Playwright E2E (blocking)` |
| frontend-ci | `panel↔metric contract (blocking)` |
| supply-chain | `Trivy filesystem scan (blocking)` |
| supply-chain | `gitleaks secret scan (blocking, full history)` |
| supply-chain | `CIS-Docker policy gate (blocking)` |
| supply-chain | `Third-party licence gate (blocking)` |
| ingest-contract-ci | `ingest + storage contracts (blocking)` |
| telemetry-catalog-ci | `invariants · conformance · pytest (blocking)` |

The last two were added 2026-09-04. Both are blocking gates that already run
`pull_request` unfiltered, and both are in the tag gate — leaving them out of the
ruleset was the exact "runs, goes green, enforces nothing" failure this page
exists to prevent.

### 1.2 Optional in the ruleset — mandatory in the tag gate

A repo admin may leave these off `main`'s ruleset with the cost understood; they
are **not** optional for a release, because `release-gate.yml` runs the whole
`fresh-install-integrity` workflow before any artifact is published.

| Workflow | Check name | Note |
|---|---|---|
| fresh-install-integrity | `integrity` | the job declares no `name:`, so the check name is the **job id**. Static preflight + real config load |
| fresh-install-integrity | `ruff (scripts/*.py, blocking)` | job id `scripts-lint` |
| fresh-install-integrity | `install.py --tls=yes two-phase boot (blocking)` | a real two-phase install on a scratch runner — the slowest check in the repo (~45 min); require it on PRs only if you want every PR to pay for it |

### 1.3 Deliberately NOT required — and why

| Workflow | Check name | Why not |
|---|---|---|
| renovate | `renovate-config-validator (blocking)` | `renovate.yml`'s `pull_request` trigger carries a `paths:` filter (`.github/renovate.json`, `.github/workflows/renovate.yml`), so on any PR that does not touch those files the check never reports and the PR sticks at "Expected" — exactly the pitfall in §2. It still blocks the PRs that matter (the ones editing the config). Drop its `paths:` filter first if you want it required |
| tracker-ci | `tracker staleness (blocking on HIGH)` | document hygiene, not artifact correctness. A stale tracker row must not be able to block a release, so it is out of the tag gate — and a check in the ruleset but not the tag gate would break the one-list invariant |

> A check only appears in GitHub's picker **after it has run at least once** on the
> repo. Open one PR first (or push to a branch) so every check reports, then add
> them. Verify the names against the workflows rather than this table if a check
> refuses to appear — the `name:` is the contract, and this page has drifted before.

## 2. The path-filter pitfall (already handled)

A required check that never runs leaves a PR stuck on *“Expected — Waiting for
status to be reported.”* This happens two ways: the workflow is skipped by a
`paths:` filter, or the required name matches no job at all (§1, defect 1).

Against the first: the workflows keep `paths:` on **`push`** (fast feedback on
feature branches) but run **`pull_request` unfiltered** — so every check in §1.1
always reports on every PR to `main`. Don't re-add `paths:` to the `pull_request`
triggers of a required workflow. `renovate.yml` is the one workflow that *does*
filter `pull_request`, which is why its job must not be required (§1.3).

Against the second: after any job rename, re-run §4's verify command and compare
it with the live `name:` values —
`grep -n '    name:' .github/workflows/*.yml`.

### 2.1 The same pitfall on a TAG — the release gate

Branch protection does not exist on tags, and a tag push carries no file diff for
a `paths:` filter to match, so the path-filtered `push` triggers cannot be what
gates a release. Until 2026-09-04 nothing did: `publish-images.yml` pushed four
images to GHCR, and `release-bundle.yml` attached the customer bundle to the
release, with **no `needs:` on any test job**.

`.github/workflows/release-gate.yml` closes that. It is a `workflow_call`-only
workflow that *calls* every gate workflow in §1.1 + §1.2, and both publishing
workflows run it as their first job and `needs:` it from every other job. Two
properties make it fail-closed by construction:

- `workflow_call` accepts **no `paths:` filter**, so a tag runs *all* jobs of
  *all* gate workflows against the tag's exact commit, regardless of the diff.
  The per-workflow `push` filters stay honest for branch feedback.
- `needs:` is enforced by Actions: a failed, cancelled **or skipped** gate leaves
  the publish job unreachable. There is no token, no polling, no TOCTOU window.

The alternative considered and rejected — a `gate` job that queries the GitHub API
for check runs on `github.sha` — is documented at the top of `release-gate.yml`.
Short version: the check runs attached to a commit are a function of that commit's
diff (path-filtered `push`) and PR check runs live on GitHub's ephemeral merge
commit, not on the commit that lands on `main`, so such a gate is either
permanently blocking or quietly fail-open. It also inspects history rather than
testing the tree being published.

When you add a gate workflow, add it to §1.1/§1.2 **and** to `release-gate.yml`.
The test named in §1 fails if you do only one.

## 3. Enable it — UI

Settings → Branches → Add branch ruleset (or “Add rule”) for `main`:
- ☑ Require a pull request before merging (≥1 approval recommended).
- ☑ Require status checks to pass → **Require branches to be up to date**, then add
  every check from §1.
- ☑ Do not allow bypassing the above settings (apply to admins).
- ☑ Block force pushes.

## 4. Enable it — `gh` CLI (scriptable)

```bash
# Requires: gh auth login as a repo admin.
gh api -X PUT repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "build · vet · test · race"},
      {"context": "offline vendor build (blocking)"},
      {"context": "Postgres integration (blocking)"},
      {"context": "govulncheck (blocking)"},
      {"context": "staticcheck + gosec (crypto/trust packages, blocking)"},
      {"context": "golangci-lint (repo-wide, blocking)"},
      {"context": "pytest (blocking)"},
      {"context": "ruff · bandit · mypy · pip-audit (blocking)"},
      {"context": "tsc -b && vite build (blocking)"},
      {"context": "npm audit (blocking)"},
      {"context": "Playwright E2E (blocking)"},
      {"context": "panel↔metric contract (blocking)"},
      {"context": "Trivy filesystem scan (blocking)"},
      {"context": "gitleaks secret scan (blocking, full history)"},
      {"context": "CIS-Docker policy gate (blocking)"},
      {"context": "Third-party licence gate (blocking)"},
      {"context": "ingest + storage contracts (blocking)"},
      {"context": "invariants · conformance · pytest (blocking)"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Verify: `gh api repos/RaoRakurty/NetOps_Observability/branches/main/protection | jq '.required_status_checks.checks'`

## 5. Keeping this list correct

There are **no** `continue-on-error` jobs left in `.github/workflows/` — the triage
tier described here previously (backend `full-lint`, correlation `lint`, frontend
`audit`) was promoted to blocking, which is why §1 grew. The failure mode is now
the reverse one: a job is added or renamed and this page (and the ruleset) is not
updated, so a gate runs green and enforces nothing.

When you add or rename a blocking job:

1. add/rename its `name:` here in §1.1 (or §1.2 / §1.3, with the reason) **and**
   in §4's JSON;
2. confirm its workflow's `pull_request` trigger has no `paths:` filter;
3. add its workflow to `.github/workflows/release-gate.yml` if the job is in
   §1.1/§1.2, and give the workflow a `workflow_call:` trigger;
4. re-run §4's verify command and diff it against §1.1.

Steps 1–3 are now **mechanically enforced**:
`NetOps_Observability/tests/test_required_checks_consistency.py` (run by
`ingest-contract-ci`, which pytest's the whole `tests/` tree) fails if

- a check name in §1 matches no real job `name:`/id in that workflow,
- §4's `gh api` payload and the §1.1 table disagree, in content or order,
- a job whose `name:` says "blocking" appears in none of §1.1/§1.2/§1.3,
- the set of workflows called by `release-gate.yml` differs from §1.1 ∪ §1.2,
- a called gate workflow lacks a `workflow_call:` trigger, or filters
  `pull_request` by `paths:`,
- a job in `publish-images.yml` or `release-bundle.yml` does not `needs:` the gate.

What it cannot check is **GitHub's ruleset itself** — that is not in the repo, so
§4 remains the manual half. `tests/test_toolchain_pin.py` guards the toolchain
version of the same drift class.

## 6. Related security follow-ups (not done here)

- **Secrets in git history.** `deployment/docker/.env` is no longer tracked and is
  gitignored (commit `6c02200`), **but it remains in history** (e.g. `4f37c7b`), so
  its secrets are still readable via `git show <rev>:.../.env`. Remediate by:
  1. **Rotating** every secret it held. Do this regardless.
     `python3 scripts/install.py --rotate-app-secrets` covers everything that can
     be rotated on a running install (application secrets + the store credentials
     it reconciles against the live store and verifies); the handful that are
     seeded into a store on first boot must be rotated in that product and copied
     back into `.env`. Both halves are in
     **`docs/runbooks/secret-rotation.md`** — do not reach for a bare
     `--reset-env`, which refuses on a started install precisely because
     regenerating those values would brick it (audit FUNC-HIGH-1).
  2. Optionally **scrubbing history** with `git filter-repo` / BFG (⚠️ destructive —
     rewrites SHAs, needs a force-push and coordination with every clone).
  A **secret-scan CI gate** (e.g. `gitleaks`) is recommended to catch the next leak
  before it merges.
- ~~**Container image CVE scanning** (trivy/grype) and **SBOM** are not yet wired.~~
  **Done (corrected 2026-09-04, was stale).** All three shipped: `supply-chain` ·
  `Trivy filesystem scan (blocking)` and `gitleaks secret scan (blocking, full
  history)` are required checks (§1.1); `supply-chain` · `SBOM (CycloneDX)` emits
  a whole-tree CycloneDX SBOM on every build; `publish-images.yml` attaches a
  per-image CycloneDX SBOM **and** a keyless SLSA build-provenance attestation to
  each pushed digest. Still open: image **signing** (cosign/Notation) and GPG
  signing of the bundle's `SHA256SUMS` — see `docs/RELEASE_CHECKLIST.md` §4.8/§4.9.
