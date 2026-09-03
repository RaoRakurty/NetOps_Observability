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

## 1. Required status checks (the blocking jobs)

Use exactly these check names — they are the `name:` of each blocking job (or the
job **id**, where a job declares no `name:`). Every one of them runs `pull_request`
**unfiltered**, so all sixteen report on every PR to `main` (see §2).

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

Two more that a repo admin may add, with their cost understood:

| Workflow | Check name | Note |
|---|---|---|
| fresh-install-integrity | `integrity` | the job declares no `name:`, so the check name is the **job id**. Static preflight + real config load |
| fresh-install-integrity | `ruff (scripts/*.py, blocking)` | job id `scripts-lint` |
| fresh-install-integrity | `install.py --tls=yes two-phase boot (blocking)` | a real two-phase install on a scratch runner — the slowest check in the repo; require it only if you want every PR to pay for it |

**Do NOT require `renovate-config-validator (blocking)`.** `renovate.yml`'s
`pull_request` trigger carries a `paths:` filter
(`.github/renovate.json`, `.github/workflows/renovate.yml`), so on any PR that does
not touch those files the check never reports and the PR sticks at "Expected" —
exactly the pitfall in §2. Either leave it out (it still blocks the PRs that
matter, which are the ones editing the config) or drop its `paths:` filter first.

> A check only appears in GitHub's picker **after it has run at least once** on the
> repo. Open one PR first (or push to a branch) so every check reports, then add
> them. Verify the names against the workflows rather than this table if a check
> refuses to appear — the `name:` is the contract, and this page has drifted before.

## 2. The path-filter pitfall (already handled)

A required check that never runs leaves a PR stuck on *“Expected — Waiting for
status to be reported.”* This happens two ways: the workflow is skipped by a
`paths:` filter, or the required name matches no job at all (§1, defect 1).

Against the first: the workflows keep `paths:` on **`push`** (fast feedback on
feature branches) but run **`pull_request` unfiltered** — so every check in §1
always reports on every PR to `main`. Don't re-add `paths:` to the `pull_request`
triggers of a required workflow. `renovate.yml` is the one workflow that *does*
filter `pull_request`, which is why its job must not be required.

Against the second: after any job rename, re-run §4's verify command and compare
it with the live `name:` values —
`grep -n '    name:' .github/workflows/*.yml`.

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
      {"context": "Third-party licence gate (blocking)"}
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

1. add/rename its `name:` here in §1 **and** in §4's JSON;
2. confirm its workflow's `pull_request` trigger has no `paths:` filter;
3. re-run §4's verify command and diff it against §1.

`tests/test_toolchain_pin.py` guards the toolchain half of the same class of drift
(one version, many files). The check-name half is still manual — GitHub's ruleset
is not in the repo.

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
- **Container image CVE scanning** (trivy/grype) and **SBOM** are not yet wired.
