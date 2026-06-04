# Runbook: make the CI gates enforce on `main`

The three CI workflows (`backend-ci`, `correlation-ci`, `frontend-ci`) run on every
PR, but a green workflow does **not** block a merge until `main` is configured to
*require* the blocking jobs. This runbook does that. It must be run by a repo
**admin** (branch-protection is an admin setting; it can't be set from the CI token
or from this agent).

## 1. Required status checks (the blocking jobs)

Use exactly these check names — they are the `name:` of each **blocking** job
(non-blocking triage jobs are intentionally NOT required):

| Workflow | Required check name |
|---|---|
| backend-ci | `build · vet · test · race · fuzz` |
| backend-ci | `govulncheck (blocking)` |
| backend-ci | `staticcheck + gosec (crypto/trust packages, blocking)` |
| correlation-ci | `pytest (blocking)` |
| frontend-ci | `tsc -b && vite build (blocking)` |

> A check only appears in GitHub's picker **after it has run at least once** on the
> repo. Open one PR first (or push to a branch) so all five report, then add them.

## 2. The path-filter pitfall (already handled)

A required check that never runs leaves a PR stuck on *“Expected — Waiting for
status to be reported.”* This happens when a workflow is skipped by a `paths:`
filter. To avoid it, the workflows keep `paths:` on **`push`** (fast feedback on
feature branches) but run **`pull_request` unfiltered** — so all five checks always
report on every PR to `main`. Don't re-add `paths:` to the `pull_request` triggers.

## 3. Enable it — UI

Settings → Branches → Add branch ruleset (or “Add rule”) for `main`:
- ☑ Require a pull request before merging (≥1 approval recommended).
- ☑ Require status checks to pass → **Require branches to be up to date**, then add
  the five checks from §1.
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
      {"context": "build · vet · test · race · fuzz"},
      {"context": "govulncheck (blocking)"},
      {"context": "staticcheck + gosec (crypto/trust packages, blocking)"},
      {"context": "pytest (blocking)"},
      {"context": "tsc -b && vite build (blocking)"}
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

## 5. Promoting the non-blocking jobs later

`backend-ci`’s `full-lint`, `correlation-ci`’s `lint`, and `frontend-ci`’s `audit`
are non-blocking triage today (pre-existing backlog / not locally validated). Once a
module is cleaned (see the per-module burn-down) or a real run confirms a Python/JS
linter green, drop its `continue-on-error: true` (or add its job name to §1) to make
it enforce.

## 6. Related security follow-ups (not done here)

- **Secrets in git history.** `deployment/docker/.env` is no longer tracked and is
  gitignored (commit `6c02200`), **but it remains in history** (e.g. `4f37c7b`), so
  its secrets are still readable via `git show <rev>:.../.env`. Remediate by:
  1. **Rotating** every secret it held — `python3 scripts/install.py --reset-env`
     regenerates them. Do this regardless.
  2. Optionally **scrubbing history** with `git filter-repo` / BFG (⚠️ destructive —
     rewrites SHAs, needs a force-push and coordination with every clone).
  A **secret-scan CI gate** (e.g. `gitleaks`) is recommended to catch the next leak
  before it merges.
- **Container image CVE scanning** (trivy/grype) and **SBOM** are not yet wired.
