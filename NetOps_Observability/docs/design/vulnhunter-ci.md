# VulnHunter in CI — agentic AI vulnerability scanning (report-only)

Status: **PARKED (owner decision 2026-07-19)** — VulnHunter requires paid
Anthropic API usage (~$5–30 per scan), so the owner deferred it: *"Let's hold
on to this for now. We can offer this as a service once customers onboard."*
The finished workflow is kept at
`NetOps_Observability/deployment/parked/vulnhunter.workflow.yml`; to activate
later, move it back to `.github/workflows/vulnhunter.yml`, add the
`VULNHUNTER_ANTHROPIC_API_KEY` secret, and enroll the account in Anthropic's
Cyber Verification Program. Productization idea: offer scans as a paid
per-tenant add-on service post-onboarding.
Owner ask (2026-07-18): "Capital One released VulnHunter… can we integrate this
into our CI/CD pipeline so that we can fix vulnerabilities as we are building
new code every day?"

---

## What VulnHunter is

[capitalone/VulnHunter](https://github.com/capitalone/vulnhunter) — released
2026-07-18, **v0.1.0**, Apache-2.0. It is not a SAST scanner; it is a set of
three **Claude Code skills** plus a headless runtime:

| Piece | What it does |
|---|---|
| `/vulnhunt` | Attacker-first analysis: starts at attacker-reachable entry points (APIs, network messages, file uploads) and reasons *forward* to sinks, then runs a **falsification pass** that tries to disprove each finding before reporting it. Emits only findings with an argued exploit path + proposed fix. |
| `/vulnhunter-fix` | Test-driven remediation (exploit demo → failing test RED → fix GREEN → PR). Interactive/dev-workstation flow. |
| `/vulnhunt-fix-verify` | Independent read-only re-verification of a claimed fix. |
| `vulnhunter-agent/` | **The piece we use.** Config-driven headless runtime (`python -m agent --mode=scan <repo-url>`): clones/reuses a checkout, drives `/vulnhunt` via the Claude Agent SDK, writes a `*_VULNHUNT_RESULTS_*` directory + schema-validated `scan_manifest.json`. Optional GitHub-issue filing and results publishing (we disable both). |

Language-agnostic by design (it reasons over source, not per-language rules),
so it covers all three of our stacks — Go backend, Python correlation service,
TS/React frontend — in one pass.

**Requirements:** Python ≥ 3.12, Claude **Opus-class** model access
(`claude-opus-4-8` is the upstream default), auth via `ANTHROPIC_API_KEY`.
There is **no local-model or offline mode**. Output is its own report format —
**no SARIF/code-scanning support** upstream yet (hence artifact + step summary,
not the GitHub Security tab).

## Data flow — source code leaves the runner (owner-approval gate)

**Running VulnHunter sends repository source code to Anthropic's API.** That is
inherent to the tool, not a configuration choice. Two consequences:

1. **The job is default-off.** It runs only when the GitHub secret
   `VULNHUNTER_ANTHROPIC_API_KEY` exists; otherwise it exits with a notice and
   a green check. **Provisioning that secret is the owner's explicit approval
   of the code→Anthropic data flow.** Nothing is sent until then.
2. **Cyber Verification Program.** Upstream warns that vuln-discovery prompts
   can trip Anthropic's real-time cyber safeguards and flag the account for
   cyber abuse unless the account is enrolled in the
   [Cyber Verification Program](https://portal.anthropic.com/programs/cvp).
   The owner should enroll the account behind the key **before** enabling.

What never leaves / never happens:

- No secrets: the repo contains none (gitleaks-enforced, full history); `.env`
  is generated at install time and gitignored, so the scanned tree is clean.
- No GitHub token reaches the agent: CI pre-seeds the checkout into the
  agent's clone slot (`--clone-dir`), so the agent's own clone path (which
  would want a token for private repos) is never exercised; issues/publish
  stages are disabled (`--no-issues --no-publish`).
- No model-driven code execution on the runner: the agent strips `Bash` from
  the allowed tools and we do not pass `--enable-bash` — the model gets
  `Agent/Glob/Read/Write` only.

## How it complements the existing gates

| Existing gate | Catches | VulnHunter adds |
|---|---|---|
| `go vet` / `staticcheck` / `golangci-lint` | correctness/style/API misuse | — |
| `gosec` | Go anti-pattern matches (SQL concat, weak crypto, …) | *exploitability reasoning*: is the flagged pattern actually reachable by an attacker, and what does it yield? |
| `govulncheck` / `pip-audit` / `npm audit` / Trivy | **known** CVEs in dependencies | **novel** flaws in *our* code — logic bugs, authz gaps, tenant-isolation leaks, injection paths no CVE describes |
| gitleaks | committed secrets | — |
| CIS-Docker gate | container posture | — |

It is the only gate that reasons across the seams (nginx → Go API → Kafka →
correlation service) the way an attacker would. It is **not** a replacement
for any existing gate (all remain blocking and untouched); it is an additive,
non-blocking layer.

## CI design (what the workflow does)

Triggers: `pull_request`, `workflow_dispatch`, weekly `schedule` (Mon 02:30
UTC, baseline scan of `main`).

1. **Gate step** — if `secrets.VULNHUNTER_ANTHROPIC_API_KEY` is empty, emit a
   `::notice`, write a step-summary line, and end successfully.
2. **Checkout under scan** — our repo (PR head) into
   `clones/NetOps_Observability`, which is exactly the path the agent's
   `shallow_clone()` reuses instead of cloning — so the scan sees the code
   under review, not `main`.
3. **Checkout VulnHunter pinned by full SHA**
   `82153a097be836b7357cd030f67a53f8346f489f` (= tag `v0.1.0`) — SC-002/SC-010
   style pinning, same as every other action/scanner in this repo. Upstream's
   Python deps (`claude-agent-sdk`, `httpx`, `tenacity`, …) are unpinned in
   its `pyproject.toml`; we record `pip freeze` into the findings artifact for
   auditability (residual supply-chain risk, acceptable for a report-only job).
4. **Run** `python -m agent --mode=scan <our repo URL> --no-publish
   --no-issues --model claude-opus-4-8` with `continue-on-error: true`.
5. **Collect + upload** `*_VULNHUNT_RESULTS_*` + `scan_manifest.json` as the
   `vulnhunter-findings-<run id>` artifact (30-day retention) and render a
   short step summary.

Bounded runtime (CLAUDE.md §9/§15): job `timeout-minutes: 90`; the agent's own
subagent stall timeout (20 min default) kills hung phases; `concurrency`
cancels superseded PR runs so pushes to the same PR never stack scans.

## How findings surface

- **Workflow artifact** `vulnhunter-findings-<run_id>`: the full
  `*_VULNHUNT_RESULTS_*` report directory + `scan_manifest.json` +
  `pip-freeze.txt`.
- **Step summary**: scan outcome + manifest head.
- Not in the GitHub Security tab (no SARIF upstream). If upstream adds SARIF,
  switch the upload to `github/codeql-action/upload-sarif`.
- The agent *can* file one deduplicated GitHub issue per confirmed finding
  (`--issues` + a token with `issues: write`). Deliberately off for now —
  evaluate signal quality from artifacts first, then consider enabling as
  step 2 of the tuning plan.

## How to enable

1. Owner decision: approve sending this repo's source to Anthropic's API.
2. Enroll the Anthropic account in the Cyber Verification Program
   (`portal.anthropic.com/programs/cvp`).
3. Create an Anthropic API key with access to Claude Opus 4.8 and add it as
   repo secret **`VULNHUNTER_ANTHROPIC_API_KEY`**.
4. Trigger a manual run (`Actions → vulnhunter → Run workflow`) and review the
   artifact before letting PR runs accumulate cost.

## Cost profile

Each scan is a long agentic Opus run (Opus 4.8: $5/M input, $25/M output
tokens). A whole-repo hunt plausibly consumes millions of tokens — budget
**single-digit to low-tens of USD per scan**. With PR triggers enabled, that
is per PR-push (minus cancelled superseded runs). If that's too hot, narrow
the trigger: drop `pull_request` and keep weekly + manual, or gate PR runs on
a `vulnhunter` label. Measure the first few runs (the manifest carries usage)
before deciding.

## Tuning plan (report-only → blocking)

1. **Now — report-only** (`continue-on-error: true`): collect 2–4 weeks of
   findings; assess false-positive rate (the falsification engine claims low
   FP, but this is a v0.1.0 tool released the day before this integration).
2. **Issues mode**: enable `--issues` with dedup labels so confirmed findings
   become tracked GitHub issues instead of buried artifacts.
3. **Blocking**: only if precision proves high — remove `continue-on-error`
   and fail on confirmed findings above a severity bar. Do not do this before
   step 1 completes; a hallucinated blocker on a young tool would burn trust
   in the gate.
4. Track upstream: watch releases for SARIF output, PR-diff-scoped scanning
   (today it scans the whole tree, not the diff), and dependency pinning; bump
   `VULNHUNTER_REF` deliberately, never float.

## Open questions for the owner

1. **Approval to send source code to Anthropic** — the enabling decision;
   expressed by creating the `VULNHUNTER_ANTHROPIC_API_KEY` secret.
2. **Cyber Verification Program enrollment** for the account behind the key.
3. **Spend ceiling** — is ~$5–30/scan on every PR push acceptable, or should
   PR runs be label-gated / weekly-only? (Workflow supports either with a
   one-line trigger edit.)
4. Later: enable GitHub-issue filing for confirmed findings (needs an
   `issues: write` token and a labels decision)?
