# Patch automation plan — every dependency class, one train

**Date:** 2026-09-03 · **Status:** proposed, config is ready to merge · **Owner action required:** one repository secret (§7)

Answers the ask *"how do we automate applying patches to all the packages we use?"*

Companion documents:

- **Procedure:** [`docs/runbooks/patch-train.md`](../runbooks/patch-train.md) — who runs what, monthly, and the emergency path.
- **Config:** [`.github/renovate.json`](../../../.github/renovate.json) (validated against the Renovate 44.59.3 schema), [`.github/workflows/renovate.yml`](../../../.github/workflows/renovate.yml), and the new `offline-build` job in [`.github/workflows/backend-ci.yml`](../../../.github/workflows/backend-ci.yml).

Nothing in this change bumps a dependency. It builds the machine that will.

---

## 1. What "all the packages we use" actually means here

Nine distinct dependency classes, in four different pin *syntaxes*, spread across 24 files. The
count matters, because the tool choice in §3 turns entirely on how many of them a given bot can
even see.

| # | Class | Where the version lives | Count | Automatable? |
|---|---|---|---|---|
| 1 | Go modules (vendored) | `src/backend/go.mod` + `vendor/modules.txt` | 9 modules (3 direct, 6 indirect) | yes |
| 2 | Go toolchain | `go.mod` `go`/`toolchain`; `GO_VERSION` in `backend-ci.yml`; a **hardcoded** `1.26.8` in `fuzz-nightly.yml`; `golang:1.26.8-alpine` digest in 3 Dockerfiles; 3 satellite `go.mod` files | 9 sites | yes, but never unattended (§5) |
| 3 | npm — product | `src/frontend/package.json` + lock | 27 direct / 265 total | yes |
| 4 | npm — docs portal | `docs-portal/package.json` + lock | 11 direct / 1 203 total | yes |
| 5 | Python — correlation | `src/correlation/requirements.in` → hash-locked `requirements.txt` | 8 direct / 27 locked | yes (`pip-compile` manager) |
| 6 | Container images | `image:` in 8 compose files (5 tracked); `FROM` in 14 Dockerfiles | 55 `image:` lines, 35 distinct refs in the **tracked** tree + 19 `FROM` | yes |
| 7 | GitHub Actions | `uses:` across 14 workflows | 53 lines, 16 distinct refs | yes |
| 8 | Gate tools | 6 named env vars in `backend-ci.yml` / `supply-chain.yml`, 5 more in `correlation-ci.yml`, 1 mirrored in `scripts/ci-backend-guard.sh` | 12 pins | yes, via custom managers |
| 9 | Scanner engines | Trivy's binary + vuln DB, carried **only** by the `trivy-action` SHA | 1 implicit pin | partially (§6.4) |

Two structural facts drive everything below.

**The pins do not live where a package manager expects them.** Half the third-party surface — the
gate tools, the Go toolchain, gitleaks — is a bare string in a YAML `env:` block. No ecosystem
manifest describes it. A bot that only understands `go.mod` and `package.json` is blind to it.

**`vendor/` is committed and the offline build is the contract.** CLAUDE.md §6 gate 2 says the tree
must build with no network. A Go bump that edits `go.mod` without regenerating `vendor/` produces a
tree that builds perfectly on a CI runner with a warm module cache and fails on a customer's
air-gapped host. Until this change, **nothing in CI proved the offline build**. That gap is the
single most important thing fixed here, and it is what makes automated Go bumps safe to merge at all.

---

## 2. Design principles

Carried straight from CLAUDE.md rather than invented for this document.

1. **§16.1 — never swallow an error.** A patch bot that silently stops working is worse than no bot:
   it converts "we are behind" into "we believe we are current." Every failure mode below is loud.
2. **§6 — the allowlist is not negotiable by a robot.** Renovate can only bump modules already in
   `go.mod`; it can never add one. Majors of the four allowlisted modules are dashboard-gated and
   never automerged, because a major is a re-review of the allowlist entry.
3. **§3 — zero trust extends to the bot.** The updater runs on our runner, from a SHA-pinned action,
   against config visible in the diff. No third-party service gets a write credential (§3).
4. **§12 — the gate decides, not the bot.** Automerge is permitted *only* where GitHub's own
   required-checks machinery holds the merge until the full blocking gate is green. The bot never
   asserts safety; the gate does.
5. **A settling period.** Three days minimum release age on everything except a security advisory. A
   release yanked six hours after publication must never have reached `main`.

---

## 3. Decision: Renovate, self-hosted — and retire `dependabot.yml`

The repo has `.github/dependabot.yml` today (weekly, 6 ecosystems). It is a reasonable starting
point and it should be replaced. The reasoning, in order of weight:

### 3.1 Dependabot cannot see the compose image pins — the largest surface we have

Dependabot's `docker` ecosystem parses **Dockerfiles only**. It has never supported
`docker-compose.yml`. The current `dependabot.yml` points its two `docker` entries at
`/NetOps_Observability/deployment/docker` and `.../swtpm-sidecar`, so it covers the 19 `FROM` lines —
and **zero of the 35 distinct image references in the compose files**. Those 35 are Kafka, Postgres,
ClickHouse, OpenSearch, Keycloak, VictoriaMetrics, Grafana, NetBox, Vector, syslog-ng and the rest:
by volume, the overwhelming majority of the third-party code this product actually runs. Renovate's
`docker-compose` manager reads them natively, including digest-only refreshes.

This alone decides it. Everything below is corroboration.

### 3.2 Dependabot cannot track a version that is a plain string

Twelve gate-tool and toolchain pins (§1 rows 2 and 8) are bare strings in `env:` blocks. Dependabot
has no mechanism for these. Renovate's `customManagers` bind each one to a real datasource — the
`go` proxy for staticcheck/gosec/govulncheck/golangci-lint, PyPI for ruff/bandit/mypy/pip-audit/pytest,
GitHub releases for gitleaks, `golang-version` for the toolchain. Eleven custom managers are
configured; each names exactly one dependency, because a regex manager binds one `depName` and a
shared block would mislabel every match.

### 3.3 Dependabot has no automerge

Dependabot version-update PRs cannot automerge from `dependabot.yml`. The usual workaround is a
second workflow running `dependabot/fetch-metadata` and `gh pr merge --auto`, which means a bespoke
merge robot with write permission — more code, and a second thing to keep correct. Renovate has
`automerge` + `platformAutomerge`, which delegates to GitHub's native auto-merge and therefore
inherits branch protection for free: **the PR merges when, and only when, the required checks pass.**
That is exactly the "green full gate" condition the ask specifies, expressed once rather than
reimplemented.

### 3.4 Grouping that spans ecosystems

The Go toolchain raise touches `go.mod`, a workflow `env:` var, three Dockerfile digests and four
gate-tool pins — four different managers. Dependabot groups only *within* one ecosystem and one
directory, so that raise would arrive as four unrelated PRs, each of which is red on its own.
Renovate's `groupName` crosses managers, so it arrives as one reviewable change. `backend-ci.yml`'s
own header already documents why they cannot move separately: *"a scanner binary built with an older
Go refuses to load a go1.26 module."*

### 3.5 Hash-locked Python

`src/correlation/requirements.txt` is `pip-compile --generate-hashes` output; pip auto-enables
`--require-hashes` because hashes are present. Dependabot's `pip` ecosystem would rewrite pins and
orphan the hashes. Renovate's dedicated `pip-compile` manager reads the header comment, re-runs the
exact command, and keeps the lock valid. The config explicitly leaves the generic `pip_requirements`
manager **off** so it can never touch that file.

### 3.6 Why self-hosted rather than the Mend Renovate App

The hosted App is the default path and it is genuinely easier. It is also a third-party service
holding write access to a repository whose CLAUDE.md opens with *"no implicit trust between
services."* Running Renovate from a SHA-pinned action on our own runner costs one workflow file and
one secret, and keeps the trust boundary where §3 puts it. The action is pinned at
`renovatebot/github-action@39b914146caeff8cd512e61c8992f1d5913af85c` (v46.2.5) and the Renovate
version itself at `44.59.3`, in the same SC-010 spirit as `STATICCHECK_VERSION` and friends.

**The cost is one hard requirement:** the bot needs a PAT or GitHub App token, *not* `GITHUB_TOKEN`.
A PR opened with `GITHUB_TOKEN` does not trigger other workflows, so `backend-ci`, `frontend-ci`,
`correlation-ci` and `supply-chain` would never run on a Renovate PR; every required check would sit
at "Expected", and automerge could never fire. The gate would be silently inert. `renovate.yml`
therefore **fails the run loudly** when `RENOVATE_TOKEN` is absent instead of skipping (§16.1).

### 3.7 What we give up

Honest accounting:

- **Renovate is a bigger, more configurable tool.** `renovate.json` is ~370 lines against
  `dependabot.yml`'s 50. That complexity is not decoration — it is the 47 compose pins and the 12
  string pins — but it is a real maintenance surface. Mitigated by the blocking
  `renovate-config-validator` job, which fails a PR that breaks the config rather than letting a
  mistyped rule silently disable itself.
- **Renovate regenerates lock artifacts by running the real toolchains** (`go mod vendor`,
  `npm install`, `pip-compile`), which needs `RENOVATE_BINARY_SOURCE=install`. If that ever
  misbehaves, a bump could arrive with a stale lock. For Go, the new `offline-build` job catches it
  outright. For npm the lock is regenerated by `npm ci` in CI anyway. For pip, `--require-hashes`
  makes a stale lock a hard install failure in `correlation-ci`. All three classes have a backstop;
  none relies on the bot being correct.
- **Dependabot *alerts* stay on.** Only *version updates* are retired. Renovate's
  `vulnerabilityAlerts` block consumes GitHub's advisory data, and `osvVulnerabilityAlerts: true`
  adds OSV coverage for ecosystems GitHub is thin on.

### 3.8 Cutover

`.github/dependabot.yml` and `.github/renovate.json` must not both be live — they would open
duplicate PRs against the same manifests. **This change leaves `dependabot.yml` in place on purpose.**
Delete it in the same commit that sets `RENOVATE_TOKEN`, so the repo is never left with neither.
`docs/runbooks/patch-train.md` §Setup carries the two-step order.

---

## 4. The train: schedule, grouping, automerge

### 4.1 Two lanes

| Lane | Trigger | Schedule | Automerge |
|---|---|---|---|
| **Patch train** | weekly cron | Mondays 03:17 UTC (`* 0-6 * * 1`) | per §4.3 |
| **Security** | a published advisory | `at any time`, `minimumReleaseAge: null` | **never** |

A security advisory does not wait for Monday, and it does not automerge either — the emergency path
in the runbook requires a human to run the gate, rebuild from a clean checkout, and prove the engines
are consuming afterwards. Concurrency is capped (`prConcurrentLimit: 8`, `prHourlyLimit: 4`) so a
quiet week cannot turn into 40 open PRs.

### 4.2 Groups

Eleven groups, each chosen so that everything inside it must move together or must be reviewed
together:

| Group | Contents | Automerge |
|---|---|---|
| `go toolchain` | `go.mod` `go`/`toolchain`, `GO_VERSION`, `golang:*-alpine` digests, the 3 satellite `go.mod` files | **no** — playbook (§5) |
| `go gate tools` | staticcheck · gosec · govulncheck · golangci-lint · gitleaks | **no** — new findings must be fixed in the same PR |
| `python gate tools` | ruff · bandit · mypy · pip-audit · pytest | **no** — same reason |
| `go modules (allowlisted)` | the 9 vendored modules | patch + minor |
| — majors of the above | | **no**, and dashboard-approval before a PR even opens |
| `container image digests` | digest-only refresh, same tag | **yes** |
| — image *tag* changes | postgres 16→17, opensearch 2.16→2.17, … | **no** |
| — stateful stores | postgres, clickhouse, opensearch, kafka, victoriametrics, netbox, keycloak | **no**, always |
| `github actions` | digest + patch | yes; major/minor reviewed |
| `frontend dev dependencies` | `src/frontend` devDeps | patch + minor |
| — `src/frontend` runtime deps | | patch only |
| — `@playwright/test` | | **no** — the npm package and the browser build must match |
| `docs portal` | all of `docs-portal` | **no**, monthly, `prPriority: -5` |
| `correlation runtime` | the hash-locked lock | patch only |
| lab trees | `scripts/lab/**`, `vm-image-builder` | **disabled** — not shipped (`make-installer.sh` `LAB_PATHS`) |

### 4.3 What "automerge with a green full gate" means mechanically

`automerge: true` + `platformAutomerge: true` calls GitHub's native auto-merge. GitHub then holds the
PR until every **required status check** on `main` passes. So the strength of automerge is exactly the
strength of the required-check list — and today that list is five checks
(`docs/runbooks/ci-branch-protection.md` §1), which does **not** include `govulncheck`'s siblings, the
supply-chain gates, or the new offline build.

**Automerge must not be enabled until the required-check list is extended.** The list below is the
precondition, not a nice-to-have; it is step 3 of the runbook's Setup.

Required checks to add before turning automerge on:

| Workflow | Check name |
|---|---|
| backend-ci | `build · vet · test · race` |
| backend-ci | `govulncheck (blocking)` |
| backend-ci | `staticcheck + gosec (crypto/trust packages, blocking)` |
| backend-ci | `golangci-lint (repo-wide, blocking)` |
| backend-ci | `Postgres integration (blocking)` |
| backend-ci | **`offline vendor build (blocking)`** ← new |
| correlation-ci | `pytest (blocking)` |
| correlation-ci | `ruff · bandit · mypy · pip-audit (blocking)` |
| frontend-ci | `tsc -b && vite build (blocking)` |
| frontend-ci | `npm audit (blocking)` |
| frontend-ci | `Playwright E2E (blocking)` |
| supply-chain | `Trivy filesystem scan (blocking)` |
| supply-chain | `gitleaks secret scan (blocking, full history)` |
| supply-chain | `CIS-Docker policy gate (blocking)` |
| fresh-install-integrity | `integrity`, `scripts-lint` |
| renovate | `renovate-config-validator (blocking)` |

> **DONE 2026-09-03.** `ci-branch-protection.md` §1 listed the backend test job as
> `build · vet · test · race · fuzz`. The job's actual `name:` is
> **`build · vet · test · race`** — live fuzzing was removed from the per-PR gate and moved to
> `fuzz-nightly.yml`. A required check whose name does not match a real job pins every PR at
> "Expected" forever. That runbook has had its correction pass: §1 now carries all sixteen
> blocking checks (this table plus `golangci-lint (repo-wide, blocking)`,
> `ruff · bandit · mypy · pip-audit (blocking)`, `npm audit (blocking)`,
> `Playwright E2E (blocking)`, `panel↔metric contract (blocking)` and
> `Third-party licence gate (blocking)`), and §4's `gh api` payload matches it.
>
> One correction to the table ABOVE: **`renovate-config-validator (blocking)` must not be
> required.** `renovate.yml`'s `pull_request` trigger carries a `paths:` filter
> (`.github/renovate.json`, `.github/workflows/renovate.yml`), so on a PR touching neither file
> the check never reports and the PR sticks at "Expected" — the exact deadlock this note warns
> about. Either leave it out or drop that `paths:` filter first. The
> `fresh-install-integrity` rows are also real but optional: `integrity` declares no `name:`
> (the check name is the job **id**), `scripts-lint` reports as
> `ruff (scripts/*.py, blocking)`, and the workflow's third job
> (`install.py --tls=yes two-phase boot (blocking)`) is the slowest check in the repo.

---

## 5. The offline-build required check

New `offline-build` job in `backend-ci.yml`:

```yaml
env:
  GOFLAGS: -mod=vendor
  GOPROXY: off
run: go build ./...
```

with `cache: false` on `setup-go`, plus a `go vet` pass and a `go test -run='^$'` pass that compiles
every test binary without running it (a test-only import missing from `vendor/` is still a broken
air-gapped build).

Three properties make it the right backstop:

- `GOPROXY=off` turns any network reach into a hard error rather than a slow success.
- `cache: false` denies the job a warm module cache, which would otherwise paper over a package
  missing from `vendor/`.
- `-mod=vendor` makes the toolchain cross-check `vendor/modules.txt` against `go.mod` **before**
  compiling. A bump that edits `go.mod` without re-vendoring fails as `inconsistent vendoring`.

We deliberately do **not** run `go mod vendor` to verify the tree: regenerating needs the module
cache and would have to reach the proxy, defeating the purpose. The toolchain's own consistency check
covers the case.

Verified locally at HEAD: `GOFLAGS=-mod=vendor GOPROXY=off go build ./...` → exit 0, ~7 s.

---

## 6. Per-class mechanics

### 6.1 Go modules (vendored)

Renovate's `gomod` manager updates `go.mod`/`go.sum` and, because `vendor/modules.txt` is present,
re-runs `go mod vendor` as part of the artifact update. `postUpdateOptions: ["gomodTidy",
"gomodUpdateImportPaths"]`. `constraints.go: "1.26"` keeps resolution honest against the declared
toolchain.

The §6 allowlist is preserved structurally: Renovate updates only modules already required, so it
**cannot add one**. Majors carry `dependencyDashboardApproval: true` — no PR opens until a human ticks
it — and a PR-body note demanding the four §6 gates be re-argued and the CLAUDE.md table updated in
the same PR.

> **Gap worth closing separately.** Nothing in CI currently asserts that `go.mod`'s direct requires
> are a subset of the §6 allowlist. The rule is enforced by human review alone. A ~40-line stdlib
> guard in `tests/` (parse `go.mod`, compare against a literal allowlist, fail on an unlisted direct
> require) would make it mechanical. Out of scope here — one bounded context per change (§7) — but it
> is the natural next step, and it is the only thing that would make §6 robot-proof rather than
> convention-proof.

### 6.2 The Go toolchain (worked example: 1.25 → 1.26, done 2026-09-02)

Today's raise is the reference. `x/crypto` v0.56.0 (GO-2026-6354/6355, `ssh` DoS) declares
`go 1.26.0`, so the module stopped building on 1.25. Nine sites had to move:

| # | Site | 2026-09-02 value |
|---|---|---|
| 1 | `src/backend/go.mod` `go` | `1.26.0` |
| 2 | `src/backend/go.mod` `toolchain` | `go1.26.8` |
| 3 | `backend-ci.yml` `GO_VERSION` | `1.26.8` |
| 4 | `Dockerfile.backend` builder FROM | `golang:1.26.8-alpine@sha256:ce864e72…` |
| 5–6 | `mock-nms`, `mock-servicenow` Dockerfiles | same digest |
| 7 | `STATICCHECK_VERSION` | `2026.2.1` |
| 8 | `GOSEC_VERSION` | `v2.29.0` |
| 9 | `GOVULNCHECK_VERSION` | `v1.7.0` |

`GOLANGCI_VERSION` stayed at `v2.12.2` only because that release's published binary happens to be
built with go1.26.2 — the workflow comment records the reasoning, which is exactly the kind of
judgement a bot cannot make. Hence: grouped into one PR, never automerged, and the runbook carries
the ordered playbook.

**Three sites the 2026-09-02 raise missed**, found while writing this plan:

- `scripts/installer-gui/go.mod` — still `go 1.25.0` / `toolchain go1.25.13`, while `backend-ci.yml`'s
  gofmt step runs over it with Go 1.26.8.
- `deployment/docker/mock-nms/go.mod` and `mock-servicenow/go.mod` — still `go 1.25`, while their
  Dockerfiles build with `golang:1.26.8-alpine`.
- `fuzz-nightly.yml` line 37 **hardcodes** `go-version: '1.26.8'` instead of referencing `GO_VERSION`.
  It happens to be correct today. Nothing links them, so the next raise will silently split them.

The first two are covered by the config (the satellite `go.mod` files are in the `go toolchain`
group). The third cannot be — a hardcoded literal in one workflow that must equal an `env:` var in
another is a structural problem, not a bot problem. Fix by referencing the var.

### 6.3 Container images

`docker-compose` and `dockerfile` managers with `pinDigests: true`. The split that matters:

- **Digest-only refresh** (same tag, upstream rebuilt with a distro CVE fix) → **automerged**. This is
  the highest-value automation in the repo: it is how a rebuilt base image actually reaches 47 pins
  without a human retyping a `sha256`.
- **Tag change** → human. Stateful stores get an extra never-automerge rule on top.

**Four unpinned image references** exist today and should be pinned in a separate hygiene commit;
Renovate's `pinDigests` will offer to do it on first run:

| File | Reference |
|---|---|
| `deployment/docker/cloud-ingest/Dockerfile:1` | `python:3.12-slim` |
| `deployment/docker/vm-image-builder/Dockerfile:6` | `ubuntu:24.04` |
| `deployment/docker/docker-compose.flowgen.yml:16` | `python:3.12-slim` |
| `scripts/lab/traffic-generator/Dockerfile:4` | `python:3.12-slim` |

The CIS-Docker gate (`scripts/audits/cis_docker.py`) requires digest pins only on the four *owned*
Dockerfiles, which is why these slipped through. Also note `scripts/lab/twin/docker/Dockerfile` pins a
**different** `python:3.12-slim` digest (`2c941e86…`) than `Dockerfile.correlation` (`090ba77e…`) — two
pins of the same tag drifting apart.

**`compose.offline-images.yml` needs no automation, and that is worth writing down** so nobody
"fixes" it. It is the offline-mirror pull list: 23 image references, tag-only, no digests, mirroring
images that `docker-compose.yml` pins *by digest*. That looks like drift waiting to happen, and it is
not — the file is **generated by `install.py` at offline-install time from `docker-compose.yml`'s own
pins**, and it is gitignored. It is tag-only because `docker load` restores image **tags, not
registry digests**; the bundle's `SHA256SUMS` carries integrity end-to-end instead. Because it is
derived rather than authored, it cannot diverge from its source, and because it is untracked it is
correctly absent from both the SBOM and Renovate's view. Two other gitignored overlays
(`compose.lab.yml`, `docker-compose.override.yml`) are site-local for the same reason.

### 6.4 Gate tools and scanner engines

Eleven custom managers, one per tool (§3.2). `GOLANGCI_VERSION` is matched in **both**
`backend-ci.yml` and `scripts/ci-backend-guard.sh` so the CI pin and its local mirror can never split.

**Trivy is the one class that stays manual.** Its binary and vulnerability-DB version are carried
solely by the `aquasecurity/trivy-action` SHA; there is no version env var to track. Renovate will
bump the action SHA (which moves the trivy version with it), but the *DB* refreshes continuously
upstream and is not pinnable. This is fine — a scanner DB that updates itself is the desired
behaviour — but it means **a supply-chain run can go red with no change on our side**. That is not a
bug; treat it as the advisory arriving.

---

## 7. Owner action required

One secret, then two settings:

1. **Create `RENOVATE_TOKEN`** — a fine-grained PAT (or GitHub App installation token) on
   `RaoRakurty/NetOps_Observability` with `Contents: read+write`, `Pull requests: read+write`,
   `Workflows: read+write`. Store as a repository secret. Without it `renovate.yml` fails loudly by
   design.
2. **Enable "Allow auto-merge"** in repo settings — `platformAutomerge` is inert without it.
3. **Extend the required-check list** to the table in §4.3 *before* automerge is relied upon, and
   delete `.github/dependabot.yml` in the same commit as step 1.

---

## 8. Current drift report — 2026-09-03

Collected today. Network was reachable (`proxy.golang.org`, npm registry, PyPI, OSV all responded),
so every upstream comparison below is real, not inferred. **Nothing was bumped.**

### 8.1 Go modules — near-current

`GOFLAGS=-mod=vendor GOPROXY=off go build ./...` → **exit 0** (~7 s). Offline build intact. 9 modules
in `vendor/modules.txt`, matching `go.mod` 1:1.

| Module | Pinned | Latest | Drift |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.9.2 | **v5.10.0** | one minor |
| `golang.org/x/net` | v0.57.0 | **v0.58.0** | one minor |
| `golang.org/x/crypto` | v0.56.0 | v0.56.0 | current |
| `golang.org/x/sync` · `x/sys` · `x/text` · `puddle/v2` · `pgpassfile` · `pgservicefile` | — | — | all current |

`pip-audit`-equivalent for Go: `govulncheck` v1.7.0 with a DB refreshed 2026-09-02. **No open Go
advisory.** This is the healthiest class in the tree, and it is the one Dependabot already covered.

### 8.2 Go toolchain — one minor line behind stable

Repo is on **go1.26.8**, which is the newest patch of the 1.26 line. Upstream stable is **go1.27.1**.
Staying on 1.26 is a defensible position (1.26.8 is fully patched); it is drift to *track*, not drift
to *fix*. Satellite modules lag as described in §6.2.

Gate-tool binaries installed on the dev host match all six CI pins exactly (staticcheck 2026.2.1,
gosec v2.29.0, govulncheck v1.7.0, golangci-lint v2.12.2, gitleaks 8.30.1). No drift between CI and
the local mirror.

### 8.3 npm — `src/frontend` clean, `docs-portal` is the problem

**`src/frontend`** — `npm audit`: **0 vulnerabilities** across 265 packages. 20 packages outdated, but
every one of them is a *major* the project has deliberately not taken (React 19, Vite 8, Vitest 4,
TypeScript 7, `@vitejs/plugin-react` 6, xterm 6, jest-dom 7). Within-range drift is trivial: four
`@fontsource/*` at 5.2.x→5.3.0, `@xyflow/react` 12.11.0→12.11.6, `happy-dom` 20.10.4→20.13.2,
`@testing-library/react` 16.3.2→16.3.3. Playwright is pinned exact at 1.60.0 (latest 1.62.1) and must
stay in step with its browser build.

**`docs-portal`** — **26 advisories: 12 high, 14 moderate**, all inside the Docusaurus 3.5.2 build
chain (latest 3.10.2). The `.trivyignore.yaml` already documents one of them
(GHSA-5c6j-r48x-rmvq, `serialize-javascript`) as build-time-only on trusted markdown. That reasoning
holds for the class as a whole — this is a static-site generator run against our own docs, not a
product runtime — but "12 high" is not a number to leave unexplained in a release. Two further notes:
the `fast-uri ^3.1.4` override does **not** clear its advisory (the vulnerable range is 3.0.0–3.1.5),
and the `webpack 5.88.2` override sits *inside* the vulnerable range. Tracker row **123** covers this.
The realistic fix is the Docusaurus 3.10 upgrade, which needs Node 20 — hence the config groups the
whole portal into one monthly, never-automerged PR.

**`scripts/lab/traffic-generator/webui`** — 5 advisories (4 high: browserslist, nanoid, postcss, vite;
1 moderate: esbuild). Lab-only, excluded from the customer bundle by `LAB_PATHS`, and disabled in the
Renovate config. Noted so it is not mistaken for product exposure.

### 8.4 Python — locked, clean, and a long way behind

`pip-audit --no-deps -r requirements.txt -s osv` → **"No known vulnerabilities found."** The
hash-locked 27-package closure has no open advisory. The running `netops-correlation-7` container's
installed set matches `requirements.txt` exactly.

But **21 of 29 installed packages are outdated**, several by a lot:

| Package | Pinned | Latest |
|---|---|---|
| uvicorn | 0.30.6 | **0.52.4** |
| fastapi | 0.133.1 | 0.141.1 |
| pydantic / pydantic-core | 2.9.2 / 2.23.4 | 2.13.5 / 2.48.0 |
| aiokafka | 0.11.0 | **0.14.0** |
| starlette | 1.3.1 | 1.6.0 |
| cramjam | 2.8.4 | 2.12.1 |
| asyncpg | 0.29.0 | 0.31.0 |
| httpx | 0.27.2 | 0.28.1 |
| websockets | 16.0 | 17.1 |

No advisory pressure, so nothing is urgent — but `aiokafka` and `uvicorn` sit under the correlation
engine's consumer loop, which is the component with the most hard-won behaviour in the tree
(rebalance handling, flush-on-revoke, storm mode). These are exactly the bumps that need the
qualification rig, not a Monday automerge. The config puts `pip-compile` majors/minors on the human
lane for this reason.

### 8.5 Container images — the real drift

Registry digests were **not** queried (no `skopeo`/`crane`/`trivy` on the host, and no pull was
performed). Local image copies match the compose pins exactly for every external image, so the ages
below are the *pinned tag's* age, which is the number that matters:

| Age of pinned tag | Images |
|---|---|
| **3 years** | `danielqsj/kafka-exporter:v1.7.0` |
| **2 years** | `balabit/syslog-ng:4.7.1` · `grafana/grafana:11.2.0` · `netsampler/goflow2:v2.2.1` · `prom/node-exporter:v1.8.2` · `timberio/vector:0.40.0-alpine` · `victoriametrics/{victoria-metrics,vmalert,vmauth}:v1.101.0` |
| ~23 months | `curlimages/curl:8.10.1` · `quay.io/keycloak/keycloak:25.0` · `opensearchproject/opensearch-dashboards:2.16.0` |
| ~18 months | `clickhouse/clickhouse-server:24.8-alpine` |
| ~17 months | `gcr.io/cadvisor/cadvisor:v0.52.1` |
| ~10 months | `apache/kafka:4.1.1` |
| ~3 months | `ghcr.io/openconfig/gnmic:0.46.0` · `postgres:16-alpine` |
| ~2 months | `valkey/valkey:8-alpine` |

**This is the largest and least-managed drift in the product.** Eight images are two-plus years old.
Trivy's `ignore-unfixed: true` means base/distro CVEs with no fix available do not block, which is the
right call for merges but does mean age accumulates invisibly. `vector 0.40.0` is doubly load-bearing:
it is also the version whose VRL crypto quirks the pipeline is calibrated against, so it is a
deliberate pin, not neglect — but that reasoning is not written down next to the pin.

Note also: `prom/prometheus:v2.54.1` is still in the host's local image store although Prometheus
appears in no compose file. Consistent with the #97 removal; a leftover layer, not a live pin.

### 8.6 GitHub Actions — 5 unpinned references

53 `uses:` lines, 16 distinct refs. 48 are correctly SHA-pinned with a `# vX.Y.Z` comment. **Five are
not**, against the repo's own SC-002 policy:

| File | Line | Reference |
|---|---|---|
| `fresh-install-integrity.yml` | 48, 59, 83 | `actions/checkout@v4` |
| `scale-miniladder-nightly.yml` | 37 | `actions/checkout@v4` |
| `scale-miniladder-nightly.yml` | 130 | `actions/upload-artifact@v4` |

`helpers:pinGitHubActionDigests` in the config will pin these on the first run. Spot-verified that the
existing pins are honest: `actions/checkout` v4.3.1 really is
`34e114876b0b11c390a56381ad16ebd13914f8d5`.

### 8.7 Version-pin sites that must move together

31 pin sites across 11 workflow files. Beyond the Go set (§6.2):

- **Node is pinned at three different values in four files**: `'18'` in `frontend-ci.yml` (×3), `20`
  in `fresh-install-integrity.yml` and `scale-miniladder-nightly.yml`, `'20'` in `release-bundle.yml`
  and `publish-images.yml`. The product frontend is *built* on 18 in CI while the release bundle
  builds it on 20 — two different toolchains producing the shipped asset.
- **Python is pinned at two values across five files**: `'3.12'` (correlation-ci ×2, perf-nightly) vs
  `'3.10'` (ingest-contract-ci, telemetry-catalog-ci, tracker-ci).
- **pytest is pinned three times and deliberately not aligned** (9.1.1 in correlation-ci, 9.0.3 in the
  other two) — documented in `correlation-ci.yml`, and the config tracks each separately so aligning
  them stays an explicit decision.

---

## 9. Follow-ups this plan identified but does not fix

Each is a separate bounded change (§7).

1. **§6 allowlist guard** — no CI check asserts `go.mod`'s direct requires ⊆ the CLAUDE.md allowlist.
2. **`fuzz-nightly.yml` hardcodes the Go version** instead of referencing `GO_VERSION`.
3. *(withdrawn — `compose.offline-images.yml` is generated from `docker-compose.yml` by `install.py` and cannot drift; see §6.3.)*
4. **Four unpinned image references** (§6.3) and two divergent `python:3.12-slim` digests.
5. **`docs/runbooks/ci-branch-protection.md` is stale** — it names a job
   (`build · vet · test · race · fuzz`) that no longer exists under that name, and its §6 still says
   "container image CVE scanning and SBOM are not yet wired" and recommends adding gitleaks, all three
   of which shipped in `supply-chain.yml`.
6. **Satellite Go modules** left on `go 1.25` by the 2026-09-02 raise.
