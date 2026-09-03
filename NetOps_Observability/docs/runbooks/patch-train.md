# Runbook: the patch train

Keeping every dependency class current, on a schedule, without breaking a running stack.

**Design + reasoning:** [`docs/design/PATCH_AUTOMATION_PLAN_2026-09-03.md`](../design/PATCH_AUTOMATION_PLAN_2026-09-03.md).
**Config:** `.github/renovate.json` · `.github/workflows/renovate.yml` · the `offline-build` job in `.github/workflows/backend-ci.yml`.

Three procedures live here:

| | When | Who | Takes |
|---|---|---|---|
| **A. Weekly triage** | Monday, after the train runs | maintainer | 15–30 min |
| **B. Monthly review** | first Monday | maintainer + owner | 45 min |
| **C. Emergency** | a CVE lands in a running lane | maintainer, owner informed | 1–3 h |

---

## Setup (once — owner)

The train is inert until all four steps are done. Do them in this order; the repo must never be left
with neither Dependabot nor Renovate running.

1. **Create the token.** A fine-grained PAT (or GitHub App installation token) on
   `RaoRakurty/NetOps_Observability` with `Contents: read+write`, `Pull requests: read+write`,
   `Workflows: read+write`. Save as repository secret **`RENOVATE_TOKEN`**.

   > `GITHUB_TOKEN` will not do. A PR opened with it does not trigger other workflows, so every
   > required check would sit at "Expected" and automerge could never fire. `renovate.yml` fails the
   > run loudly if the secret is missing — that is deliberate (CLAUDE.md §16.1), not a bug.

2. **Delete `.github/dependabot.yml`** in the same commit. Running both bots opens duplicate PRs
   against the same manifests. Leave GitHub's Dependabot **alerts** (Settings → Code security) ON —
   Renovate's `vulnerabilityAlerts` consumes that advisory feed.

3. **Enable auto-merge.** Settings → General → Pull Requests → ☑ *Allow auto-merge*.
   `platformAutomerge` is inert without it.

4. **Extend the required-status-check list** on `main` to the table in the plan §4.3 — including the
   new `offline vendor build (blocking)`. Automerge is exactly as strong as that list; today's list
   is five checks and does not include the supply-chain gates or the offline build.

   > ⚠️ `docs/runbooks/ci-branch-protection.md` §1 names the backend test job
   > `build · vet · test · race · fuzz`. Its real `name:` is **`build · vet · test · race`** — live
   > fuzzing moved to `fuzz-nightly.yml`. A required check that names a non-existent job pins every
   > PR at "Expected" forever. Use the names in the plan.

**Verify setup:** Actions → *renovate* → *Run workflow* with `dry_run: full`. A green run that logs
repository extraction and lists candidate updates without opening a PR means the train is wired.

---

## A. Weekly triage (Monday)

The train runs Mondays 03:17 UTC. By start of day there is a **Dependency Dashboard** issue and some
PRs.

### A1. Read the dashboard first, not the PRs

The dashboard issue (*"Dependency Dashboard (patch train)"*) is the whole picture: what was updated,
what is rate-limited, and — the part that matters — what is sitting behind
`dependencyDashboardApproval` waiting for a human. Anything in that section is a Go **major**, i.e. a
CLAUDE.md §6 allowlist re-review. It does not open a PR until you tick it.

### A2. Sort the PRs into three piles

| Pile | Looks like | Action |
|---|---|---|
| **Automerged already** | `container image digests`, `github actions`, frontend devDeps, Go patch/minor | Nothing. Confirm the merge commits look sane. |
| **Waiting on review** | gate-tool groups, image *tag* changes, `docs portal`, correlation minors | §A3 |
| **Blocked / red** | any PR with a failing check | §A4 |

### A3. Reviewing a held PR

- **`go gate tools` / `python gate tools`** — expect new findings. **Fix them in this PR.** A gate-tool
  bump that needs a follow-up commit is a bump that leaves `main` red. This is a rule the repo learned
  the hard way: an unpinned ruff produced 250 findings on 2026-07-25 between two commits that touched
  no Python. Also check that `GOLANGCI_VERSION` moved in **both** `.github/workflows/backend-ci.yml`
  and `NetOps_Observability/scripts/ci-backend-guard.sh` — Renovate updates both, but verify.
- **Image tag changes** — read `docs/UPGRADE.md` and `docs/runbooks/upgrade-bootstraps.md` before
  merging. Postgres, ClickHouse, OpenSearch, Kafka, NetBox and Keycloak carry on-disk state; a tag
  change can be a migration. These never automerge, by rule.
- **`correlation runtime` minor/major** — `aiokafka` and `uvicorn` sit under the consumer loop
  (rebalance handling, flush-on-revoke, storm mode). Do not merge one of these on a Monday morning
  without rig time. Park it on the dashboard if the rig is not available.
- **`docs portal`** — batched monthly, low priority, ships no product runtime code.

### A4. A red PR

Read the failure before rebasing anything.

- **`offline vendor build (blocking)` red** → `vendor/` did not get regenerated with `go.mod`. The
  message is usually `inconsistent vendoring`. Fix locally:
  ```bash
  cd NetOps_Observability/src/backend
  go mod tidy && go mod vendor
  GOFLAGS=-mod=vendor GOPROXY=off go build ./...   # must be exit 0
  ```
  Push onto the Renovate branch. If this recurs, `RENOVATE_BINARY_SOURCE=install` is not provisioning
  the Go toolchain — check the renovate workflow log, do not paper over it.
- **`Trivy filesystem scan` red with no dependency change** → the scanner's vulnerability DB moved.
  That is the advisory arriving, not a false alarm. Treat as §C.
- **`renovate-config-validator` red** → someone edited `.github/renovate.json`. Reproduce locally:
  ```bash
  cd /path/to/repo && npx --yes --package renovate@44.59.3 renovate-config-validator
  ```

### A5. Verify

At the end of triage:

```bash
gh pr list --label deps                 # nothing unexpected left open
gh run list --workflow backend-ci.yml --branch main --limit 3   # main is green
```

`main` green after the last automerge is the pass condition. If it is not, §A6.

### A6. Rollback

Automerges are ordinary commits on `main` and revert cleanly:

```bash
git revert --no-edit <sha>       # the offending merge
git push origin main             # or via a PR if main is protected (it should be)
```

Then set the dependency to `enabled: false` in `.github/renovate.json` with a comment naming the
reason and a review date, so the train does not re-propose it next Monday. A silent re-proposal of a
change you just reverted is how a bad bump lands twice.

**If the bad bump already reached a deployed stack**, do not revert-and-forget — the running images
are ahead of `main`. Follow §C4–C6 to redeploy the reverted state, including the bootstraps.

---

## B. Monthly review (first Monday, with the owner)

Triage keeps the tree moving. This is the half-hour that catches what triage cannot see.

1. **Regenerate the SBOM and read the diff.**
   ```bash
   cd NetOps_Observability
   python3 scripts/sbom.py --out docs/sbom
   git diff --stat docs/sbom/
   ```
   A component that appeared or changed version without a corresponding PR is the interesting case.

2. **Age-check the container images.** The oldest pins are the largest un-managed risk, and digest
   refreshes hide it: an image can be freshly *rebuilt* and still be two years old by *tag*. As of
   2026-09-03, eight pinned tags are two-plus years old (`kafka-exporter` v1.7.0 is three). Pick one
   per month, read its upstream changelog, and either raise it or write down why not — next to the pin.

3. **Confirm the §6 allowlist still describes reality.**
   ```bash
   grep -A3 '^require' NetOps_Observability/src/backend/go.mod
   ```
   Direct requires must be exactly `github.com/jackc/pgx/v5`, `golang.org/x/crypto`, `golang.org/x/net`.
   Anything else means the allowlist table in `CLAUDE.md` §6 was not amended. (No CI check enforces
   this yet — see the plan §9.1.)

4. **Check `docs-portal` advisory count** against the last review. 26 as of 2026-09-03 (12 high), all
   in the Docusaurus 3.5.2 build chain; tracker row 123. It is build-time-only on our own markdown,
   but the number must be *known*, not merely tolerated.

5. **Check the three unsynchronised toolchain sites** (plan §6.2 / §8.7): the satellite `go.mod` files,
   the hardcoded Go version in `fuzz-nightly.yml`, and the node-18-vs-20 split between `frontend-ci`
   and `release-bundle`.

---

## Toolchain raise playbook

Use when a fix requires a newer Go — the 2026-09-02 raise (1.25.13 → 1.26.8, forced by `x/crypto`
v0.56.0 declaring `go 1.26.0` for GO-2026-6354/6355) is the worked example. Renovate groups these into
one PR and **never** automerges it.

Nine sites move together. Out-of-order edits leave a tree where the compiler and the scanners disagree
about what the module even is.

1. **`src/backend/go.mod`** — `go 1.NN.0` and `toolchain go1.NN.P`.
2. **Re-vendor**: `go mod tidy && go mod vendor`.
3. **`.github/workflows/backend-ci.yml`** — `GO_VERSION`.
4. **`.github/workflows/fuzz-nightly.yml`** — the hardcoded `go-version` (it does *not* reference
   `GO_VERSION`; nothing links them — see plan §9.2).
5. **Builder image digests** — `deployment/docker/Dockerfile.backend`,
   `deployment/docker/mock-nms/Dockerfile`, `deployment/docker/mock-servicenow/Dockerfile`. All three
   use the same `golang:1.NN.P-alpine@sha256:…`.
6. **Satellite modules** — `deployment/docker/mock-nms/go.mod`,
   `mock-servicenow/go.mod`, `scripts/installer-gui/go.mod`.
7. **Gate-tool pins** — a scanner binary built with an older Go **refuses to load** a newer module,
   so `STATICCHECK_VERSION`, `GOSEC_VERSION`, `GOVULNCHECK_VERSION` must move to releases built with
   ≥ the new toolchain. `GOLANGCI_VERSION` needs the same check but may not need to move: v2.12.2's
   published linux-amd64 binary is built with go1.26.2, which is why it survived the 1.26 raise. **Verify,
   record the reasoning in the workflow comment, and do not assume.**
8. **`CLAUDE.md` §6** — the allowlist Notes column records why the raise happened. Update it in the
   same PR.
9. **Verify, in this order:**
   ```bash
   cd NetOps_Observability/src/backend
   GOFLAGS=-mod=vendor GOPROXY=off go build ./...    # offline contract — must be exit 0
   go vet ./... && go test ./...
   bash ../../scripts/ci-backend-guard.sh            # local mirror of the blocking gate
   ```
   Then let CI run the full set (`-race`, `pg-integration`, `govulncheck`, `golangci-lint`).

**Rollback:** revert the whole PR as one unit. A partial revert — say, `go.mod` back to 1.25 while the
Dockerfile stays on the 1.26 builder — produces an image that builds nothing and a CI run whose
failure message points at the wrong file.

## Docker base-digest refresh

Digest-only refreshes (same tag, upstream rebuilt) **automerge**. They are how a rebuilt base image
carrying a distro CVE fix reaches the 47 compose pins without a human retyping a `sha256`.

Nothing to do routinely. Two things to know:

- The refresh only changes `main`. **A running stack keeps its old image until it is rebuilt and
  redeployed** — `docker compose pull && up -d`, or `scripts/update.sh`. `main` being current is not
  the same as the customer being current.
- `deployment/docker/compose.offline-images.yml` lists 23 images **tag-only, with no digests**, while
  `docker-compose.yml` pins the same images *by digest*. The two can drift silently, so the offline
  bundle would ship a different image than the online stack runs. Renovate keeps tags current but
  cannot assert parity. Eyeball it whenever a compose image changes (plan §9.3).

---

## C. Emergency path — a CVE in a running lane

For a published advisory affecting code that is deployed. Renovate opens these immediately, outside
the weekly schedule, labelled `security` — it does **not** automerge them.

The sequence is the one used on 2026-09-01/02 for CVE-2026-56854 and GO-2026-6354/6355.

### C1. Establish whether it is reachable

Not every advisory in the graph is an advisory in the product.

```bash
cd NetOps_Observability/src/backend
govulncheck ./...        # call-graph reachability, not just "the version is in go.mod"
```
```bash
cd NetOps_Observability/src/correlation && pip-audit -r requirements.txt
cd NetOps_Observability/src/frontend && npm audit --audit-level=high
```

If `govulncheck` reports the vulnerable symbol is not reachable, say so in the PR and downgrade to the
weekly train. Record the reasoning — "not reachable" is a claim that must be re-checked when the call
graph changes.

### C2. Bump, minimally

Take the smallest version that clears the advisory. Do not opportunistically bump neighbours in a
security PR; the change must be reviewable at 2 a.m.

If the fix needs a newer Go, this becomes a toolchain raise — run the playbook above, in full, in the
same PR. That is what happened on 2026-09-02.

### C3. Run the gate — the whole gate

```bash
cd NetOps_Observability/src/backend
GOFLAGS=-mod=vendor GOPROXY=off go build ./...   # offline contract first: fastest, catches re-vendor misses
go vet ./... && go test ./... && go test -race ./...
staticcheck ./... && gosec -quiet ./... && govulncheck ./...
bash ../../scripts/ci-backend-guard.sh
```

> The gate tools are **not** on a default PATH — they live in `/home/rao/go/bin`. Export it, or you
> will get a green run that checked nothing:
> ```bash
> export PATH="$PATH:/home/rao/go/bin"
> ```

Push and let CI confirm. A local green is a fast signal, not the gate.

### C4. Rebuild from a CLEAN checkout

**Do not build from the working tree.** It carries uncommitted changes, and an image built from it
cannot be reproduced or attributed to a commit.

```bash
git clone --depth 1 --branch main https://github.com/RaoRakurty/NetOps_Observability.git /tmp/rel && cd /tmp/rel/NetOps_Observability
npm --prefix src/frontend ci && npm --prefix src/frontend run build   # dist/ is gitignored; the image COPYs it
docker compose -f deployment/docker/docker-compose.yml build --pull api correlation frontend nginx
```

> `deployment/docker/Dockerfile.frontend` `COPY`s `src/frontend/dist` and `docs-portal/build`, and
> **both are gitignored**. Building without the `npm run build` step above fails on a clean clone.
> This is the same trap recorded for routine frontend deploys: always build in the main tree first,
> then verify a marker string in the served bundle.

### C5. Deploy — with the bootstraps

```bash
cd /path/to/deployed/NetOps_Observability
scripts/update.sh            # backup → .env reconcile → pull → build → up -d → bootstrap-opensearch
```

`update.sh` runs **only** `bootstrap-opensearch.sh`. It does **not** apply Kafka ACLs, create topics,
or apply the OpenSearch ISM policy. On a TLS/mTLS stack a new topic or a new lane without its ACL
fails the *whole* subscription, not just that lane. `deploy-qualify.sh` in the next step is what runs
those. Read `docs/runbooks/upgrade-bootstraps.md` if the change touched topics, indices or ACLs.

### C6. Qualify — prove the engines are consuming

```bash
scripts/deploy-qualify.sh
echo "exit=$?"
```

Runs the bootstraps (Kafka ACL matrix · `kafka-init` topics · OpenSearch ISM · router-lane
writability), then proves the engines actually work: correlation joined its consumer group, every
`netops-router-*` group has a live member, lag is draining, both Vector tiers are emitting, no
bootstrap-class Kafka errors, API answering, OpenSearch not RED.

| Exit | Meaning | Do |
|---|---|---|
| `0` | qualified | done — record the SHA and image tags |
| `1` | a required check FAILED | **not qualified.** Roll back (§C7). |
| `2` | INCOMPLETE — a required check could not be evaluated | **not a pass.** A SKIP is never a PASS. Re-run with `--timeout 600`; if it stays 2, treat as failure. |
| `3` | precondition failure (docker / project / layout) | fix the environment; nothing was assessed |

`docker compose up` exiting 0 is not evidence of anything. This step is the evidence.

### C7. Rollback

```bash
docker compose -f deployment/docker/docker-compose.yml down
git -C /path/to/deployed checkout <previous-good-sha>
scripts/update.sh --no-backup     # a backup was already taken on the way in
scripts/deploy-qualify.sh         # must exit 0 before you walk away
```

Then revert the PR on `main` and disable the dependency in `.github/renovate.json` with a comment, so
Monday does not re-propose it.

### C8. Record it

- Update the `CLAUDE.md` §6 allowlist Notes column with the CVE and the version it forced — that
  column is the reason the 2026-09-02 raise is reconstructable today.
- If a Trivy finding is a genuine, reasoned exception, add it to `.trivyignore.yaml` **with the
  reasoning and a revisit condition**, in the style of the existing entries. Never a bare ID.
- Add a tracker row if the fix is partial or deferred.

---

## Appendix: what runs where

| Class | Manager | Automerge | Backstop if the bot gets it wrong |
|---|---|---|---|
| Go modules | `gomod` (+ auto `go mod vendor`) | patch/minor | `offline vendor build` fails on a stale `vendor/` |
| Go toolchain | `gomod` + custom `GO_VERSION` | never | playbook above |
| Gate tools ×5 | custom regex, `go` datasource | never | the gate itself goes red |
| Python gate tools ×5 | custom regex, PyPI | never | `correlation-ci` lint job |
| npm (frontend) | `npm` | dev patch/minor, prod patch | `tsc -b && vite build`, `npm audit`, Playwright E2E |
| npm (docs-portal) | `npm` | never, monthly | docs build |
| Python runtime | `pip-compile` | patch only | `--require-hashes` makes a stale lock a hard install failure |
| Images (digest) | `docker-compose`, `dockerfile` | yes | Trivy misconfig + CIS-Docker gate |
| Images (tag) | same | never | `deploy-qualify.sh` on the target |
| GitHub Actions | `github-actions` | digest/patch | workflow fails immediately |
| Trivy engine + DB | *not pinnable* | n/a | the supply-chain gate going red **is** the signal |
