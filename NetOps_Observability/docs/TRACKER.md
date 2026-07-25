# NetOps_Observability — Current Work Tracker

**Reconciled 2026-07-25.** This file lists what is OPEN. Shipped work is not
re-listed here — `git log` is the record of what landed, and
`docs/audit/INVARIANTS.md` is the record of what is *proven* versus merely built.

> History through 2026-07-20 lives in
> `docs/archive/TRACKER-ARCHIVE-through-2026-07-20.DO-NOT-USE-AS-CURRENT.md`.
> Read it only to recover the rationale behind a past decision. It is frozen and
> was already wrong in places when frozen; never cite it for current state.

**Rules for this file**

1. An entry earns its place by being open. **When it ships, DELETE the row** —
   don't convert it to a ✅ row. The archived tracker reached 263 KB because
   nothing was ever removed, and the rot stayed invisible until an item filed as
   "open research" turned out to have shipped months earlier.
2. Keep the 4-column table shape (`# | Item | Pri | Status`) with a **numeric
   id** — `scripts/tracker_staleness.py` (blocking in `tracker-ci`) parses
   exactly that and cross-checks each open id against `feat()`/`fix()` commits.
   A different shape silently makes the guard inert.
3. Verify a premise against the code before building on it. The staleness guard
   catches shipped-but-not-marked-done; it cannot catch "premise went moot".

---

## 👤 Blocked on owner — nothing moves without these

Not numbered: no commit will ever close these, so the staleness guard correctly
ignores them.

- **O1 · GCP project + service-account key.** No `GCP_*`/`GOOGLE_*` keys exist in
  the environment at all (verified 2026-07-25). GCP is explicitly FIRST in the
  #105 ordering — nothing GCP starts without this.
- **O2 · AWS access key + secret** for the lab tenant. `AWS_REGION` is set;
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` are empty. Blocks all AWS live
  validation and the T5 counter drills.
- **O3 · `az provider register --namespace Microsoft.ResourceHealth`.** One
  command, needs subscription rights. Azure is otherwise fully configured.
- **O4 · Spend decisions:** AWS fidelity Terraform apply (~$2–3/drill day) ·
  ALB for target-health (~$16/mo; no ALB exists in the lab) · Azure VNet flow
  logs (needs a storage account — real engineering, "the next big lane").
- **O5 · Decision:** `aws.json`/`azure.json` are poller-rewritten but still
  git-tracked, so they churn the working tree on every poll. Gitignore + seed a
  fixture, or keep tracked?
- **O6 · Decision:** 8 stale agent worktrees under `.claude/worktrees/` (890 MB,
  each on an unmerged branch with commits). Merge or drop, per branch.

---

## 🔧 Open engineering

| # | Item | Pri | Status |
|---|------|-----|--------|
| 114 | **Kubernetes deployment packaging** — Helm chart over the 19-service stack (StatefulSets + PVCs for CH/OS/PG/Kafka), per-service requests from `RESOURCE_SIZING.md`, ingress replacing nginx, secrets from the installer `.env` contract, air-gapped image bundle for k8s registries, CI packaging leg alongside `make-installer.sh`. Customers get single-host artifacts only today. | High | ⏳ not started — confirmed absent 2026-07-20; **a project, not a task** |
| 115 | **Wire the Postgres integration tests into CI** — `pg_integration_test.go` exists and compiles (`c7b2fa58`) but is `//go:build pgintegration` and nothing runs it. Needs a Postgres service container in `backend-ci.yml`. Closes INVARIANTS standing gap #4; until then the tests rot. | High | ⏳ not started |
| 116 | **Extract a `tenantRepo` interface** — INVARIANTS gap #3: the F-81 tenant-create rollback is compile-reviewed only because `s.tenants` is a concrete `*tenantStore` with no seam, so mid-request failure cannot be injected. The fix is named in the gap itself. Most tractable of the invariant gaps. | High | ⏳ not started |
| 117 | **250 deferred ruff findings** — `618b87b8` pinned ruff to 0.15.22 to restore determinism after an unpinned upgrade turned CI red. That defers the new rules, it does not resolve them; `ruff check --fix` handles 197 automatically. Do this BEFORE the next deliberate ruff bump. | Med | ⏳ not started |
| 118 | **echarts XSS (GHSA-fgmj-fm8m-jvvx)** — moderate, so `npm audit --audit-level=high` does not block it, but it is an XSS in the library rendering the dashboard. Fix is echarts 6.x, a breaking major: needs a planned migration, not `audit fix --force`. | Med | ⏳ not started |
| 119 | **#102 tail — `--plan-resources` default-on for dev installs.** P1–P5 all shipped and live; `install.py` still has `default=None` while the customer bundle is already default-on. | Low | ⏳ not started |
| 120 | **#105 T5 prep — counter-verification harness** from the `docs/design/cloud-provider-parity.md` acceptance drills, built now so the drills run the moment O1/O2 land instead of after. | Med | ⏳ not started |
| 121 | **#53 remnants** — the Explorer and dedup/triage halves shipped (`events_feed.go`, `alert_episodes.go`). Left: maintenance windows (no `maintenance` handling in the alert path), audit + deploy events as feed sources, UI processor editor (enrich/normalize/redact is still Vector YAML). | Med | ⏳ not started |
| 122 | **Audit the other 9 workflows for unpinned tools** — `backend-ci.yml` pins all five of its tools; `correlation-ci.yml` did not, and that cost a red branch on 2026-07-25. The convention exists; apply it uniformly. | Med | ⏳ not started |
| 123 | **`docs-portal` advisory triage** — 46 npm advisories (14 high). Only 2 were Trivy-visible (`ignore-unfixed: true`) and are fixed. Triage the rest so what is deferred is deferred knowingly. | Low | ⏳ not started |
| 124 | **Notification hook swallows every error** — the `.claude/settings.local.json` Notification hook ends in `2>/dev/null \|\| true`, the §16.1 cardinal rule violated in our own tooling. If the ntfy push dies, nothing reports it. | Low | ⏳ not started |
| 125 | **Stale customer bundle** — the pre-push hook warns on every push; `make bundle` when ready to ship. Note `6092adce` deliberately took this off its daily cron per §16.4, so rebuild is event-driven and manual by design. | Low | ⏳ not started |

---

## 🏷️ Deferred by design — not open, do not re-file

- **Off-host DR + disk sizing (F-55)** — CODE-COMPLETE, tagged for first-customer
  validation (`TAG:OFFHOST-DR`, `TAG:F55-DISK` in
  `docs/runbooks/first-customer-acceptance.md` §9). The lab has no off-host store
  and no large disk to finish the proof against; a real customer environment
  does. Not code. INVARIANTS standing gap #1.
- **#70 AWS leg of the cross-seam network** — DROPPED 2026-07-25, superseded by
  the cloud program that actually shipped (#104/#105/#110).
- **#73 multi-vendor telemetry coverage** — DROPPED 2026-07-25, build items ①–⑥
  included. BGP all-AFI is **not** being refiled; `profiles.go:68` stays
  IPv4-only as a known, accepted state. The 23 verified groundings remain in
  `docs/design/telemetry-coverage-reference.md`.
- **T4 (#67 replay calibration)** — parked; reopen trigger = promoted-incident
  history exists.
- **T6 Stream 6** — parked; designs saved. Revisit before scale.
- **#55 per-role session policy UI** — won't do (owner, 2026-06-09).

---

## 📌 Remaining INVARIANTS standing gaps

`docs/audit/INVARIANTS.md` — not this file — is authoritative for what is *proven*.

| Gap | State |
|-----|-------|
| #1 Off-host DR / disk sizing | Deferred to first customer (above) |
| #3 Tenant-create rollback compile-reviewed only | → item **116** |
| #4 Postgres paths compile-reviewed only | Tests now exist → item **115** to actually run them |
| #5 `go test -race` runs only in CI | No local gate; the sandboxes used had no cgo |
| #6 Documented env switches unverified as a class | One was found lying; nothing checks the rest |
| #7 API response-shape stability is prose | Totals ride on headers; a header-blind client silently misses them |
