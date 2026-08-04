# Runbook (OUTLINE) — Migrate ClickHouse to TLS + certificate authentication

> **Status: OUTLINE. NOT EXECUTABLE — feature not built.** ClickHouse is reached
> over `http://clickhouse:8123` with Basic credentials
> (`deployment/docker/docker-compose.yml:974,1120`), i.e. **credentials in the
> clear on every request**. Every step below is **[PENDING SEC-010]**.

**Decision record:** ADR-SEC-004 (native TLS + native authz), ADR-SEC-008
(violation V3).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) "Outbound backend
TLS (phase 3)" — the client side already exists and fails closed; this is the
server side. Also `docs/runbooks/clickhouse-query-budget.md` and
`docs/runbooks/correlation-retention-cold-archive.md` for the operational
context this must not disturb.

---

## 1. Purpose

Move every ClickHouse connection to TLS with certificate-based client
authentication, **while preserving the row-policy tenant isolation that is
currently the strongest control in the platform.**

## 2. Prerequisites

- [ ] `bootstrap-pki.md` complete; a ClickHouse server certificate and client
      certificates for each consumer.
- [ ] Inventory of every ClickHouse client: the Go API
      (`CLICKHOUSE_URL`, via `backend_client.go`), `vector-router` (the write
      path), the `correlation` service, cold-export/retention tooling
      (`scripts/ch-cold-export.sh`, `ch-cold-restore.sh`,
      `ch-retention-dry-run.sh`, `ch-query-budget-check.sh`), and any operator
      tooling.
- [ ] The ClickHouse user model drafted: one user per client, least privilege.
- [ ] **A verified backup** (`scripts/backup.sh`; see
      `docs/runbooks/backup-restore.md`).

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **ROW POLICIES ARE THE TENANT BOUNDARY — do not disturb them** | `src/backend/clickhouse_policies.go` converges row policies on every API start (idempotent, self-healing) and is guarded by tests that fail if any policy on a `corr_*`/`path_*` table is written leniently (`clickhouse_policies_test.go:65-69`, `ch_convergence_test.go:96`, `cloud_costs_test.go:79-84`). Any user/role change must preserve them. **A new user without the right policy attached is a cross-tenant leak.** |
| 🔴 **Access-storage reset destroys policies** | Policies live in ClickHouse's access storage (`data/clickhouse/access`). Anything that resets or replaces it drops every policy. HLD §9 phase 4 flags this explicitly: policy recreation after an access-storage reset must be *guarded*, not assumed. The API's convergence-on-start is the safety net — **verify it ran** after any such event. |
| 🔴 **WILL drop telemetry** | `vector-router` writes flows/metrics here. Unauthenticated or mis-configured TLS on that hop stops ingestion; Vector buffers, then drops. |
| 🟠 **Basic credentials are in compose today** | They are exposed on every plaintext request. Treat them as compromised once TLS lands and **rotate them**, do not merely wrap them (`docs/runbooks/secret-rotation.md`). |
| 🟠 **Scripts must not swallow auth errors** | The `ch-*.sh` scripts run unattended (cron). Under `scripts/CLAUDE.md` §16.1 a suppressed auth failure that reports success is forbidden — verify each one surfaces a credential failure loudly. |
| 🟠 **Query-budget and retention jobs will break silently otherwise** | They are the least-watched clients and the most likely to be forgotten in the inventory. |
| ⚪ **Reversible via a dual listener** | Keep the plaintext port until every client is cut over. |

## 4. Pre-validation

1. Verified backup; record table row counts per tenant for the reconciliation.
2. Enumerate **all** clients — including cron scripts — and confirm each can
   present a certificate.
3. Capture the current row-policy set as a fingerprint ("before" evidence).
4. Baseline: ingestion rate, query latency, error rate.
5. **[PENDING SEC-008]** Validator run: record violation V3.

## 5. Procedure *(all steps **[PENDING SEC-010]**)*

1. **Enable the TLS (HTTPS) port** alongside the existing plaintext port. Both
   listening; nothing migrated yet.
2. Install the server certificate; verify the chain and SANs match the names
   clients actually dial (`clickhouse`), because the client cannot skip
   verification by construction.
3. **Create per-client users** with least-privilege grants; attach the correct
   row policies to each. **Verify the policies are attached before the user is
   used.**
4. **Migrate clients one at a time**: Go API (`CLICKHOUSE_URL` → `https://`,
   plus `TLS_BACKEND_*` per `docs/runbooks/tls-mtls.md`), then `vector-router`,
   then `correlation`, then each cron script.
5. After each client: verify writes/reads succeed **and** that a cross-tenant
   query is still refused.
6. **Rotate the old shared Basic credentials** (they transited plaintext).
7. **Remove the plaintext port.** ⚠ Point of no return.
8. Update transport-policy rows; close the migration exception
   **[PENDING SEC-001]**.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–2 | Remove the TLS port; no client affected. |
| 3 | Drop the new users (ensure nothing is using them first). |
| 4–5 | Point the individual client back at the plaintext port — still available. |
| 6 | Credential rotation is not reversible; re-rotate if needed. |
| 7 | Re-add the plaintext port and restart. Recoverable but disruptive. |
| Policy loss | Restart the API to force row-policy convergence (`clickhouse_policies.go`), then **verify** against the pre-migration fingerprint. If convergence does not restore them, restore from backup. |

## 7. Audit evidence to capture

- Row-policy fingerprint **before and after** — the single most important
  artifact in this runbook.
- The user/grant matrix as applied, with reviewer.
- Server and client certificate details.
- Per-client cutover timestamps and verification results.
- Cross-tenant negative-test results, run live after cutover.
- Row counts per tenant before/after; ingestion continuity.
- Old Basic credential rotation record.

## 8. Post-checks

1. Every client on `https://`; the plaintext port is gone.
2. Row policies present and identical to (or stricter than) the "before"
   fingerprint.
3. **Negative test:** a tenant-scoped user cannot read another tenant's rows.
4. The `clickhouse_policies.go` convergence path still runs cleanly on API start
   under the new credentials.
5. Ingestion and query latency at baseline; no error-rate increase.
6. Every cron script (`ch-cold-export.sh`, `ch-retention-dry-run.sh`,
   `ch-query-budget-check.sh`) runs successfully on its next scheduled
   invocation — and would fail loudly if it could not authenticate.
7. Validator violation V3 clears for ClickHouse.
