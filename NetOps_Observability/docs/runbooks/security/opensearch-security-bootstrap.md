# Runbook (OUTLINE) — Bootstrap OpenSearch security (authentication + TLS + roles)

> **Status: OUTLINE. NOT EXECUTABLE — feature not built.** OpenSearch runs with
> `DISABLE_SECURITY_PLUGIN: "true"` (`deployment/docker/docker-compose.yml:538`,
> commented "dev default; flip for prod and add certs") and is reached over
> `http://opensearch:9200` (`:571,973,1119`). **There is no authentication at all
> in front of every tenant's logs and flows** — HLD threat T14, scored
> **CRITICAL**. Every step below is **[PENDING SEC-008/009]**.

**Decision record:** ADR-SEC-004 (native authz per component), ADR-SEC-003
(identities), ADR-SEC-008 (violation V4).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) "Outbound backend
TLS (phase 3)" — the **client** side is already built and fails closed
(`TLS_BACKEND_CA_FILE`/`CERT`/`KEY`, `src/backend/backend_client.go`); this
runbook is the **server** side that must exist before those variables mean
anything. Also `scripts/bootstrap-opensearch.sh` (existing, applies index
templates — unrelated to security, but it will need credentials afterwards).

---

## 1. Purpose

Turn on the OpenSearch security plugin: TLS on the HTTP and transport layers,
authentication for every client, and roles that match Correlix's per-tenant
index model. Remove anonymous access permanently.

## 2. Prerequisites

- [ ] `bootstrap-pki.md` complete; a server certificate for OpenSearch and client
      certificates for every consumer (**who mints these is ADR-SEC-003 U5,
      unresolved**).
- [ ] Inventory of every OpenSearch client: the Go API
      (`backend_client.go`, `OPENSEARCH_URL`), `vector-router` (writes indices),
      OpenSearch Dashboards, `scripts/bootstrap-opensearch.sh`, backup/snapshot
      tooling (`docs/runbooks/backup-restore.md` — daily `netops-daily`
      snapshots), and any operator tooling.
- [ ] The role model drafted: which principal may read/write which index
      patterns, aligned with the existing per-tenant index + `osTenantFilter`
      design.
- [ ] A full snapshot taken and **verified restorable** before starting.
- [ ] Cluster health green.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **WILL drop telemetry** | `vector-router` writes logs and flows to OpenSearch. The moment security is on and Vector is not yet authenticated, indexing fails. Vector buffers, then drops. Sequence Vector's credentials *before* enabling enforcement. |
| 🔴 **WILL lock operators out** | Dashboards and any direct query tooling lose access instantly. Have a break-glass admin credential ready *and tested* before enabling. |
| 🔴 **Security-plugin bootstrap is invasive** | It initializes a security index and can require a cluster restart. HLD §9 phase 4 rates this the most invasive datastore change. On a single node there is no rolling option. |
| 🔴 **Snapshot/restore interacts with security** | Snapshot repositories and the security index itself have special handling. A restore performed later without accounting for security config can wipe or resurrect roles. Prove restore *before* and *after*. |
| 🔴 **Tenant isolation must be re-proven under the new auth** | HLD §9 phase 4 is explicit. Per-tenant indices + filters are the isolation mechanism; new roles must not widen it. Re-run the isolation tests, do not assume. |
| 🟠 **Dotted-field gotcha is unrelated but adjacent** | Root `CLAUDE.md` documents that dotted keys silently broke *all* app-log indexing once. If indexing breaks during this migration, distinguish an auth failure from a mapping failure before escalating. |
| 🟠 **Certificate hostname/SAN mismatches** | The client side refuses to skip verification by construction (`tlsconfig`), so a SAN mismatch is a hard failure, not a warning. |
| ⚪ **Reversible until anonymous access is removed** | The plugin can be disabled again by reverting compose and restarting — at the cost of another restart and a window of exposure. |

## 4. Pre-validation

1. Full snapshot + **verified** restore drill (`scripts/restore-drill.sh`
   exists; confirm it covers OpenSearch).
2. Record baseline: index counts and document counts per tenant, ingestion rate,
   cluster health.
3. Confirm every client's ability to present a certificate or credential in a
   scratch environment.
4. Confirm the break-glass admin credential works against a scratch cluster.
5. **[PENDING SEC-008]** Validator run: record violation V4.

## 5. Procedure *(all steps **[PENDING SEC-008/009]**)*

1. **Stage certificates**: server cert for the node (HTTP + transport layers),
   admin certificate for bootstrapping, client certificates for consumers.
2. **Enable TLS on the transport layer first** (node-to-node), then the HTTP
   layer. Restart. Verify the cluster forms and health returns green.
3. **Enable the security plugin** (remove `DISABLE_SECURITY_PLUGIN`) with the
   security index initialized from a reviewed configuration: internal users,
   roles, role mappings.
4. **Define roles** matching the per-tenant index model — least privilege per
   principal; no role that can read across tenants except the platform/admin
   role, which must be explicitly named and audited.
5. **Migrate clients one at a time**, verifying each: the Go API
   (`OPENSEARCH_URL` → `https://`, plus `TLS_BACKEND_*` per
   `docs/runbooks/tls-mtls.md`), then `vector-router`, then Dashboards, then
   snapshot tooling, then `scripts/bootstrap-opensearch.sh`.
6. **Remove anonymous access** and any permissive default role.
7. Re-run the tenant-isolation tests against the live cluster.
8. Update the transport-policy rows and close the migration exception
   **[PENDING SEC-001]**.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–2 | Revert TLS settings; restart. No data implications. |
| 3–4 | Disable the security plugin; restart. ⚠ The security index remains — a later re-enable inherits it, so record its state. |
| 5 | Revert the individual client to plaintext/anonymous (still available until step 6). |
| 6 | Re-enable anonymous access; restart. Recoverable, but it re-opens the CRITICAL exposure — treat as an emergency measure with a time limit. |
| Data corruption | Restore from the pre-migration snapshot (this is why step 0 is a *verified* restore, not just a snapshot). |

## 7. Audit evidence to capture

- The role and role-mapping configuration as applied, with the reviewer.
- Certificate details for the node and every client.
- Per-client cutover timestamps and verification results.
- Index/document counts per tenant before and after — the no-loss evidence.
- Tenant-isolation test results **run against the live cluster after cutover**.
- Confirmation that anonymous access is gone (a deliberate unauthenticated
  request that is refused, captured).
- Snapshot IDs before and after, and the restore-drill result.

## 8. Post-checks

1. An unauthenticated request to `:9200` is refused (test it).
2. Every client authenticated; ingestion rate at baseline; no index errors.
3. Document counts per tenant reconcile with the baseline.
4. **Negative test:** a principal scoped to tenant A cannot read tenant B's
   indices.
5. Dashboards accessible only through the nginx `auth_request` gate *and* native
   OpenSearch auth (HLD T16 — the gate must be retained, not replaced).
6. Snapshots still run and restore, with security enabled.
7. `scripts/bootstrap-opensearch.sh` still works (it will need credentials —
   confirm it is updated, and that it does not swallow an auth error, per
   `scripts/CLAUDE.md` §16.1).
8. Validator violation V4 clears.
