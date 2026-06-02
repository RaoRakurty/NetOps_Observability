# NetOps_Observability — Consolidated Work Tracker

> Branch: `feat/observability-platform` · Last updated: 2026-06-02
> Single source of truth for remaining work. Reconciled against the git history
> on this branch and the roadmap memories. Update status here as items land.

Legend: ✅ done · 🟡 in progress · 🔜 next · ⏳ open · 🔬 needs research · 🧪 needs live lab · 👤 user action

> **Numbering note:** #1–#20 are the original in-session task IDs. #21+ are
> tracked items that had shipped (or were identified) but were never recorded
> here — added during the 2026-06-02 reconciliation.

---

## ✅ Done (shipped + deployed on this branch)

### Tenancy & isolation
| # | Item | Commit |
|---|------|--------|
| 1 | Strict tenant isolation (platform-owner-only cross-tenant) | `116eb94` |
| 2 | Infra-stack monitoring → global tenant only (+ Stack Health) | `952e0bc` |
| 11 | Phase 1 — Authorization core (`authz.go`, single policy chokepoint) | `a57e517` |
| 12 | Phase 2 — Cross-tenant isolation test matrix | `c71179e` |
| 13 | Phase 3 — Audit trail (`audit.go` + `/api/audit` + UI) | `5ef4389` |
| 14 | Phase 4 — `Tenant.IsolationMode` seam + `TenantRouter` | `a732c43` |
| 26 | Tenants admin (renameable global tenant, view-scope catalog, TopBar tenant chip, `handleMe` enrich) | `dd904f0` |
| — | Overview tiles + WS feeds scoped to caller's tenant | `6d116cc` |
| — | Infrastructure (SNMP credentials + Collectors) scoped | `78a702c` |

### Identity / SSO / access
| # | Item | Commit |
|---|------|--------|
| 22 | **SSO configurable from admin UI** — OIDC (live-tested), LDAP (real stdlib BER/ASN.1 simple-bind, `ldap.go`), TACACS+ (PAP+MD5, `tacacs.go`), SAML SP/IdP-init + RelayState allowlist | `2212e5a` + tests `c7064d6` / `36f2773` |
| 23 | **API tokens** — RFC 7591 OAuth client metadata (grant_types, client_uri, contacts, source-CIDR allowlist, client/secret expiry) + scopes + per-min rate-limit + revoke | `3db3a43` |
| — | Runtime-configurable token policy (access/refresh TTL) | `061c736` |
| — | Required-field asterisk + legend on config forms | `5255b58` |
| — | Drop backend vendor/module names from user-facing UI | `2d279a3` |

### Telemetry / collectors / flows / alerting
| # | Item | Commit |
|---|------|--------|
| 3 | Flows source-type filter (NetFlow/IPFIX/sFlow) on Explore→Flows | `fc1b5ec` |
| 6 | **SNMP profile manager** — vendor OID/metric library + Datadog-style UI + catalog loader (173 profiles / 6,436 OIDs) | `93c9c12` / `8104395` / `fd571c1` |
| 7 | 69 NOC alert rules (availability/errors/saturation/env/routing/capacity/SLA/security/self-health) | `3147014` |
| 24 | Collectors v2c/v3 split + gNMI/NETCONF session counters + device discovery-source attribution | `dd904f0` |
| — | SNMPv3 USM engine (stdlib) + per-device v3 polling | `9a362cc` |
| — | gnmic sidecar streaming telemetry → VictoriaMetrics | `9ceb889` |
| — | Expanded SNMP + gNMI metric coverage | `8f4db1e` |

### Product features
| # | Item | Commit |
|---|------|--------|
| 8 | **Scheduled reports + notifications** — UI-configurable SMTP/Twilio/ntfy, critical→email/text routing, per-tenant reports, exec report types | `341b9f5` (+ exec reports `dd904f0`) |
| 10 | **Clickable Overview drilldowns** — panel items link to detail pages | `b215ba7` / `940d595` |
| 25 | Copilot enablement (Claude provider picker, gated on `FEATURE_COPILOT`) | `dd904f0` |

### Ops / reliability / governance
| # | Item | Commit |
|---|------|--------|
| 21 | Run-for-days hardening — per-service `mem_limits` + healthchecks | `9edb09e` |
| 27 | OpenSearch ISM retention policy (auto-delete old log/flow indices) | `417244e` |
| — | Bound container logs (50m×3) + quiet syslog-ng (stop disk fill) | `65e3b6e` |
| — | Loosen stdlib-only rule → zero-trust dependency allowlist (pgx+sqlc) | `595a03a` |
| — | Phase 5 RLS design doc + blocker writeup (`docs/design/postgres-rls.md`) | `1df5e64` |
| — | Guardrail compliance report; clean new-code lint/gosec | `55434c7` |

---

## ⭐ Foundation — do FIRST (serves both the lab run AND SaaS)
*These harden the single deployment and are literally the first SaaS steps — no wasted motion. Sequence ahead of new features.*

| # | Task | Status | Why |
|---|------|--------|-----|
| 19 | **M0 — normalize app-state → Postgres rows + RLS** (pgx+sqlc, migrations, tx + `SET app.current_tenant`, FORCE RLS, importer, backups) | 🟡 **in progress** (see below) | Unblocks RLS / per-tenant encryption / tamper-evident audit. SaaS prerequisite (a query bug = multi-customer breach). |
| 20 | **Multi-tenant telemetry isolation** — tenant-tag at Vector ingest + ClickHouse row policies + OpenSearch per-tenant indices/DLS + VM tenants | ⏳ open | Real customer data separation for flows/logs/metrics. Pairs with real-traffic #4/#5. Independent of #19. |

**SaaS ingestion decision to make early (one-way door):** customer-run collector/agent vs. exposed receivers — shapes tenant identity + data model. Design doc TODO.

### 🟡 #19 M0 — current state of the working tree (uncommitted)
**Laid down:** pgx allowlisted + vendored (`go.mod`/`go.sum`/`vendor/`, offline build intact) · Dockerfile `golang:1.22→1.24-alpine` · `migrations/0001_app_state.sql` (normalized `tenants`/`users`/`api_keys`/`saved_objects`/`snmp_credentials`/`audit_events` with `FORCE ROW LEVEL SECURITY` + fail-closed `app.current_tenant` GUC; global `roles`/`snmp_profiles` unscoped) · `db.go` (`pgxpool` + in-house forward-only migrator + `withTenant()`). `build`/`vet`/`test` all green.
**Not done yet:** `db.go` is a standalone foundation — **nothing calls `newPgDB`/`withTenant`**; the 16 stores still run the old blob-kv path (`kvstore.go`→`pgkv.go`). Two Postgres backends now coexist. Remaining: row-level store seam replacing blob `kvLoad`/`kvSave`, blob→rows one-time importer, backups, migrator + RLS-isolation tests (skip-without-DB).

---

## ⏳ Remaining — by workstream

### A. Enterprise tenant-isolation foundation
*See memory `netops-enterprise-tenancy-roadmap`.*

| # | Task | Pri | Status |
|---|------|-----|--------|
| 15 | **Phase 5 — PostgreSQL RLS** (app-state) | High | 🟡 design staged (`docs/design/postgres-rls.md`); **now unblocking via #19** — decision was A(normalize). Lands as #19 wires rows + `withTenant`. |
| 16 | **Later**: Tenant→Project→Env ownership; per-tenant encryption; ClickHouse `PARTITION BY tenant_id`; workload identities; policy-defined roles (Auditor/API-Client) | Low | ⏳ open |

### B. Security & crypto infrastructure

| # | Task | Pri | Depends on | Delegate? |
|---|------|-----|-----------|-----------|
| 17 | **swtpm secret/cert store**: TPM-sealed KEK + stdlib AES-GCM envelope via sidecar; per-tenant KEKs. Design doc → phased build | Med | — | Subagent: design doc draft |
| 18 | **Full SSL/TLS**: inbound nginx (1.2/1.3, robust client-initiated negotiation, reject <1.2), API→backends TLS, device-facing (gNMI/NETCONF). No SSLv3/1.0/1.1. mTLS out of scope | Med | 17 (certs) | — |
| 30 | **SAML cert auto-rotation scheduler** — publish ahead of `NotAfter` (current scaffold publishes old+new but has no ahead-of-expiry timer). Remainder of #22. | Med | 17 | — |

### C. Telemetry / data sourcing (container lab — `10.70.245.120`, rao/rao123)
*Mostly blocked on live lab + device config the agent can't write (user runs device scripts).*

| # | Task | Pri | Notes | Delegate? |
|---|------|-----|-------|-----------|
| 4 | **Real NetFlow/IPFIX/sFlow** from lab subnet | 🧪 Med | sFlow real (11 exporters); NetFlow/IPFIX synthetic — device not in data path | 👤 needs device cfg |
| 5 | **Syslog hostnames + lab test cases**: sources show container IDs (690***), only MARK keepalives | 🧪 Med | validate end-to-end, per-host names | partial subagent |
| 9 | **Real incidents from lab**: correlation healthy but starved | 🧪 Med | depends on #4/#5 real telemetry | — |

### D. Product polish / decisions

| # | Task | Pri | Notes |
|---|------|-----|-------|
| 28 | **Dead nav stubs** — `DeviceDetail.tsx` is "Coming soon"; decide build vs hide. (`SavedDashboards` previously a stub — re-verify.) | Low | per-device metrics + history is the natural #10 drilldown target |
| 29 | **NETCONF honesty** — `collectors/netconf.go` is a TCP/830 reachability probe, not a real NETCONF session. Either build a real SSH/YANG session or relabel the counter honestly. | Low | stdlib-only makes a real client large |

---

## Recommended sequencing
1. **#19 M0** (in progress) — wire `db.go` into the store seam, importer, RLS tests. Lands #15 as the backstop.
2. **#20 telemetry isolation** — independent of #19; Vector `tenant_id` tagging → ClickHouse row policy + OpenSearch DLS.
3. **#17 swtpm** + **#18 TLS** + **#30 cert auto-rotation** as a paired crypto-infra effort.
4. Lab tier (#4/#5/#9) when device config can be coordinated (user runs scripts).
5. Polish (#28/#29) as standalone cleanups.

## Subagent usage
- **#17** design doc draft, **#15** RLS test authoring → spin up on demand when that lane starts.
- Lab tasks (#4/#5/#9) are **not** good autonomous-agent targets (need live device config / user scripts).
