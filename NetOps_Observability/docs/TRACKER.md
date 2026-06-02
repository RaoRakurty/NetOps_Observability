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
| 19 | **M0 — normalize app-state → Postgres rows + RLS** (pgx, migrations, tx + `SET app.current_tenant`, FORCE RLS, importer) | ✅ **storage layer done** (see below) — follow-ups #31/#32/#33 | Unblocks RLS / per-tenant encryption / tamper-evident audit. SaaS prerequisite (a query bug = multi-customer breach). |
| 20 | **Multi-tenant telemetry isolation** — tenant-tag at Vector ingest + ClickHouse row policies + OpenSearch per-tenant indices/DLS + VM tenants | ⏳ open | Real customer data separation for flows/logs/metrics. Pairs with real-traffic #4/#5. Independent of #19. |

**SaaS ingestion decision to make early (one-way door):** customer-run collector/agent vs. exposed receivers — shapes tenant identity + data model. Design doc TODO.

### ✅ #19 M0 — storage layer landed; what it is and is NOT
**Shipped:** pgx allowlisted + vendored (offline build intact) · `migrations/0001_app_state.sql` (normalized `tenants`/`users`/`api_keys`/`saved_objects`/`snmp_credentials`/`audit_events` with `FORCE ROW LEVEL SECURITY` + fail-closed `app.current_tenant` GUC; global `roles`/`snmp_profiles`; `app_kv` blob fallback for singleton configs) · `db.go` (`pgxpool` + forward-only migrator + `withTenant()`) · `pgstore.go` (`kvBackend` that **explodes** each collection blob into RLS rows on Save / **reassembles** on Load, with a one-time legacy `netops_kv` importer) · `pgstore_test.go` (pure explode/assemble + **live RLS-isolation + importer tests** gated on `DATABASE_URL_TEST`, verified against Postgres 16). Old `pgkv.go` blob backend removed. `build`/`vet`/`test` green; vendored offline build verified.

**Deliberately a bridge, not the destination** (see design review). It gets normalized rows + RLS + tenant isolation with **zero store/API churn**. It does NOT yet give: per-request tenant-scoped reads (RLS is a **backstop** today — the app still loads all tenants into memory as platform-owner `'*'`), partial updates (flush = delete-all+insert-all), pagination, or multi-instance cache coherence. Those are the follow-ups below.

**⚠️ Operational:** `DATABASE_URL` MUST be a non-superuser, non-BYPASSRLS role — superusers bypass RLS even with FORCE, silently disabling isolation (documented in `db.go`).

### 🟡 #33 — `users` converted to a typed per-request-scoped repository
**Shipped:** `usersRepo` interface + `newUsersStore` selector (mirrors `auditRepo`/`newAuditStore`) · `users_pg.go` (`pgUsersStore`) — real per-row SQL, no in-process cache (multi-instance coherent), **`List(tenant,cross)` enforced PER REQUEST by RLS** (`withTenant(tenant)` — RLS stops being a mere backstop on this read path), partial `UPDATE`s instead of rewrite-whole, `FOR UPDATE` read-modify-write. Shared **pure helpers** (`applyUserPatch`/`mergeFederated`/`updateTouchesLastSuperAdmin`/`validatePassword`/`applyCreateDefaults` + sentinel errors) in `users.go` keep the file and pg backends from drifting. Handler filter moved out of `handleUsers` into the repo. `users_pg_test.go` (gated on `DATABASE_URL_TEST`) verified vs **Postgres 16**: scoped-List isolation, platform sees-all, tenant-blind Get, last-super-admin invariant (platform-wide), MAX_USERS cap + federated exemption, password round-trips.

**Scope rule (deliberate):** only `List` is request-tenant-scoped. `Get`/`Count`/mutations run at platform scope `'*'` because **username is the global PK** (login resolves tenant *from* the row before any scope exists) and the **last-super-admin floor is platform-wide**; who-may-mutate-whom stays enforced at the handler/`Authorize()` chokepoint. No `users` migration needed — the existing `tenant_iso` policy already covers it (unlike `saved_objects`, which still needs a `tenant_id='' OR …` shared-visibility variant before its conversion).

**Next per-store:** `api_keys` + `snmp_credentials` are mechanical (same strict policy as users). `saved_objects` needs the shared-policy variant first. `roles`/`snmp_profiles` stay cached (global reference data).

---

## ⏳ Remaining — by workstream

### A. Enterprise tenant-isolation foundation
*See memory `netops-enterprise-tenancy-roadmap`.*

| # | Task | Pri | Status |
|---|------|-----|--------|
| 15 | **Phase 5 — PostgreSQL RLS** (app-state) | High | 🟡 design staged (`docs/design/postgres-rls.md`); **now unblocking via #19** — decision was A(normalize). Lands as #19 wires rows + `withTenant`. |
| 31 | **Cross-backend conformance suite** — shared kvBackend contract run vs file/mem/pgStore so the two backends can't drift silently | High | ✅ done (`kvconformance_test.go`) |
| 32 | **Audit → append/query repository** — `audit_events` now has a real per-row append + time-range + keyset-pagination repository on the pg backend (`audit_pg.go`), **first store using per-request RLS-scoped reads**; file backend keeps the bounded ring. Tenant-id normalized (lower+trim) to match the GUC. | High | ✅ done |
| 33 | **Typed per-domain repositories + per-request tenant-scoped reads** — graduate growing/multi-tenant stores off load-all-cache to tenant-scoped queries. Makes RLS *enforce per request* (not just backstop), enables partial updates + pagination + multi-instance coherence, and shrinks the generic `pgStore` router (never grow it). Bounded config stores (roles/profiles) stay cached by design. **Audit (#32) is the proven template.** ⚠️ NOT mechanical — each store needs its RLS-policy variant chosen. | High | 🟡 **`users` converted** (`users_pg.go`, see below); `api_keys`/`snmp_credentials`/`saved_objects` still on the blob bridge |
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
| 28 | **Dead nav stubs** — re-verified 2026-06-02: `DeviceDetail.tsx` is **orphaned** (no import/route/nav link anywhere) — not reachable in the UI, so it's effectively already hidden; real choice is *build + wire it* vs *delete the dead file* (👤 decision). `SavedDashboards.tsx` is **not** a broken stub — it's an intentional honest "Phase 1 reserves the slot" empty-state, reachable in nav, that points users to Grafana; keep as-is. | Low | per-device metrics + history is the natural #10 drilldown target |
| 29 | **NETCONF honesty** — ✅ **already resolved** (re-verified 2026-06-02). `collectors/netconf.go` is **not** a bare TCP probe: `sshBannerProbe` (poller.go) reads the device's SSH identification banner (RFC 4253, `SSH-` prefix) on :830, so it counts NETCONF/SSH transports *answering*, not just open ports. The UI (`Collectors.tsx`) labels it **"Reachable"** (`reachable/targets`), never "active sessions" — honest. A real per-session count (RFC 6022 `/netconf-state/sessions`) would need an authenticated SSH/YANG client (`x/crypto/ssh`), outside the stdlib budget; not claimed. | Low | done — banner probe + "Reachable" label |
| 34 | **OpenSearch Dashboards 502 — permanent fix** — ✅ **(b)+(c) done.** nginx `/search/` now graceful-degrades: `proxy_intercept_errors` + `error_page 502/503/504 → @osd_down` returns a styled "optional operator tool — start with `--profile osd`" **503** instead of a raw 502 when Dashboards is absent (verified both states; needs a full `docker compose restart nginx`, not just `-s reload`, to take effect on the resolver-phase 502). `scripts/install.py` `compose_up` now starts the stack with `--profile osd` so Dashboards is up by default. Did NOT drop the profile gate (a) — kept optional so it can still be stopped to reclaim ~0.7 GiB. | Med | done 2026-06-02 |
| 35 | **Restrict `/search` (OpenSearch Dashboards) to the platform owner** — ✅ **done.** nginx `auth_request` on `/search/` → internal `/__osd_auth` → Go `handleOSDGate` (`auth.go`), which authenticates from an **httpOnly cookie scoped to `Path=/search`** (`netops_osd`, set at login + refresh, cleared at logout) and 200s ONLY for a global-tenant super-admin (`principalTenant` cross==true); 401/403 → `@osd_denied` page. Cookie `Secure` gated on `SECURE_COOKIES=true` (off until TLS #18). Verified live: unauthenticated → 403, tenant super-admin (`tenant=acme`) → 403, platform owner → 200. Note: per-request subrequest adds a JWT-verify per `/search` asset — fine for occasional admin use. Pairs with #20 (OpenSearch per-tenant DLS) for real tenant-facing search. | High | done 2026-06-02 |
| 36 | **Reports ↔ notifications: contact points + per-report delivery** — design `docs/design/contact-points-and-report-delivery.md` (user chose **contact-points model** + **per-report body\|link delivery**). Today a report's "email" routes to the single global `smtpConfig.To` — no per-report recipients, no groups, no tenant scoping. **Phase 1 ✅ done:** `contactpoints.go` — tenant-scoped reusable audiences (email list/slack/webhook) + CRUD API `/api/notify/contact-points` + `resolveEmailRecipients`; additive routing layer (alert path untouched). **Phase 2 ✅ done:** `reportSpec.ContactPoints` + `DeliveryMode`; scheduler resolves email points in the report's tenant scope and emails directly via `notifyCfg.emailSenderTo` (ungated one-off SMTP); UI — Contact points CRUD card in Notifications admin + recipient picker & delivery-mode select in the report builder; `delivery_mode="link"` recorded as pending without leaking the body (phase 3). **Phase 3 ⏳:** secure-link delivery (signed short-lived report-view endpoint). **Phase 4 ⏳ later:** alerts adopt contact points + routing policies. | High | phase 2 done 2026-06-02 |
| 37 | **Reporting platform restructure — async pipeline (Phase 1 of N)** — user supplied a full enterprise reporting architecture spec; reconciled to the stdlib+pgx budget (decisions: **HTML-first** render via `html/template`, PDF deferred to a headless-Chromium sidecar; **Postgres-backed queue** via `FOR UPDATE SKIP LOCKED`; first increment = async spine + immutable execution history). **Phase 1 ✅ done 2026-06-02:** replaced the synchronous run-in-handler path with schedule → PG queue → stateless worker pool → execution tracking → delivery. New: `reports/` pkg (calendar/TZ `Recurrence`+`NextFire`, `html/template` renderer, model interfaces), `report_jobs_pg.go` (queue: idempotent enqueue, SKIP-LOCKED claim, **lease heartbeat**, backoff+dead-letter, crash recovery), `report_executions_pg.go` (immutable history + **`report_execution_events` phase timeline**), `report_artifacts.go` (`ArtifactStore` iface, app_kv impl), `report_delivery.go` (per-recipient/per-channel `DeliveryStatus`; HTML email via new `Email.SendDocument`; empty Channels = contact-points-only, **no fan-out**), `report_pipeline.go` (enqueue-only scheduler w/ tick jitter + configurable catch-up `REPORT_MAX_CATCHUP_*`, worker pool w/ two-phase RLS scope + per-job timeout). `migrations/0002_report_pipeline.sql` (3 RLS tables). `handleReportRunNow` → **202 + execution_id** (async); new `/api/reports/executions[/{id}[/artifact]]`; `/api/reports/runs` derives from executions under PG; `/metrics` report gauges; correlation-id logging (execution/tenant/schedule/job/worker). File backend keeps the legacy in-process scheduler (honest 409 on `/executions`). Verified e2e against real Postgres + SMTP sink: 202 → queued→running→rendering→delivering→completed timeline, HTML email to contact points, downloadable artifact, durable across restart, weekly America/Chicago next-fire = correct. Review-driven hardening folded in (lease renewal, events table, ArtifactStore abstraction, configurable catch-up, scheduler jitter, two-phase RLS, correlation IDs). **Phase 2+ ⏳:** structured per-kind ViewModel sections, PDF sidecar, guided executive UX (goal cards / audience / NL schedule / preview), `execution_deliveries` table for per-recipient retry, Slack/Teams providers. | High | phase 1 done 2026-06-02 |

---

## Recommended sequencing
1. **#19 M0** ✅ storage layer + #31 conformance landed — RLS is the backstop (#15) under the app-layer chokepoint.
2. **#32 audit repository** — first store off the load-all model (the one that's actively wrong at scale).
3. **#33 typed repositories + per-request scoping** — the SaaS-correctness step (per-request RLS enforcement, partial updates, pagination, multi-instance coherence). Convert `users` first as the template; `pgStore` router shrinks per store, never grows.
4. **#20 telemetry isolation** — independent; Vector `tenant_id` tagging → ClickHouse row policy + OpenSearch DLS.
5. **#17 swtpm** + **#18 TLS** + **#30 cert auto-rotation** as a paired crypto-infra effort.
6. Lab tier (#4/#5/#9) when device config can be coordinated; polish (#28/#29) standalone.

## Subagent usage
- **#17** design doc draft, **#15** RLS test authoring → spin up on demand when that lane starts.
- Lab tasks (#4/#5/#9) are **not** good autonomous-agent targets (need live device config / user scripts).
