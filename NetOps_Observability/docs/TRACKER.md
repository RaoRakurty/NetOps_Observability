# NetOps_Observability — Consolidated Work Tracker

> Branch: `feat/observability-platform` · Last updated: 2026-06-02
> Single source of truth for remaining work. Mirrors the in-session task list
> (#1–#18) and the memory roadmap. Update status here as items land.

Legend: ✅ done · 🔜 next · ⏳ open · 🔬 needs research · 🧪 needs live lab · 👤 user action

---

## ✅ Done (shipped + deployed on this branch)

| # | Item | Commit |
|---|------|--------|
| 1 | Strict tenant isolation (platform-owner-only cross-tenant) | `116eb94` |
| 2 | Infra-stack monitoring → global tenant only (+ Stack Health) | `952e0bc` |
| 3 | Flows source-type selector (NetFlow/IPFIX/sFlow) | `fc1b5ec` |
| 7 | 69 NOC alert rules | `3147014` |
| — | Overview dashboard + WS feeds tenant-scoped | `6d116cc` |
| — | Infrastructure (SNMP creds tenant-scoped, Collectors platform-only) | `78a702c` |

---

## ⏳ Remaining — by workstream

### A. Enterprise tenant-isolation foundation
*The architecture the ad-hoc tenancy fixes should consolidate into. See memory `netops-enterprise-tenancy-roadmap`.*

| # | Task | Pri | Status |
|---|------|-----|--------|
| 11 | **Phase 1 — Authorization core** (`authz.go`) | High | ✅ done `a57e517` |
| 12 | **Phase 2 — Cross-tenant test matrix** | High | ✅ done `c71179e` |
| 13 | **Phase 3 — Audit trail** (`audit.go` + `/api/audit` + UI) | Med | ✅ done `5ef4389` |
| 14 | **Phase 4 — `Tenant.IsolationMode` seam** + `TenantRouter` | Med | ✅ done `a732c43` |
| 15 | **Phase 5 — PostgreSQL RLS** + telemetry isolation | Med | 🟡 **design staged** (`docs/design/postgres-rls.md`) — blocked: blob-kv must be normalized to rows first; needs A(normalize)/B(defer) decision |
| 16 | **Later**: Tenant→Project→Env ownership; per-tenant encryption; ClickHouse `PARTITION BY tenant_id`; workload identities; policy-defined roles (Auditor/API-Client) | Low | ⏳ open |

### B. Security & crypto infrastructure

| # | Task | Pri | Depends on | Delegate? |
|---|------|-----|-----------|-----------|
| 17 | **swtpm secret/cert store**: TPM-sealed KEK + stdlib AES-GCM envelope via sidecar; per-tenant KEKs. Design doc → phased build | Med | — | Subagent: design doc draft |
| 18 | **Full SSL/TLS**: inbound nginx (1.2/1.3, robust client-initiated negotiation, reject <1.2), API→backends TLS, device-facing (gNMI/NETCONF). No SSLv3/1.0/1.1. mTLS out of scope | Med | 17 (certs) | — |

### C. Telemetry / data sourcing (container lab — `10.70.245.120`, rao/rao123)
*Mostly blocked on live lab + device config the agent can't write (user runs device scripts).*

| # | Task | Pri | Notes | Delegate? |
|---|------|-----|-------|-----------|
| 4 | **Real NetFlow/IPFIX/sFlow** from lab subnet | 🧪 Med | sFlow real (11 exporters); NetFlow/IPFIX synthetic — device not in data path | 👤 needs device cfg |
| 5 | **Syslog hostnames + lab test cases**: sources show container IDs (690***), only MARK keepalives | 🧪 Med | validate end-to-end, per-host names | partial subagent |
| 9 | **Real incidents from lab**: correlation healthy but starved | 🧪 Med | depends on #4/#5 real telemetry | — |

### D. Product features

| # | Task | Pri | Notes | Delegate? |
|---|------|-----|-------|-----------|
| 6 | **SNMP profile manager UI**: vendors → OIDs/metrics, upload, 30–50 default metrics/vendor across routers/switches/firewalls/VoIP/APs/printers/IoT | 🔬 Med | big research + CRUD UI | **Subagent: vendor OID research (LAUNCHED)** |
| 8 | **Scheduled reports + SMTP/Twilio**: secure+nonsecure SMTP config UI, Twilio setup, wire Critical→email/text, **per-tenant reports**, multitenancy | Med | senders exist; needs config stores + UI + routing + tenant scoping | — |
| 10 | **Clickable Overview drilldowns**: panels link to detail (e.g. device-down → device detail + reason) | Med | wire each panel to destination | — |

---

## Recommended sequencing
1. **#11 Authorization core** — keystone; unifies #12, #13, the ad-hoc gates, and underpins RLS (#15).
2. **#12 test matrix** right after, to lock the refactor.
3. Parallel track: **#6 vendor research** (subagent, in flight) → SNMP profile manager UI.
4. **#18 TLS** + **#17 swtpm** (crypto infra) as a paired effort.
5. Lab tier (#4/#5/#9) when device config can be coordinated.
6. **#8 reports/notifications**, **#10 clickable overview** as standalone features.

## Subagent usage
- **#6** vendor OID/metric library → background research agent (durable doc, integration-ready).
- **#11** design review, **#12** test authoring, **#15** RLS schema, **#17** design doc → spin up on demand when that lane starts.
- Lab tasks (#4/#5/#9) are **not** good autonomous-agent targets (need live device config / user scripts).
