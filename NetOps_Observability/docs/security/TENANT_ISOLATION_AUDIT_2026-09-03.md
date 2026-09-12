# Tenant-Isolation Audit — 2026-09-03

**Scope:** every surface built on 2026-09-03, i.e. the 25 commits `5b0be333..a207fbdc`
(Iris skills/chaining/parsers/state battery/memory/BGP tools · protocol-diagnostics live
collect · igpmon · VRF interfaces · BGP depth/BMP/bgpwatch alerting/bogons/classes/peers ·
security lane/findings/config capture/hardening · alertwebhook · compliance frameworks).

**Standard:** `CLAUDE.md` §3a rules 1–5. A comment claiming isolation was treated as a
claim, never as evidence; every verdict below is traced to a code path (file:line) or to a
live HTTP transcript.

**Method:** three layers — (A) structural, over the whole diff; (B) behavioural, against
the running stack with a second real tenant; (C) platform-scope surfaces.

**Headline:** **no cross-tenant data leak was found between two tenants.** 230+ live
requests as a scoped foreign principal returned zero bytes of the lab tenant's data.
Four gaps were found, one of them **CRITICAL and live in production at the time of the
audit** — on the *platform-global* path, not the tenant API: customer device identity was
being delivered to the operator's phone. That one is **fixed**. Three remaining gaps are
in files owned by concurrently-running agents and are **handed off** below.

---

## 1. Result summary

| Verdict | Count | |
|---|---|---|
| PASS (structural + behavioural) | 61 surfaces | |
| GAP-CRITICAL | 1 | **fixed in this pass** |
| GAP-MEDIUM | 5 | 1 fixed, 3 handed off, 1 owner decision |
| GAP-LOW | 9 | 2 fixed, 7 recorded |

No route added today is unclassified (`TestEveryRouteClassified` passes), every `scoped`
route is covered (`TestEveryScopedRouteHasIsolationCoverage` passes), and none of today's
routes needed a `isolationCoverageBaseline` exemption.

---

## 2. Layer A — structural

### 2.1 Routes added since `5b0be333`

All 17 new routes are in `routeIsolationLedger` (`src/backend/route_isolation_test.go`).

| Route | Ledger class | Gate | Tenant applied at |
|---|---|---|---|
| `/api/bgp/rpki` | scoped | `requirePerm(infrastructure, read)` `bgp_ops.go:761` | watchlist read `:784` |
| `/api/bgp/feed` | scoped | same `bgp_ops.go:992` | cross/empty refused `:1010`; ring keyed by tenant |
| `/api/bgp/alerts` | scoped | `bgpWatchAuthz` `bgp_alerts.go:141` | `internal/bgpwatch/http.go:132` `scoped()` |
| `/api/bgp/alerts/config` | scoped | same, `write` on PUT `bgp_alerts.go:132` | owner from `p.Subject` `http.go:338` |
| `/api/bgp/bogons` | scoped | same | `Sightings(tenant, …)` `http.go:377` |
| `/api/bgp/bmp/{sessions,updates,stats}` | scoped | `bmpAuthz` `bmp_deps.go:66` | `(p.Tenant, p.Cross)` on every store read |
| `/api/bgp/{aspa,geofeed,aspath-graph}` | globalRef | `requirePerm(infrastructure, read)` | public internet facts; graph **marks only** |
| `/api/protocols/{ospf,isis}/{adjacencies,summary,health}` | scoped | `requirePerm(infrastructure, read)` `igpmon_deps.go:70` | CH `chTenantScope`; VM `extra_filters[]` |
| `/api/devices/{id}/interfaces/by-vrf` | scoped | `requirePerm(infrastructure, read)` `ifgroup_deps.go:64` | device 404 `internal/ifgroup/http.go:191`; VM filters |
| `/api/internal/vmalert/` | token | shared secret, `subtle.ConstantTimeCompare` `internal/alertwebhook/alertwebhook.go:345` | **platform-global; carries no tenant data** — see §4.1 |

No tenant-data route sits behind a platform gate. No platform-global config sits behind a
scope-blind `requireAdmin` — every one of the 15 notify-channel routes changed today goes
through `handleChannelConfig`, which gates on `requirePlatformAdmin` (`notify_config.go:414`),
and this was **confirmed behaviourally** in §3.4: a tenant org-admin holding
`administration:admin` is refused all of them.

### 2.2 Stores added

| Store | Isolation mechanism | Evidence |
|---|---|---|
| migration `0040_iris_investigations` | `ENABLE` + **`FORCE ROW LEVEL SECURITY`** + `tenant_iso` policy, PK `(tenant_id, id)`, all indexes tenant-leading | `internal/platformdb/migrations/0040_iris_investigations.sql:72-79` |
| — its Go store | `WithTenant` on **every** query; write hard-wires `cross=false` | `ai/investigation_memory.go:455`, `:489` |
| migration `0041_bgp_alert_policy` | same `tenant_iso` FORCE-RLS shape as the `0035` template | `internal/platformdb/migrations/0041_bgp_alert_policy.sql:28-35` |
| — its Go store (PG) | `WithTenant(ctx, t, false, …)` — cross never `'*'` even for an owner | `internal/bgpwatch/state.go:271`, `:306` |
| — file build | `map[string]TenantPolicy` keyed by tenant, no "list all" | `internal/bgpwatch/state.go:147` |
| Iris memory file store | tenant is the map KEY *and* the read predicate; `!q.HasKey() → nil` (no unscoped list) | `ai/investigation_memory.go:291`, `:392`, `:400` |
| Iris pending buffer | keyed `(tenant, sub)` from the token; TTL 30 m, 8/principal, 512 principals | `ai/investigation_pending.go:99`, `:31-35` |
| BMP session store | **every** read takes `(tenant, cross)`; `scopeAdmits` default-closed; no unscoped method exists | `internal/bmp/store.go:502-510`, `:560`, `:677`, `:783` |
| bgpwatch evaluator state | `map[string]*tenantState`; every read opens with `concreteTenant` (refuses `""`/`"*"`) | `internal/bgpwatch/evaluate.go:197`, `helpers.go:24` |
| bgpdepth feed ring | `map[string]*ring` keyed by tenant, fixed 2000/tenant | `internal/bgpdepth/feed.go:158` |
| bogon sightings | per-tenant submap; eviction stays **within** the tenant | `internal/bgpwatch/bogon.go:383`, `:414` |
| `secapi` rule state | PG FORCE-RLS (0037) + file tenant map; owner = `p.Tenant`, twice, never the body | `secapi/http.go:968` |

### 2.3 Iris tools (§3a rules 1–2)

The `ai` package holds **no store and no token**. Every tool calls an injected closure
built per request in `s.aiTroubleshootDeps(r, claims)` (`ai_handlers.go:157`), and every
closure **discards the `ai.Principal` it is handed** (`func(ctx, _ ai.Principal, …)`) and
derives scope from the captured JWT claims instead — `principalTenant(claims)` /
`aiLookupDevice(claims, …)` at `ai_troubleshoot_deps.go:154, 173, 205, 225, 249, 342, 402,
558, 641, 1391, 1435, 1482`.

- **No `tenant` argument exists in any tool schema** (`ai/toolspec.go:154-236`).
- The model **cannot request a tool or an argument** — gather steps come from
  server-owned `SKILL.md` files, bound only from the closed entity set
  `{correlation_id, device_id, device, seam, peer, prefix}` (`ai/skill.go:124-131`); the
  model's only choice is a skill *name* from a closed list, and an out-of-list name is
  refused and audited (`ai/skill_chain.go:450`).
- Entities are resolved **once, server-side, before any skill runs**
  (`ai/skill_run.go:246`), and a later hop cannot rebind.
- Every device/case id is **re-resolved** at the tool boundary; cross-tenant is
  `ai.ErrNotFound`, never `ErrForbidden` (`ai/tools.go:11-13`). `ErrForbidden` is used
  only for RBAC denial on tenant-agnostic capability, so it leaks no existence.

### 2.4 Storage-engine scoping

- **ClickHouse** — igpmon has exactly one CH call site (`internal/igpmon/events.go:172`),
  always with `chTenantScope`; an empty tenant short-circuits **before the DB is touched**
  (`events.go:169`). Row policies on `corr_signals` / `corr_signals_archive` are strict
  (`deployment/docker/clickhouse/init.sql:846`, `:858`).
- **VictoriaMetrics** — all eight reads in igpmon + ifgroup take `extra_filters` from
  `metricFilters`. A scoped principal with no device boundary is **REFUSED**
  (`internal/igpmon/live.go:83`, `internal/ifgroup/http.go:201` → 403), not served the
  fleet. This is the distinction that matters and it is the correct side of it.
- **OpenSearch** — all seven queries in `secapi` (list, get, facets, current-fold, trend,
  coverage, and the new `list.go` AI path) route through one `scope()` helper that returns
  `oslog.TenantIndexPattern` + `oslog.TenantFilter` (`secapi/http.go:131`). No handler
  hand-builds an index pattern. **No unfiltered aggregate exists.**
- **Bus** — bgpwatch stamps `TenantID` from the tenant-repo loop variable, re-validated by
  `concreteTenant` inside the event builder (`internal/bgpwatch/evidence.go:162`, `:236`);
  nothing derived from RIPEstat or BMP payloads reaches it.

### 2.5 BMP connect-time attribution (§3a rule 2)

Tenant is stamped once, at CONNECT, from the inventory device the **source address**
resolves to (`internal/bmp/listener.go:178`). An unresolvable source closes the socket
(`:179-185`); `Open` refuses a blank tenant as a second line (`store.go:196`). Nothing on
the wire — router BGP ID, peer distinguisher, sysName TLV — can influence attribution;
those land only in display fields. Verified.

---

## 3. Layer B — behavioural, on the live stack

**Setup.** Tenant `audit-b` (`t_a6d18170ba2571d616d6560374fec78f`) created via API, with two
**real scoped principals** (not an admin narrowing):

- `auditb-op` — role `operator`, JWT `{"tenant":"t_a6d1…"}`, no cross grant
- `auditb-adm` — role `org-admin` (holds `administration:admin`), same tenant

Lab objects targeted: devices `spine1`/`spine2`, finding
`f7e29354…c180e4`, config version `22fe79d2…0d68bb`, correlation
`f4c03f0c-878a-56a6-a21b-77c0af91256a`.

Leak detector on every response body: `spine1`, `spine2`, `t_d3d501aa…`, `172.40.40.`,
the finding id, the config sha, the correlation id.

### 3.1 Reads — 44 surfaces × 2 principals

| Surface group | Request | Status | Body leak | Verdict |
|---|---|---|---|---|
| `GET /api/devices` | list | 200 | `[]` | PASS |
| `GET /api/devices/spine1` | cross-tenant get | **404** (`404 page not found`) | none | PASS |
| `GET /api/devices/spine1/interfaces/by-vrf` | cross-tenant | **404**, byte-identical to absent | none | PASS |
| `GET /api/devices/spine1/config/{versions,versions/{sha},diff,status}` | cross-tenant | **404** `{"error":"not found"}` | none | PASS |
| `GET /api/devices/spine1/pcap` | cross-tenant | **404** | none | PASS |
| `GET /api/security/findings?limit=5` | list | 200 `{"items":[],"total":0}` | none | PASS |
| `GET /api/security/findings/{lab id}` | cross-tenant get | **404** `finding not found` | none | PASS |
| `GET /api/security/findings/{facets,trend}` | aggregates | 200, all-zero | none | PASS |
| `GET /api/security/{posture,exposure-stories,views}` | | 200, empty | none | PASS |
| `GET /api/security/rules` | catalog + own state | 200 (catalog is global by design) | none | PASS |
| `GET /api/config/drift` | | 200 `{"items":[],"total":0}` | none | PASS |
| `GET /api/bgp/{alerts,alerts/config,bogons,rpki,feed}` | | 200, own-tenant empty | none | PASS |
| `GET /api/bgp/bmp/{sessions,updates,stats}` | | 200, `count:0` | none | PASS |
| `GET /api/bgp/{aspa,geofeed,aspath-graph}` | globalRef | 200, public facts | none | PASS |
| `GET /api/protocols/{ospf,isis}/{adjacencies,health}?device=spine1` | cross-tenant | **404** | none | PASS |
| `GET /api/protocols/{ospf,isis}/summary` | fleet roll-up | 200 `devices:[]` | none | PASS |
| `GET /api/correlations?limit=5` | | 200 `{"data":[]}` | none | PASS |
| `GET /api/correlations/{lab id}` | cross-tenant get | **404** | none | PASS |
| `GET /api/alerts` | | 200 `[]` | none | PASS |

**Existence-oracle check (the important one).** As the lab-owning admin the same requests
return real data — `isis/health?device=spine1` → `adjacencies_up: 4`,
`interfaces/by-vrf` → full VPRN grouping, `collect` on `spine1` → `503 collector not
configured`. As admin, a *nonexistent* device returns `404 page not found`. As `audit-b`,
`spine1` returns **the same bytes** as a nonexistent device. The 404 is a real tenant
refusal and reveals nothing. **PASS.**

### 3.2 `as_tenant` / `X-Acting-Tenant` escalation — 48 attempts

`?as_tenant=lab`, `?as_tenant=t_d3d501aa…`, `X-Acting-Tenant: {lab, <id>, global, all}`
against `/api/devices`, findings, posture, facets, config/drift, correlations,
`bgp/bmp/updates`, `bgp/alerts`, `protocols/*/summary`, alerts, exposure-stories — as both
principals.

**Result: every one ignored, fail-closed. 200 with own-tenant (empty) data, zero leak
markers.** The mechanism is `withActingTenant` (`tenancy.go:112-140`): a non-owner's
selection is honoured only if `reachesTenant`, and `principalTenant` ignores
`ActingTenant` for a non-owner as a hard invariant. **PASS.**

### 3.3 Writes and actions

| Surface | Request | Result | Verdict |
|---|---|---|---|
| `POST /api/devices` with `"tenant_id":"<lab>"` in the body | both principals | **201, stamped `tenant_id: t_a6d1…`** (own tenant) | PASS — §3a.2 |
| `POST /api/security/scan` | tenant admin | `202 {"tenant_seg":"t_a6d1…"}` | PASS |
| `POST /api/security/scan?as_tenant=lab` | tenant admin | `202 {"tenant_seg":"t_a6d1…"}` — **narrowing refused** | PASS |
| `PUT /api/security/rules` | operator | `403 administration write permission required` | PASS |
| `PUT /api/notify/itsm?tenant=lab` (and `?tenant=<lab id>`) | tenant admin | 200, but **wrote only audit-b's record**; lab's config unchanged (verified by re-reading both) | PASS |
| `POST /api/troubleshoot/protocol-diagnostics/collect {"device_id":"spine1"}` | both | **404**, identical to an absent device | PASS |
| `POST /api/devices/spine1/pcap` | both | 404/405 (module off); never reached the device | PASS |
| `POST /api/bgp/watchlist` | both | `503 requires the relational store` (file build) | N/A on this deployment |

### 3.4 Platform-global config — the §3a.3 privilege-gate check

The point of this block: a **tenant** org-admin holds full `administration:admin`, so a
scope-blind `requireAdmin` on platform-global config is a privilege leak. Result for
`auditb-adm`:

| Route | Result |
|---|---|
| `/api/notify/{ntfy,slack,smtp,pagerduty,teams,sns,twilio}` | **403 platform administrator required** ✅ |
| `/api/auth/token-policy` | 403 ✅ |
| `/api/auth/sso/idp` | 403 ✅ |
| `/api/auth/{ldap,tacacs}/config` | 403 ✅ |
| `/api/ai/tenants` (provider/LLM keys) | 403 ✅ |
| `/api/security-settings` | 403 ✅ |
| `/api/collectors`, `/api/stack/health` | 403 ✅ |
| `/api/notify/itsm` | 200 — but the record is **per-tenant** (`itsmKey(tenant)`, `itsm_config.go:167`) and `?tenant=` is honoured only for a `cross` principal. Correct class; the `main.go:1947` comment `// (platform-owner)` is **stale and misleading**. LOW, doc-only. |
| `/api/{tenants,orgs,users,bindings,audit}` | 200, **filtered to audit-b only** — lab's tenant, users, bindings and audit rows absent ✅ |

### 3.5 Iris (`POST /api/ai/ask`)

| Probe (as `auditb-op`) | Answer | Verdict |
|---|---|---|
| "Why is BGP down on **spine1**?" | `"No evidence was returned for this scope… no device, peer, prefix or case id was in scope"` — and the disclosure `"no device in this tenant's inventory matches the name in the question — say so; do not assume the device exists"` | PASS |
| *same question as the lab admin* | gathers real evidence naming spine1 — the contrast proves the tool chain works and was scoped, not merely empty | PASS |
| `context.correlation_id` = **real lab uuid** | `Problem "…" isn't available in your scope.` | PASS |
| `context.correlation_id` = **fabricated uuid** | **byte-identical answer** → no existence oracle | PASS |
| `context` = `{correlation_id: <lab>, tenant: <lab>, tenant_id: <lab>, as_tenant: "lab", device: "spine1"}` | identical refusal — client context cannot widen scope | PASS |
| "recall what we investigated on spine1" / memory recall | no memory returned; `"prior investigations are CONTEXT, not current state"` | PASS |
| "list every device in tenant lab" | capability fallback, no data | PASS |

One apparent leak was chased to ground and cleared: an Iris answer to `audit-b` cited
incident `P-7B32F8`. That correlation (`7b32f8ef-…`) is about `leak-probe` — the device the
**auditor had just created inside audit-b**. It is audit-b's own incident, correctly scoped;
`/api/correlations` for audit-b returned exactly that one row and none of lab's. This is a
positive proof that the correlation engine attributes a new device's incidents to the
creating tenant.

---

## 4. Layer C — platform-scope surfaces

### 4.1 `/api/internal/vmalert/` (alertwebhook)

- **Auth**: shared secret, Bearer **or** Basic, both compared with
  `subtle.ConstantTimeCompare` and **both always evaluated** (`alertwebhook.go:345-347`);
  auth runs before the path check and before any body read.
- **JWT-exempt** at `auth.go:889`; the route is registered **only** when
  `VMALERT_WEBHOOK_TOKEN` is set (`main.go:1041`) — fail-closed.
- **Bounded**: `MaxBytesReader` 1 MiB (`:352`), ≤500 alerts/request, hard-capped dedup store.
  Correctly noted that the JWT-exempt prefix bypasses `requestBodyLimit`, so this is the
  only cap.
- **Live proof of the tenant refusal**: a crafted Alertmanager-v2 payload with
  `labels.tenant = <lab tenant id>`, posted over mTLS with the vmalert SVID, was
  **DROPPED** — `{"msg":"vmalert alert dropped: tenant-scoped label on a platform-global
  path","label":"tenant"}` and `netops_alert_webhook_dropped_tenant_total 1`. **PASS.**

**But** — see GAP-1. The refusal did not cover the case that was actually occurring.

### 4.2 Host-monitoring push route

No tenant principal can inject: the only producer of a host job is `pushHost`, reachable
only through the shared-secret-authenticated handler. Queue bounded and non-blocking, topic
never logged, metric label set closed (`route` constant, `tier` ∈ {page,warning,resolved}).
**PASS on injection**; the data it was carrying is GAP-1.

---

## 5. Gaps

### GAP-1 — **CRITICAL — customer device identity on the platform-global operator channels** — FIXED

**Surface:** `internal/alertwebhook/alertwebhook.go` (commit `d4052426`, today).

**What was wrong.** The new layer normalization stamped `layer = "platform"` on **every**
alert whose layer was not already a platform layer:

```go
if orig := labels["layer"]; !notify.PlatformLayers[orig] {
        if orig != "" { labels["rule_layer"] = orig }
        labels["layer"] = "platform"      // unconditional
}
```

That directly inverts the #103 guard, whose contract is stated at
`notify/platform_scope.go:24-27`: *"Customer alerts carry no layer label (or a non-platform
one) and are dropped here by default-closed matching."* `PlatformScopeFilter` wraps the
global PagerDuty routing key and platform-scoped SNS; `pushHost` runs unconditionally on
every dispatched alert and puts the annotation summary on the operator's ntfy phone topic.

The code's own justification — *"everything vmalert can emit is platform self-health by
construction"* — is false. Measured: **126 of the 130 rules in `src/config/rules.yaml`
carry no `layer` label at all**, and they are the `noc-availability` / `noc-errors` /
`noc-saturation` / `noc-environmental` / `noc-routing` / `noc-capacity` / `noc-security`
groups — per-device customer telemetry whose annotations interpolate `{{ $labels.device }}`.

**This was live at audit time.** From the stack's own logs and vmalert's `/api/v1/alerts`:

```
{"alertname":"DeviceUnreachable","msg":"platform alert pushed to host monitoring",
 "route":"host_monitoring","tier":"warning","ts":"2026-09-03T03:32:08Z"}

DeviceUnreachable -> {"alertgroup":"noc-availability","device":"spine1",
                      "collector":"snmpv2c","severity":"critical"}   # no layer
```

A tenant's router hostname was being delivered to a channel that is not principal-scoped
and cannot be. §3a rule 1.

Secondary holes in the same function: the tenant refusal was a **three-name, case-sensitive
denylist** (`tenant`, `tenant_id`, `org`) over `labels` only — `org_id`, `tenant_name`,
`customer`, `Tenant`, and anything in `annotations` (which is copied verbatim onto the
phone by `summaryOf`/`descriptionOf`) all passed.

**Fix applied** (`internal/alertwebhook/alertwebhook.go`, `metrics.go`, new
`tenant_isolation_test.go`):

1. `tenantLabels` widened to 13 spellings and matched **case-insensitively**, over
   annotation keys as well as label keys (`foldKeys`).
2. New `customerIdentityLabels` refusal — `device`, `device_id`, `device_name`, `hostname`,
   `interface`, `ifname`, `if_name`, `peer`, `neighbor`, `site`, `circuit` — with a new
   `resultDroppedCustomer` outcome and a `netops_alert_webhook_dropped_customer_total`
   counter (§10: no silent drops).
3. The layer normalization is now a **closed allowlist** of the nine layers our own rule
   files stamp, plus the layer-less case. An unrecognised layer is left alone so the
   default-closed `PlatformScopeFilter` keeps rejecting it.

**The discriminator, and why it is the `layer` stamp rather than the label name.** A
name-only refusal was built first and then falsified against the live stack:

```
DeviceUnreachable   device="spine1"                          (no layer)   → customer
DiskHeadroomLow     device="/dev/mapper/ubuntu--vg-…"        layer="host" → platform
HostDiskLow         device="/dev/mapper/ubuntu--vg-…"        layer="host" → platform
```

Both carry `device`; only the first is a customer router. What separates them is that our
own checked-in rule file **authored** the second as host self-health. That stamp is a
server-side assertion (§3a.2 — classification comes from the server, never from the
observed data); the device label *value* is data and is not trusted. So the customer
refusal applies only to alerts carrying no recognised self-health layer.

**Net effect on this deployment** (verified against vmalert's live alert set): `CollectorDown`,
`CollectorAllTargetsUnreachable`, `CollectorPartialReachability`, `NoSamplesIngested`,
`DiskHeadroomLow`, `HostDiskLow`, `HostCPULoadHigh`, `CorrDeadLettersRising`,
`CorrEventsDroppedRising`, `VectorComponentErrors`, `AlertingHeartbeat` — **all still
delivered** (the owner's 2026-09-03 intent in `d4052426` is preserved). `DeviceUnreachable`
— **now dropped and counted**. That is the leak and nothing else.

**Tests shipped** (`internal/alertwebhook/tenant_isolation_test.go`, §3a rule 5):
`TestEveryTenantSpellingIsRefused`, `TestTenantLabelRefusalIsCaseInsensitive`,
`TestTenantIdentityInAnAnnotationIsRefused`,
`TestCustomerDeviceAlertsNeverReachTheGlobalChannels` (four real rules),
`TestTheDiscriminatorIsTheLayerStampNotTheLabelName` (the false-positive regression),
`TestCustomerAlertResolveIsRefusedToo`,
`TestCustomerDeviceAlertNeverReachesTheHostPhoneRoute` (the second destination),
`TestLayerNormalizationOnlyCoversOurOwnSelfHealthLayers`,
`TestPlatformSelfHealthIsUnaffectedByTheRefusals` (live label sets, incl. both
`device="/dev/mapper/…"` cases), `TestTheTwoRefusalVocabulariesDoNotOverlap`.

**Residual, for the owner.** A rule that stamps a self-health `layer` on a device-bearing
alert would still pass. That is the same residual #103 already accepts (the whole scope
model is keyed on the layer stamp), and it is a checked-in, reviewed file. The durable
improvement is to stamp `layer:` explicitly on the platform groups in `rules.yaml` so
classification is asserted at the source rather than inferred from absence — **not done
here**, because re-classifying 154 alert rules is a product decision, not an audit fix.

---

### GAP-2 — **MEDIUM — cross-tenant aggregate counters returned to tenant principals** — HANDED OFF

Three surfaces return **process-wide** counters, aggregated across all tenants, inside a
per-tenant response body. Each is a volume oracle: tenant A learns how much scanning /
alerting / BGP activity the rest of the platform is doing, and how many other tenants exist.

| Surface | Field | Code |
|---|---|---|
| `GET /api/security/lane/status` | `metrics` | `internal/seclane/http.go:38` → `l.metrics.Snapshot()`; `l.metrics` is **one** `*Metrics` on the Lane, summed across every tenant (`internal/seclane/metrics.go:124-136`) |
| `GET /api/bgp/alerts` | `metrics` | `internal/bgpwatch/http.go:206` → process-wide `Metrics().Snapshot()` |
| `GET /api/bgp/feed` | `metrics.rings`, `metrics.pollers_active` | `bgp_ops.go:1042` → `internal/bgpdepth/feed.go:209-219`; `len(rt.rings)` **is the number of other tenants using the feed** |

**Live transcript** (as `auditb-adm`, a tenant admin of a tenant created minutes earlier):

```
GET /api/security/lane/status
  metrics = {"emitted_exposure":20,"emitted_posture":108,"scan_runs_total":4, …}
  tenants = [ audit-b only ]        ← correctly filtered
```

The `tenants` array is scoped; the `metrics` block beside it is not.

**The repo already sets the correct standard** — the sibling module refuses to do this,
in as many words, at `internal/bmp/http.go:170-172`: *"The process-wide counters are
deliberately not exposed here: another tenant's message volume is another tenant's data."*

**Minimal fix:** drop the `metrics` block from all three response bodies (operators already
have them on `/metrics`), or reduce each to the caller's own `Status`/`FeedStatus`.
Ship it with an isolation test asserting the body carries no cross-tenant aggregate.

**Handed off** — `internal/seclane/*`, `internal/bgpwatch/*`, `bgp_ops.go` and
`bgp_alerts.go` are all in the working set of the concurrently-running agents.

---

### GAP-3 — **MEDIUM — a tenantless principal reads platform-owned devices, and two new comments claimed otherwise** — comments FIXED, policy HANDED OFF

`rbac.SameTenantStrict("", "")` is `strings.EqualFold("", "")` → **true**
(`internal/rbac/authz.go:113-115`), so `Authorize` takes the same-tenant branch and a
principal whose token carries **no** tenant matches an **untagged** device.

**Verified live** (objects created and deleted during the audit): an operator account with
no `tenant_id` — claims `{"sub":"auditb-notenant","role":"operator"}`, no `tenant` — read a
platform-owned device through today's new routes:

```
GET /api/devices                                        200  [audit-platform-dev]
GET /api/devices/audit-platform-dev                     200  full record
GET /api/devices/audit-platform-dev/interfaces/by-vrf   200  full VRF grouping
GET /api/protocols/ospf/health?device=audit-platform-dev 200 full health block
GET /api/devices/spine1                                 404  ← lab's device still refused
```

**This is not a cross-tenant leak** — no tenant's device reached another tenant — and it is
pre-existing platform policy, not something today's modules introduced. It is recorded
because the two new modules shipped a comment asserting the opposite:

> *"global/unassigned devices are platform-owned and visible only cross-tenant"*
> — `igpmon_deps.go`, `ifgroup_deps.go`

**Fixed here:** both comments corrected to state what the code actually does, with the live
verification date and a pointer to where a real fix belongs.

**Handed off:** tightening `SameTenantStrict` to refuse a blank principal tenant is the
fail-closed reading of "untagged is platform-owned", but its blast radius is every
tenant-scoped resource in the product. It needs its own change and its own test sweep.

---

### GAP-4 — **MEDIUM — `/api/ai/ask` and the BGP AI tools lack an end-to-end isolation test** — RECORDED

The Iris chain is proven at the **seam and tool** layers (see §2.3) but the only
route-level `/api/ai/ask` isolation test — `ai_datasource_isolation_test.go:72`
`TestAIAskStrictForForeignTenant` — asks *"what is going on right now?"*, a `current_state`
intent that `ai/skill_select.go:23` **excludes from the skills layer**. So no test drives
the Iris/skill path through the router with a foreign device or a foreign correlation id.
The behavioural probes in §3.5 do exactly that and pass, but a transcript is not a
regression test.

Likewise `get_bgp_watchlist` / `get_bgp_rpki` have no two-tenant separation test through
the AI seam: `ai_troubleshoot_deps_test.go:918` only exercises the **unwired-store** branch
and asserts the scope *label*, never that tenant A's watched prefixes are absent from
tenant B's answer.

**Note on the coverage guard itself:** `TestEveryScopedRouteHasIsolationCoverage` proves a
route is *mentioned* in a file containing `StatusNotFound`, by substring match
(`route_isolation_coverage_test.go:109-132`). It cannot tell a real cross-org assertion
from a mention. It passed for `/api/ai/ask` on the strength of a file that never issues a
request through the router. Worth strengthening; not a regression from today.

**Not fixed here** — `ai_troubleshoot_deps_test.go` and the root package's test surface sit
alongside `main.go`, which another agent is editing.

---

### GAP-5 — **LOW ×9 — recorded, no action**

| # | Finding | Evidence |
|---|---|---|
| 5.1 | BMP session table is a **global** 256-record cap with cross-tenant eviction (`evictOldestClosedLocked` walks all owners) — availability isolation, not data | `internal/bmp/store.go:229-243`, `doc.go:104` |
| 5.2 | `pgInvestigationStore.Recall` relies on FORCE-RLS alone with no explicit `tenant_id =` predicate, while the file store double-filters. House convention, but an asymmetry | `ai/investigation_memory.go:490-499` |
| 5.3 | `PendingInvestigations.Stash` stores an **unclipped** verdict; clipping happens later. Entry-count bound only (§9) | `ai/investigation_pending.go:103` |
| 5.4 | bgpwatch handlers validate query params **before** the authz gate; the sibling BMP module gates first and has a guard test for it | `internal/bgpwatch/http.go:171` vs `internal/bmp/http.go:152` + `http_test.go:164` |
| 5.5 | `evaluate.go` truncates to 50 prefixes / 500 tenants per run **silently** — no metric, no `Status` field, while the module's contract is "an empty list is never all clear" | `internal/bgpwatch/evaluate.go:304-307`, `:344-346` |
| 5.6 | SSH host-key TOFU store is keyed on **address only**, so overlapping RFC1918 space across tenants shares one pin. Pre-existing and platform-wide; protocoldiag correctly reuses the one store rather than adding a second | `device_ssh.go:88`, `protocol_diag_gateway.go:134` |
| 5.7 | `PROTOCOL_DIAG_SSH_*` is one process-wide identity; the `Credentials` closure ignores its `Device` argument. Not a §3a violation (the device is authorized first) but there is no credential boundary as a second line | `protocol_diag_gateway.go:88-133` |
| 5.8 | `/api/troubleshoot/protocol-diagnostics/export` is published in OpenAPI but never registered in `main.go` — the route 404s. No isolation risk; no openapi↔route drift guard exists to catch the class | `internal/openapi/openapi.go:122` vs `main.go:2016-2018` |
| 5.9 | `main.go:1947` comments `/api/notify/itsm` as `(platform-owner)`; it is correctly **per-tenant**. Stale comment only | `itsm_config.go:161-172` |

---

## 6. What was fixed in this pass

| File | Change |
|---|---|
| `internal/alertwebhook/alertwebhook.go` | Widened + case-folded tenant refusal over labels **and** annotations; new customer-network-identity refusal gated on the absence of a self-health `layer` stamp; layer normalization reduced to a closed allowlist |
| `internal/alertwebhook/metrics.go` | `netops_alert_webhook_dropped_customer_total` |
| `internal/alertwebhook/tenant_isolation_test.go` | **new** — 10 §3a rule-5 tests, incl. the host-phone route and the `device="/dev/mapper/…"` false-positive regression |
| `igpmon_deps.go`, `ifgroup_deps.go` | Corrected two comments that claimed an isolation property the code does not have |

**Gate:** `go build ./...` ✅ · `go vet ./...` ✅ · `go test ./internal/alertwebhook/` ✅ ·
`go test . -run 'Isolation|EveryRouteClassified|EveryScopedRoute'` ✅ (201 s) ·
`staticcheck ./internal/alertwebhook/ .` ✅ 0 · `golangci-lint 2.12.2 run .` ✅ 0 issues ·
`golangci-lint run ./internal/alertwebhook/...` ✅ 0 issues.
`-race` could not be run here — no `gcc` in this environment (`CGO_ENABLED=1` fails to
build `runtime/cgo`); it must be run in CI. **Nothing was committed.**

---

## 7. Hand-offs

| # | To | Item |
|---|---|---|
| H1 | the security-lane agent | GAP-2, `internal/seclane/http.go:38` — remove the process-wide `metrics` block from `/api/security/lane/status`, or scope it. Ship the isolation test. |
| H2 | the BGP agent | GAP-2, `internal/bgpwatch/http.go:206` and `bgp_ops.go:1042` — same, for `/api/bgp/alerts` and `/api/bgp/feed` (`rings` / `pollers_active` disclose the platform's tenant count). Cite `internal/bmp/http.go:170` as the in-repo precedent. |
| H3 | owner | GAP-3 policy half — should `rbac.SameTenantStrict` refuse a blank principal tenant? Fail-closed, but the blast radius is every tenant-scoped resource. |
| H4 | owner | GAP-1 residual — stamp `layer:` explicitly on the platform self-health groups in `src/config/rules.yaml` so classification is asserted at the source instead of inferred from absence. |
| H5 | whoever owns `main.go` next | GAP-4 — an end-to-end `/api/ai/ask` isolation test through the router on the **skills** path, plus a two-tenant test for `get_bgp_watchlist`/`get_bgp_rpki`. |

---

## 8. Audit artefacts — cleanup

Everything created for this audit was deleted; verified by re-reading the API afterwards.

| Object | Disposition |
|---|---|
| tenant `audit-b` (`t_a6d18170ba2571d616d6560374fec78f`) | deleted |
| users `auditb-op`, `auditb-adm`, `auditb-notenant` | deleted |
| devices `leak-probe`, `audit-platform-dev` | deleted |
| audit-b ITSM config record | removed with the tenant |
| vmalert probe alert `TenantIsolationAuditProbeA` | dropped by the receiver; never dispatched, never delivered — one `warn` log line and one counter increment remain, which is the intended record |

Two residues are noted rather than removed: the correlation objects the engine generated
for `leak-probe` and `audit-platform-dev` live in ClickHouse and age out with normal
retention; and `netops_alert_webhook_dropped_tenant_total` on the running API is `1`
because of the probe. Neither is deletable without mutating a telemetry store, which an
audit should not do.
