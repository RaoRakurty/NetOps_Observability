# Service View — Expert Audit Panel (2026-07-13)

Four expert auditors swept the Service View at the owner's request ("launch AWS
and Azure cloud experts, let me audit everything the way I am doing"). This is
the consolidated, prioritized finding list. Owner reviews; then we fix in order.

---

# A. AWS TELEMETRY AUDIT

**Verdict:** ingestion skeleton is sound (real APIs, honest "not measured",
route-tables-as-truth is genuinely good design) — but the **app-attribution
layer is silently broken**, the **new CloudWatch lane manufactures false
anomalies by construction**, and **CloudTrail loses events**.

## AWS P0 — the platform is currently asserting false things

### P0-1 · `app_id` tag ignored → every host becomes an "application" · HONESTY BUG
`discover.py:29` + `cloud/resolve.go:12` list app tag keys as
`app, application, app_name, app-name, service, workload`. The live account tags
instances **`app_id: shared`** (`cloud-fixtures/aws.json:26,52`). Miss → fallback
`resolve.go:47-53` copies `ResourceName` into `AppName` **and stamps
`Confidence: Strong`**.
Consequences live right now: Applications tab lists 3 "apps" that are actually
hosts (one is the **VPN NAT appliance** — infrastructure presented as an app);
the Attribution funnel reports **~100% "Strong by resource graph", 0% unknown**
when true attribution is **0%**. The coverage metric — the product's flagship
honesty differentiator — is a vanity number hiding the exact problem it exists to
expose.
**Fix:** add `app_id`/`component` to both lists; **demote the ResourceName
fallback from `Strong` to `Suspected`/`Unknown`** so unattributed resources land
in TopUnknown and drag the funnel down honestly.

### P0-2 · CloudWatch reads the in-flight bucket → false "traffic collapsed" evidence
`cloudmetrics.py:85-91`: `ScanBy=TimestampDescending` + `EndTime=now()` ⇒
`vals[0]` is the **still-filling** 5-min bucket. For `Sum` stats (NetworkIn/Out)
that returns a fraction of the true value. This feeds **VictoriaMetrics AND the
CUSUM detector** → a false-evidence generator wired straight into RCA: it will
fire "network traffic collapsed" episodes on healthy instances, on a schedule.
**Fix:** `EndTime = now - PERIOD_S` (skip the in-flight bucket).

### P0-3 · CloudTrail drops events in bursts (no pagination + advancing checkpoint)
`poller.py:129-159`: `lookup_events(MaxResults=50)` never follows `NextToken`,
then advances `trail_ts` past everything unread. A deploy/Terraform apply
produces >50 events — exactly when the control-plane lane matters most — and the
change that CAUSED the incident is the one most likely to be dropped. Silent.
**Fix:** paginate to exhaustion before advancing the checkpoint; add `EndTime`.

### P0-4 · Flow-log file grows without bound → disk exhaustion
`poller.py:76,110` append to `aws-vpc-flow.vpc` forever. No rotation, no cap. At
real flow volume this fills the disk and takes the poller (and possibly
correlation) down.
**Fix:** rotate/truncate/size-cap, or stream instead of file-append.

## AWS P1 — required before prod-grade
- **P1-1 Composite `StatusCheckFailed`** (`cloudmetrics.py:38`) destroys the
  AWS-vs-customer blame boundary. Poll `_System` / `_Instance` / `_AttachedEBS`
  separately — `_System` = AWS's fault, `_Instance` = yours. This is *the* metric
  a NOC opens the console for.
- **P1-2 EC2 lifecycle `State` not captured** (`discover.py:63-78`) → **stopped ≡
  broken ≡ unknown**. 2 of 3 live instances are stopped RIGHT NOW and the Service
  View has no idea. Highest effort:value ratio on the list — one field.
- **P1-3 CloudWatch metrics reach VictoriaMetrics but no Service View surface
  reads them** — the new lane feeds CUSUM but not the counters it was built for.
  (Partially fixed 2026-07-13 by cloud_enrich.go; UI wiring pending.)
- **P1-4 ALB/target-group health absent** — the #1 app-impact signal in AWS
  (`UnHealthyHostCount`, `HTTPCode_Target_5XX_Count`, `TargetResponseTime`).
- **P1-5 Flow-log parser drops any non-default format wholesale**
  (`cloud_log_parsers.py:117-135`); the header line declaring the schema is
  *stripped* by `poller.py:112` and then the layout is *guessed*.
- **P1-6 ACCEPT flows discarded** (`cloud_log_parsers.py:161`) → the Traffic
  column is structurally unfillable; no top-talkers, no dependency map.
- **P1-7 Flow signals carry NO event timestamp** (`:177`) — only ingest time.
  Breaks temporal ordering, the core of the RCA engine.
- **P1-8 VGW / TGW / peering routes silently dropped; blackhole routes ignored;
  main-route-table subnets get zero edges** (`discover.py:98,104-118`). For a
  product whose flagship story is IPsec/hybrid, dropping the VGW route is the
  sharpest irony in the codebase.
- **P1-9 No pagination on any `describe_*`** (`discover.py:37-56`).
- **P1-10 CloudTrail**: no server-side `ReadOnly=false` filter (hand-maintained
  16-prefix guess instead); `errorCode` discarded (AccessDenied is RCA gold);
  `Resources[0]` arbitrary → entity sometimes literally the event name.
- **P1-11 Four lanes share one failure domain**; a metric-sink hiccup rolls back
  flow+trail checkpoints → duplicate ingestion.
- **P1-12 `NetworkIn` Sum-over-300s labelled `bytes`, rendered as a rate → 300× wrong.**
- **P1-13 CPU credits** (`CPUCreditBalance`) — burstable brownout is invisible.
- **P1-14 Single account/region hardcoded**; no `sts:AssumeRole`.
- **P1-15 No IAM policy committed anywhere** — permission set unreviewable.
- **P1-16 GetMetricData cost** scales linearly: ~$0.03/day today, **~$345/month
  at 1000 instances for 4 metrics**. Above ~500 resources switch to Metric
  Streams → Firehose.
- **P1-17 No console deep-links; account shown as bare 12-digit number; AZ
  captured but never displayed** (AZ is the #1 blast-radius dimension in AWS).

## AWS — what a production tool must ingest that we don't (ranked for NOC RCA)
1. **ELB/ALB target health** (highest value app-impact signal in AWS)
2. **EC2 status checks, split** (`_System` vs `_Instance` = the blame boundary)
3. **EC2 lifecycle state** (one field, huge)
4. **CPU credits** (invisible burstable brownout)
5. VPN tunnel state (`AWS/VPN TunnelState`) — only if a real Site-to-Site VPN
6. **VPC flow logs: ACCEPT + v5 fields** (instance-id/subnet-id/vpc-id give
   direct attribution with zero ENI indirection; flow-direction/traffic-path)
7. CloudWatch Logs (app logs)
8. EBS (`BurstBalance` — silent latency killer)
9. **AWS Health API** ⚠️ **requires Business/Enterprise Support — flag, don't
   silently omit**
10. Route53 health checks · 11. Transit Gateway · 12. **AWS Config** (before/after
   diffs — the right source for change-correlation, richer than CloudTrail)
13. SSM `PingStatus` · 14. X-Ray (correctly deprioritized) · 15. Trusted
   Advisor/Cost (correctly deprioritized — do not let FinOps jump the queue)

## AWS identity — the idiomatic answer
1. **`awsApplication` tag + Service Catalog AppRegistry** (AWS's own first-party
   "what is an application"; compatible with myApplications console)
2. **Resource Groups Tagging API** (`GetResources`) — one call returns every
   resource with a tag across all services; eliminates the pagination bug class
3. Conventional tag keys, **operator-configurable** (hardcoding six keys
   guarantees you're wrong at the first customer)
4. **Structural inference** (ALB→TargetGroup→instances; ASG→instances) — THIS is
   what `Strong`/resource-graph should mean, not copying a Name tag
5. **Fallback = Unknown, not Strong**

---

# B. AZURE TELEMETRY AUDIT

**Verdict:** Azure isn't missing a pipeline — the pipeline is built and generic.
Azure is missing a **producer**, and the reason is a **single unmade identity
decision**. Two owner commands unblock everything. The P0 lane costs **$0/month**,
needs **no Azure SDK**, needs **no container rebuild**.

## Proven live against the subscription (read-only)
| Probe | Result |
|---|---|
| `az monitor metrics list` on the NVA | **WORKS NOW** — CPU 0.157%, Network In/Out, PT1M grain |
| **`VmAvailabilityMetric`** | **EXISTS, returns 1.0, agentless** — the direct `StatusCheckFailed` analogue |
| `Available Memory Bytes` | 673185792 — agentless, no agent needed |
| `az monitor activity-log list` | **WORKS NOW** — captured a real NSG security-rule write |
| `Microsoft.ResourceHealth` provider | **`NotRegistered`** → API 409s. **One owner command fixes it** |
| NSG flow logs | **none configured** (no storage account, no workspace) |
| **`az network vnet-gateway list`** | **EMPTY — there is NO Azure VPN Gateway** |

**The VPN-Gateway premise is wrong.** `TunnelAverageBandwidth` etc. do not exist
for this lab and never will — the tunnel terminates on a self-managed strongSwan
NVA VM. Do not build a VPN-Gateway metric lane. The honest Azure-side tunnel
telemetry is the NVA VM's `Network In/Out Total` + `Inbound/Outbound Flows`.

## Current state: inventory-only, and the inventory is ROTTING
```
aws.json      2026-07-13 23:47   ← live poller, minutes old
azure.json    2026-07-12 14:18   ← 33 HOURS STALE, frozen
```
Blockers: `cloud-ingest/Dockerfile:2` (boto3 only), `poller.py:164` (boto3
session), **`cloudmetrics.py:68` `if not rid.startswith("i-"): continue`** — a
hard AWS-instance-id guard that Azure VMs can never pass; `discover.py:170` same.
`docker-compose.override.yml:68-88` mounts `~/.aws` with no Azure counterpart.
`scripts/cloud-discover-azure.py:12-13` **already flagged** that a service
principal is needed — "an identity grant only the owner can make". Never actioned.

## AZURE P0 (all free, all verified working today)
- **P0-1 Azure metrics → the canonical lane.** 6 metrics. **The key trick:
  invert `VmAvailabilityMetric` → `cloud_status_check_failed = 1 - value`**
  (Azure: 1=available; AWS: 1=failed). Do that and `cloud_enrich.go` lights up
  **with ZERO Go changes** — the canonical metric names are already
  provider-neutral. Highest-leverage single change in the whole audit.
- **P0-2 Inventory refresh loop** — kills the 33h staleness.
- **P0-3 `power_state` in inventory** — **`correlix-app-host-01` is `VM
  deallocated` right now** and renders identically to a running VM. Most
  embarrassing finding: an operator sees it in the portal in 2 seconds.
- **P0-4 Activity Log → `cloud_change`** (the CloudTrail equivalent; works today).
  Needs an Azure noise filter: **`Microsoft.Advisor/*` dominates** the log.
- **P0-5 Resource Health → `cloud_resource_health`.** The first thing an Azure
  operator opens; **needs NO support plan** (unlike AWS Health API).
  `reasonType` = `Platform Initiated` vs `Customer Initiated` is exactly the RCA
  discriminator. **BLOCKED on owner:** `az provider register --namespace
  Microsoft.ResourceHealth` (60s, free).
- **P0-6 `app_id` missing from `APP_TAG_KEYS`** — same one-line bug as AWS P0-1.
- **P0-7 Ingestion Status is PROVIDER-BLIND** (`cloud_ingestion.go:82-88` groups
  by kind with no provider dimension) → AWS metrics landing make the matrix show
  "metrics: flowing" **globally**, so a NOC reads "Azure metrics are flowing".
  They are not. **This is an honesty bug, not cosmetic**, in a product whose
  stated ethic is "we never invent coverage we do not have".

## AZURE P1
- **P1-1 Service principal + `azure.py` in the poller using stdlib `urllib` ONLY
  — no SDK, no Dockerfile change.** (`azure-mgmt-monitor` drags msrest/azure-core/
  azure-identity to wrap two REST calls the container can already make.)
  **BLOCKED on owner:** `az ad sp create-for-rbac --name correlix-telemetry
  --role "Monitoring Reader" --scopes /subscriptions/8d0f8a4e-…` + `Reader`.
  Two roles cover the whole lane. Secret → Key Vault `correlix-kv-8d0f` (exists).
- **P1-3 ARM resource id as inventory primary key** — `azure.json:7` uses the VM
  *name*; names collide across resource groups.
- **P1-4 VNet Flow Logs** (NOT NSG flow logs — **retiring 30 Sep 2027**; there is
  no v3). Only lane with real engineering cost: nested JSON with an embedded CSV
  `flowTuples` string — a genuinely new parser, not a config tweak.
- **P1-5 Resource-group / subscription facets** — Azure operators navigate by RG.
- **P1-6 Azure-correct health copy** — `cloud_enrich.go:148` says "failed status
  check" (AWS idiom); Azure says "unavailable".

## Consciously NOT building
VPN Gateway metrics (**no gateway exists**); Log Analytics/KQL (~$2.30/GB, buys
nothing today); App Insights (needs instrumentation); Traffic Analytics.

## Interim vs prod shape
**NOW (no owner grant needed):** host-side `scripts/azure-telemetry-emitter.sh`
modelled on `drills/ipsec-tunnel-emitter.sh` — the host `az` is authenticated and
every P0 signal returns live data through it. Caveat stated plainly: that's a
**user token** (`correlixlens@gmail.com`), not rotatable, must never enter a
container. A lab bridge, not a product.
**PROD:** service principal + `azure.py` (stdlib urllib) in the poller; managed
identity via IMDS if Correlix ever runs inside Azure.

---

# C. UX / NOC-LANGUAGE AUDIT

**Verdict:** *"The page is epistemically excellent and operationally unreadable.
It was written by someone proving the data is honest; it is read by someone
trying to find out what's broken."*

## The four root causes behind every complaint the owner raised
| Owner's words | Actual mechanism | File:line |
|---|---|---|
| "everything greyed out (even Confidence STRONG)" | **`CONF_TONE.strong = var(--accent)` — and `--accent` IS grey (`#475569`).** STRONG is *literally painted slate-grey*. 3 of 5 confidence tiers render grey. Not perception — paint. | `badges.tsx:30-36`; `styles.css:118` |
| "Applications tab reads dead" | `toApp()` **hard-codes** `health:"unknown"`, traffic/err/p95 = NOT_MEASURED → **6 of 13 columns render "—" by construction** | `api.ts:73-95` |
| "Ingestion: all logs greyed out" | `cloudSourceKinds` maps only **5 of 11** sources; the rest have **no kind mapping** → forced "off" → double-greyed. And "off" conflates *not-shipped* / *disabled* / *broken*. | `cloud_ingestion.go:32-38` |
| "Active Cloud RCA — Apps column empty" | Objects born from network/probe signals **always** have empty `affected.apps`; bare IPs don't resolve | `cloud_signals.go:888-913` |

**Plus:** the backend's new `cloud_ref` (console-pivot payload) **is thrown away
by the frontend** — not declared in `services/api.ts:2122`, not mapped in
`appobs/api.ts:240`. *"The single highest-leverage unblock on the page."*

## The tone rule to encode (why "grey" means five different things today)
| Meaning | Today | Should be |
|---|---|---|
| Measured and normal | grey `unknown` / `—` | **Green**, stated: `Healthy` |
| Measured and bad | amber/red ✔ | keep |
| Not measured (source on, no data) | `—` grey | `No data` — dashed border |
| **Not configured** (you can enable it) | `—` grey + "not ingested" | **`Not configured` + Enable →** (AWS/Azure *sell* the unenabled feature; Correlix apologizes for it) |
| Not supported yet | `off` grey | `Coming soon` / hide |

**Three rules:** (1) `--accent` is NEVER a state color. (2) A not-configured
feature gets a CTA, not a dash. (3) **A permanently-dashed column or KPI tile is
deleted, not shipped.**

## Terminology sweep (developer → operator; AWS/Azure reference)
| Current | Proposed | Ref |
|---|---|---|
| App Observability | **Services / Service View** | AWS "Application Signals", Azure "App Insights" |
| Active App RCA / "correlation objects" | **Open investigations** | — |
| Top hypothesis | **Probable cause** | — |
| Verdict / verdict tier | **Assessment** (Confirmed cause / Likely cause / Investigating) | — |
| Attribution | **Service mapping** | *no AWS/Azure console uses "attribution"* |
| "Strong by resource graph" | **From resource relationships** | — |
| Unknowns | **Untagged resources** | AWS "Untagged resources", Azure Advisor |
| Underlay Impact | **Network connectivity** | AWS Network Manager, Azure Connection Monitor |
| Evidence | **Findings** | AWS Detective / Security Hub |
| Ingestion | **Data sources** | AWS "Data sources", Azure "Data collection" |
| Health & Changes | **split → Alerts · Changes** | Azure ships these as two blades |
| Identity src (`cloud_tag`/`cloud_graph`) | **Mapped by** (Tag / Resource graph / Operator) | — |
| Signal type (`cloud_flow_log`) | **Signal** (VPC Flow Log / Health alert / Config change) | — |
| RCA group (8 chars of a UUID!) | **Investigation** — the probable-cause title, linked | — |
| Window start | **Started** | — |
| "seam" | **connection** (DX/VPN/ExpressRoute *are* "connections" in both consoles) | — |

## Empty states that are thesis defenses, not information
- *"cloud signals are landing but the engine has not grounded a correlation
  object — unknown stays first-class"* → **"No open investigations in the last 24
  hours."**
- *"unknown is a real answer — never a guess · resolve each to lift coverage"* →
  **"Tag these resources to complete your service map."**
- The **entire Underlay Impact tab** is an apology panel. AWS/Azure never ship an
  empty top-level tab — they show an **enablement card with a Set-up button**.

## Identifier leaks (the `eni-…` complaint, systematized)
**Rule (what AWS and Azure both do):** *the cell shows the **name**; the **ID** is
secondary, mono, copyable; the **console link** is an action.* Never the ID alone
in a primary column.
The backend `cloudResourceNamer` **already resolves ENI→name** — the frontend
just isn't using it.

**Console deep-links (everything needed is already in `cloud_ref`):**
```
AWS ENI     https://{region}.console.aws.amazon.com/ec2/home?region={region}#NetworkInterface:networkInterfaceId={eni}
AWS EC2     https://{region}.console.aws.amazon.com/ec2/home?region={region}#InstanceDetails:instanceId={id}
AWS Trail   https://{region}.console.aws.amazon.com/cloudtrailv2/home?region={region}#/events/{eventId}
Azure any   https://portal.azure.com/#@{tenantId}/resource{armResourceId}
Azure log   https://portal.azure.com/#@{tenantId}/resource{armResourceId}/eventlogs
```
*"The single feature that makes this page feel like a cloud monitoring tool
rather than a report about one."*

## Also caught
- **6 "Remediate" buttons all navigate to the same page** (`:656-663`). A button
  that lies is worse than a missing button. Will be caught in a demo.
- `Ingestion` **Permission column is hardcoded "not checked"** for every account —
  a placeholder shipping as a feature.
- Provider filter offers **Azure and GCP with no ingestion path** — dead filters
  that always return zero read as broken software.
- Two different "not measured" sentinels (`NOT_MEASURED=-1` and `p95ms=0`).

## Proposed IA — 5 tabs, not 11
Eleven tabs is a *data-model* menu, not a *task* menu. No AWS/Azure console
exposes its ingestion plumbing as a peer of its health view.
```
Overview | Services | Investigations | Resources | Data sources
                     (Alerts+Changes    (Resources+Untagged
                      +Findings+Network) +Service mapping)
```

---

# D. COUNTER-CORRECTNESS AUDIT (verified live against the running stack)

**Verdict:** *"Ground truth right now: 3 EC2 instances, 2 stopped, 1 AWS account,
2 real cloud changes in 24h, 10 open cloud objects. The Service View reports:
3 apps, 5 resources, 2 accounts, 0 degraded, 33 changes, 2 active RCA, 0%
unknown attribution. **Every one of those seven numbers is wrong.**"*

## D-P0 — counters lying RIGHT NOW

1. **`cloud_enrich.go` is undeployed AND unconsumable.** The running API emits no
   `live` key; the frontend row types have no health/traffic fields and hardcode
   `health:"unknown"` / `NOT_MEASURED` (`appobs/api.ts:81,101,112`). The
   enrichment is **orphaned at both ends** — fix all three layers or Health and
   Traffic stay "—" forever.
2. **"Apps Degraded" = 0 while 2 of 3 hosts are STOPPED.** Its only feed
   (`cloud_health`) **died 28.7h ago** — one hour outside its own 24h window. A
   dead producer renders as "0 degraded" = "all healthy": **the cardinal sin.**
   Meanwhile 10.60.10.10 has 300 failing active checks in 15 min. Must fall back
   to provider status-checks + probe failures + instance state, and must render
   **"—" not 0** when the feed is off.
3. **"Recent Cloud Changes" overcounts 16×.** 33 rows = **2 distinct events**
   with duplicate `signal_id` (AuthorizeSecurityGroupIngress ×19,
   StopInstances ×14 — same signal_id each). The ingester re-inserts the same
   signal every poll. Dedupe in `cloudChangesSQL` (`cloud_signals.go:581`) AND
   fix the re-inserting ingester.
4. **Phantom Azure inventory.** `azure.json` (hand-written, Jul-12, for an account
   with NO connected telemetry) inflates Resources 3→5, Accounts 1→2, Clouds 1→2,
   and **collides app_ids across clouds** (the phantom Azure
   `correlix-app-host-01` merges with the real AWS one into ONE app). Gate
   fixtures on a connected account.

## D-P1 — structurally impossible metrics
5. **"Unknown Attribution %" can NEVER exceed 0.** The graph-name fallback
   (`resolve.go:50-55`) attributes every named resource at `Strong`. `unknown`
   requires a resource with **no name at all**. Coverage/Unknowns/Top-unknown all
   report perfect coverage — **guaranteed 0%, not a measurement.** Top-unknown
   renders *"every discovered resource has an app identity — coverage is
   complete"*: **false comfort.**
6. **`app_id` in neither `appTagKeys` (`resolve.go:12`) nor `APP_KEYS`
   (`appobs/api.ts:53`)** — the fixtures literally carry `app_id: "shared"`.
   Result: real tag ignored (Confirmed-by-tag = 0%) **and** every resource flagged
   "Missing tags: app" while simultaneously shown as `strong`-confidence
   attributed. Self-contradictory on the same screen.
7. **"Active App RCA" capped at 10** (`cloudEvidenceMaxObjects`) and drowned by
   **2,366 merged objects** → shows 2, truth 10. **Undercounts 5×.** Count opens
   with a dedicated COUNT(*), don't derive from a LIMIT-10 list.
8. **Ingestion "Metrics = off"** while 4 cloud metric series actively flow —
   `cloud_ingestion.go:35` queries ClickHouse for a feed that lives in
   **VictoriaMetrics**. Wrong store.

## D-P2 — honesty / labelling
9. `worstHealth` (`AppDetail.tsx:35-40`): `if (health.length > 0) return
   "healthy"` — **any** non-degraded signal (including `state:"unknown"`) upgrades
   the app to healthy, contradicting the comment directly above it.
10. App health rollup (`cloud_handlers.go:103,127`): rank `unknown=0 < healthy=1`,
    so 1 healthy + 1 unmeasured resource ⇒ app "healthy". Contradicts the file's
    own honesty header.
11. `cloudHealthState` (`cloud_signals.go:90`): `severity="info"` → `"healthy"`
    **inside a problems-only table**.
12. **"Observers" shows source PLANES, not observers** (`cloud_handlers.go:205`) —
    displays `probe · cloud` (2) when the object has **4 distinct observer_ids and
    524 signals**. **"crossPlane/Corroborated" is true for almost everything**
    (108k flow-log signals touch nearly every object) → the badge carries zero
    information.
13. **Evidence `count` is the LIMIT, not a count** (`limit=200`→210,
    `limit=500`→510). `category`/`used_in_verdict` hardcoded (`:832,840`) —
    claims every archived signal fed the verdict.
14. "Active cloud RCA" panel renders **8 merged objects** under an "Active" title.
15. **`vmQuery` latent cross-cloud contamination** (`cloud_enrich.go:77-80`):
    falls back to the `device` label as join key — a phantom Azure
    `correlix-vpn-nat-01` could **inherit the real AWS NVA's metrics**.

## D — the double-counting, confirmed with live data
`cloud_enrich.go:107-128` sums probe failures per target after cutting on `->`:
```
10.60.10.10                150   ← bare rollup entity
api->10.60.10.10            60   ← the SAME executions, per-vantage
prober->10.60.10.10         60   ← same
lan-vantage-1->10.60.10.10  30   ← same
```
All four collapse to `10.60.10.10` and **sum to 300** — the rollup is added on top
of the per-vantage rows that produced it. HealthBasis would print *"300 active
checks failed"*: **fabricated precision from ~1 target under ~3 vantages.**

---

# CONSOLIDATED FIX ORDER (proposed — owner to confirm)

**Wave 1 — stop asserting false things (cheap, severe):**
1. AWS P0-1 / Azure P0-6 — `app_id` tag + demote the `Strong` fallback (honesty)
2. AWS P0-2 — CloudWatch in-flight bucket (false RCA evidence)
3. AWS P0-3 — CloudTrail pagination (dropped changes)
4. AWS P0-4 — flow-file disk bomb
5. AWS P1-2 / Azure P0-3 — **lifecycle/power state** (stopped ≠ broken; 2 AWS
   hosts + 1 Azure VM are stopped RIGHT NOW and the product doesn't know)

**Wave 2 — make Azure real ($0, no SDK, no rebuild):**
6. Azure P0-1 (metrics + the VmAvailabilityMetric inversion), P0-2 (refresh),
   P0-4 (activity log), P0-5 (resource health — **owner: `az provider register`**)
7. Azure P0-7 — provider-facet the ingestion matrix (honesty bug)

**Wave 3 — make the UI a cloud monitoring tool:**
8. Confidence tone off `--accent`; wire `cloud_enrich` health/traffic into the UI
9. Stop dropping `cloud_ref`; ship **console deep-links**
10. Kill raw IDs from primary columns; rewrite the 6 thesis-defense empty states
11. Terminology sweep; delete permanently-dashed columns/tiles; fix the 6 lying
    buttons

**Wave 4 — depth:** ALB target health, ACCEPT flows + v5 fields, split status
checks, IAM policy commit, Azure VNet flow logs, the 5-tab IA restructure.

**Owner-gated commands (2, both free, ~5 min total):**
```
az provider register --namespace Microsoft.ResourceHealth
az ad sp create-for-rbac --name correlix-telemetry --role "Monitoring Reader" \
   --scopes /subscriptions/8d0f8a4e-c36e-4265-821f-d6df48123c24
```
