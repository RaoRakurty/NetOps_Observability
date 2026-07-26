# Wireless as a native Correlix access domain — architecture & repository-impact report

**Pass 1 deliverable for `docs/Correlix-Wireless-Architecture.pdf` §37.**
Repository investigation and architecture only. **No production implementation
has been started, and none should start until this report is signed off**
(spec §36 mandatory stop gate; the §36 self-assessment is [§26](#26-36-stop-gate-self-assessment)).

- **Author:** Claude Opus 5, 2026-07-26
- **Spec:** `docs/Correlix-Wireless-Architecture.pdf` (55 pp, 37 §§, authored in ChatGPT Canvas)
- **Tracker:** item **128**
- **Supersedes:** `docs/design/multi-vendor-wifi-expansion.md` §3 — a *pre-research
  skeleton* explicitly parked by the owner on 2026-06-14 pending exactly this design.

## Evidence tiers used throughout

Every non-trivial claim below carries one of these tags. The spec demands the
separation and it is load-bearing: roughly a third of what follows is inference,
and treating it as fact is how a design like this fails six months in.

| Tag | Meaning |
|-----|---------|
| **[V]** | **Verified** — read in this repository at the cited `file:line`. |
| **[I]** | **Inference** — a conclusion drawn from verified facts, not itself read. |
| **[A]** | **Assumption** — taken on faith; stated so it can be challenged. |
| **[L]** | **Needs live validation** — cannot be settled without a real controller/AP. |

---

## 0. Two corrections to the spec before anything else

The spec is a strong document, but two of its premises are false against this
repository. Building to them would introduce forbidden dependencies.

1. **"Redpanda or Kafka topics" (spec §2).** Redpanda is *fully removed* and
   `CLAUDE.md` says **never reintroduce it** (licensing, tracker #97). The bus is
   single-node Kafka in KRaft mode, service `kafka`, profile `embedded-bus`, and
   every client resolves it via `BROKER_URLS`. **[V]** This report designs
   Kafka-only.
2. **"Redis keys and cache behavior" (spec §2).** Redis is *fully removed*, same
   rule, same tracker item. **[V]** There is a `collectors/redis.go` **[V]**, but
   it is not a Redis dependency of the platform — nothing in the wireless design
   may assume a cache tier exists. Where the spec's design implicitly wants one
   (client session state, BSSID→AP resolution cache), this report places that
   state in ClickHouse or in-process, never in Redis.

A third, softer divergence: the spec asks for "an LLM that does not
independently guess root cause" — that is already the architecture (Iris AI is
read-only and evidence-grounded, §18), so this is agreement, not a gap.

---

## 1. Current Correlix architecture relevant to wireless

Correlix is a Docker-Compose stack: discovery → multi-protocol telemetry
ingestion → Kafka → storage (OpenSearch / VictoriaMetrics / ClickHouse /
Postgres) → correlation + RCA → API → React SPA, behind nginx on `:8000`. **[V]**

The parts that matter for wireless:

**Ingestion & discovery (Go, `src/backend/collectors/`).** SNMP (v2c/v3), gNMI,
NETCONF, syslog, SNMP traps, NetFlow/IPFIX, LLDP/CDP, BGP-LS, DOM/optics, entity
inventory, STAMP, synthetics, traceroute. **[V]** Device classification is
`devicetype.go` (`inferDeviceType`) plus `topology/roles.go`, whose device-role
taxonomy is `access_switch`, `distribution_switch`, `core_router`, `firewall`,
`load_balancer`, `wan_edge`, `carrier_hop`, `dc_wan_edge`, `dc_leaf`, `dc_spine`,
`cloud_edge`, `unknown` **[V]** (`topology/roles.go:42-53`). **There is no AP,
WLC, radio or wireless-client role anywhere in it.** **[V]**

**Vendor-controller intelligence (Go, `src/backend/nms/`).** A vendor-neutral,
stdlib-only connector framework — `Connector`/`ConnectorSpec` with declared
`SupportedAuth`, `PreferredAuth`, `Streams`, `RatePerSec`, plus auth (5 kinds),
rate limiting, retry-with-jitter, dedupe, state diffing and normalization. **[V]**
Shipping connectors: Meraki, Catalyst Center, vManage, NDFC, Prime, Versa
Director, Versa Concerto, generic REST/webhook **[V]** (`nms/specs.go:22-85`). It
normalizes into three routed classes — `controller_metric`, `controller_state`,
`controller_event` — mapped onto the correlation engine's existing axes
(`Source.CONTROLLER`, `ModalityClass.MANAGEMENT_PLANE`, `ObserverType.CONTROLLER`)
**[V]** (`nms/model.go:26-47`).

This framework is the single most important reuse asset in the repository for
this programme. It is *already* the "capability-driven provider architecture"
spec §14 asks for; §13 states precisely what it lacks.

**Correlation engine (Python, `src/correlation/`).** A pure, replayable
deterministic core (`engine.py`, 1 405 lines) fed by a Kafka consumer
(`main.py`, 3 019 lines), with a signature catalog (`catalog.py`, 3 058 lines,
137 built-in templates), episode detection, verdict gating, scoring, path graph,
timestamp normalization and confirmability. **[V]** Full lifecycle in §2.

**Service Path Graph (frozen contract v1).** `path_graph.py` + Postgres migration
`0023_service_path_graph.sql` + ClickHouse `path_observations` / `path_hops` /
`corr_path_edges`. **[V]** This is the ordered end-to-end path the spec's chain
(client → access → LAN → SD-WAN → carrier → cloud → app) must live in.

**Iris AI (`src/backend/ai/`).** A governed, read-only, evidence-grounded NOC
assistant: intent → module routing → read-only tool selection → cited evidence
bundle → typed answer schema, with a `PolicyEngine` that hard-denies
write/execute by default. 16 registered modules. **[V]**

**Existing wireless footprint — essentially zero, and deliberately so.**
`collectors/unifi.go` is the only wireless-adjacent collector, and its header
says so outright:

> "SCOPE (owner hold): this is the controller DATA-ACQUISITION plumbing +
> device-level health… The wireless-specific metric family (per-radio channel
> utilization, SSID/band breakdown, AP signatures, wireless UI) is **DEFERRED to
> the owner's wireless-AP design** — this connector deliberately stops at
> device-level monitoring so it doesn't pre-empt that design." **[V]**
> (`collectors/unifi.go:22-27`)

That is this design. The premise checks out: there is no wireless model to
retrofit and no accidental wireless code to reconcile. Greenfield inside a
mature frame.

---

## 2. The exact Correlix correlation-engine lifecycle

Spec §3 demands this be stated exactly, because wireless must enter it rather
than parallel it. Stages are numbered as the code numbers them.

```
[1] ingest        main.py Kafka consumers → per-source normalizers → canonical Signal
[2] episodes      episodes.py — two-sided CUSUM (H=4σ, K=0.5σ) over signed z-deviation
                  · onset = START of the accumulation run, never the alert firing time
                  · onset uncertainty = ±1 sampling interval + source clock-quality budget
                  · baseline FROZEN while an episode is open
[3] nodes         engine.build_nodes — one Node per (entity_type, entity_id, kind) in window
[4] grounding     engine.resolve_grounding — THE ranked relationship gate (below)
[5] edges         engine.build_edges — weight = w_temporal × w_topo × w_reinforce, + direction
[6] components    union-find over admitted edges → one correlation object per component
[7] verdict       scoring.rank against the catalog, then verdicts.py independence gate
[8] persist       ObjectSnapshot → corr_objects / corr_edges / corr_evidence /
                  corr_current / corr_signals_archive (FULL window slice, for replay)
```

**Stage [4] is the owner's hard constraint and it never relaxes.** A pair of
episodes admits an edge **only** with seam context or explicit topology
grounding; ungrounded co-occurrences become counted topology-gap hints, never
edges. **[V]** (`engine.py:12-15`)

The ranked ladder — `resolve_grounding`, `engine.py:364-442`: **[V]**

| Rank | Relationship | Evidence class |
|------|--------------|----------------|
| 1 | same resource identity (device containment) | observed |
| 2 | seam membership by structural identity / endpoint binding | observed |
| 3 | path-hop inventory resolution · L2/L3 topology link | observed |
| 4 | application → endpoint binding | observed |
| 5 | flow / NAT session stitch | observed |
| 6 | cloud route / BGP / SD-WAN policy relation | **inferred** |
| 7 | shared token / name similarity | **candidate** |

Ranks 1–5 may be authoritative. Rank 6 supports but never asserts traffic took
the path. Rank 7 still forms an edge (so an object is not lost) but is demoted
and labelled, and `Grounding.authoritative` is `False`. **[V]**

**The verdict gates in `run_window` (`engine.py:1201-1233`) — all three cap, none block: [V]**

1. `data_class` ≠ live (synthetic/replay/lab) ⇒ may support, never confirm.
2. No authoritative edge (object rests only on rank 6 or 7) ⇒ never confirm.
3. Unknown hops are preserved and declared in `evidence_missing`, never bridged.

**The independence gate (`verdicts.py`) is the single most consequential fact in
this report for wireless.** `confirmed` requires a pair of signals that are
simultaneously (a) of *different modality classes* and (b) *mutually independent
observations*. Independence collapses on measurement authority: **[V]**

- `direct` / `via_aggregator` = **transport**. Telegraf/Vector relay what the
  device measured; the device stays the observer; independence survives.
- `via_controller[:instance]` / `via_cloud_api[:instance]` = **measurement
  authority**. The intermediary *is* the effective witness. Two signals sharing
  an authority instance share its failure modes and are **not** independent.
- Unknown instance ⇒ all signals of that authority *kind* conservatively share
  one instance. Fail-closed: under-claim independence, never over-claim it.

The `nms` package states the consequence in its own comment: "The independence
gate makes a lone management-plane witness cap at 'suspected' —
controller-alone-cannot-confirm is enforced for free." **[V]** (`nms/model.go:42-45`)

**Object identity, merge, resolution, reopen: [V]**

- `correlation_id = uuid5(tenant, earliest-node.key, onset_ms)` — stable while the
  earliest signal stays in the sliding window.
- When it ages out, the same incident re-keys under a new id (split-brain).
  `find_merges` resolves it: a still-live object overlapping a stale open object
  by entity set + time window tombstones the stale one (`state='merged'`,
  `merged_into=<survivor>`).
- Merge writes **only** a lifecycle state + a backlink. It never re-keys a live
  object and never re-ranks an ungrounded union — either would breach both the
  §4.2 grounding gate and the replay contract (`engine.py:1294-1310`).
- Correlation-object state is `Enum8('open','closed','merged')` **[V]**.
  The operator-facing incident lifecycle, including explicit reopen, is separate
  and lives in Go: `incidents.go:93-105`, `incidents_http.go:291`. **[V]**
- Ticketing has its own reopen protection: a stale OPEN arriving after a RESOLVE
  does not auto-reopen, and an old UPDATE must never reopen/repage a resolved
  incident. **[V]** (`ticketing_worker.go:128-155`)

**Replay contract.** `engine.py` is pure: no IO, no wall clock, no randomness, no
dict-order dependence. `engine_version` pins semver + a content hash of every
tunable. Snapshots embed the grounding context (seam views, orientations,
adjacency pairs, path view) so a stored object re-runs forever even after live
inventory evolves. **[V]** **Every wireless addition must preserve this or it is
invalid**; the practical rule is in §21.

---

## 3. Existing abstractions that can be reused as-is

This is the good news, and it is substantial. Wireless needs no new discovery
framework, correlation engine, evidence model, incident model, workflow engine,
ticketing path or remediation framework — the spec forbids all of those, and the
repository makes the prohibition cheap.

| Abstraction | Where | Why it carries wireless unchanged |
|---|---|---|
| `nms.Connector` / `ConnectorSpec` | `src/backend/nms/` | Auth, rate limit, retry+jitter, dedupe, state diffing, poll runner, webhook. A WLC *is* a controller; this is the controller framework. **[V]** |
| `ControllerMetric`/`State`/`Event` | `nms/model.go` | Three routing classes already cover RF metrics, radio/AP state, and WLC alarms. **[V]** |
| `Source.CONTROLLER`, `ObserverType.CONTROLLER`, `ModalityClass.MANAGEMENT_PLANE` | `signals.py:46,56,66` | The wireless controller plane already has canonical axes — **no `source` enum change needed**. **[V]** |
| Independence / measurement-authority gate | `verdicts.py` | `via_controller:<wlc-id>` already collapses two WLC-derived signals into one witness. Exactly right for wireless; no change. **[V]** |
| Ranked grounding gate | `engine.py:364` | Wireless edges plug in as new *resolution methods* at existing ranks (§8). Ladder semantics unchanged. **[V]** |
| Episode detection (CUSUM, onset uncertainty, frozen baseline) | `episodes.py` | Applies to RF metrics unmodified. **[V]** |
| Signature catalog as validated, versioned, CI-fixtured data | `catalog.py` (83 templates) | Wireless signatures are new *rows*, not new machinery. **[V]** |
| Service Path Graph contract v1 | `path_graph.py`, mig `0023`, CH `path_*` | Ordered hops, endpoint bindings, transformations, unknown-hop preservation, validity windows, provenance. **[V]** |
| Event-time discipline & timestamp normalization | `signals.py:323`, `timenorm.py` | `ts` must be tz-aware or the record dead-letters. Receive-time substitution is structurally refused. **[V]** |
| Tenant isolation (CH row policies, PG FORCE-RLS, `tenant_scope`) | `init.sql:562-572`, migs `0010/0012/0023` | Uniform and enforced. **[V]** |
| Iris module/tool/policy registry | `src/backend/ai/` | A wireless module is a registry entry + read-only tools. **[V]** |
| ITSM/ticketing + notification outbox, reopen protection | `ticketing_*.go`, `notify/` | Wireless incidents ride the same path. **[V]** |
| **Enum-extension migration pattern** | `corr_schema.go:135-142` | Precedent: `source` gained `cloud`/`app_identity`/`controller`/`verification`, `entity_type` gained `app`/`cloud_resource`, all via converge-on-boot `ALTER … MODIFY COLUMN`. **[V]** |

That last row matters more than it looks: the riskiest-*sounding* migration in
this programme — extending a frozen ClickHouse `Enum8` — is a **practiced,
already-shipped** operation here, not a novel one.

---

## 4. Existing abstractions that require extension

| Abstraction | Extension needed | Cost |
|---|---|---|
| `EntityType` (`signals.py:76`, CH `Enum8` ×2) | +7 wireless entity types (§7). Needs `ALTER … MODIFY COLUMN` on `corr_signals` **and** `corr_signals_archive`. | Medium — mechanical, but touches a frozen enum and the replay archive. |
| `CausalLayer` (`layers.py:21`) | RF/PHY has no home. `DEVICE=0 … APPLICATION=6` is a dense `IntEnum` used as an *ordering*. | **High risk** — blocker B1. |
| `_KIND_LAYER` (`layers.py:39`) | ~25 new wireless kinds → layers. Additive. | Low. |
| `BOUNDARY_OF_KIND` (`path_graph.py:215`) | Add `wireless_client`/`wireless_access` kinds mapping to `LAN` (owner: wired + wireless are one LAN boundary). | Low — §6. |
| `ResolutionMethod` / `RANK` (`path_graph.py:124-146`) | New wireless resolution methods at existing ranks. Additive. | Low. |
| `topology` node kinds / `DevRole*` (`types.go:41`, `roles.go:42`) | AP, WLC, radio, wireless client. | Low — free-form strings. |
| `nms.ConnectorSpec` | No capability model beyond `Streams []string`; no per-field fidelity declaration. | Medium — §13. |
| `collectors/unifi.go` | Un-park the wireless metric family it deferred. | Low. |
| `PathObservation.method` | `traceroute_icmp\|traceroute_tcp\|stamp\|transaction\|flow_stitch` — wireless access has no traceroute hop. | Medium — blocker B3. |
| Iris `registry.go` | A `wireless` module + read-only tools. | Low. |

---

## 5. Architectural gaps and blockers

Brutally honest, worst first.

### B1 — `CausalLayer` cannot express RF without a renumber or a lie *(blocker)*

`CausalLayer` is a dense `IntEnum` — `DEVICE=0, PHYSICAL=1, LINK=2, NETWORK=3,
TRANSPORT=4, SERVICE=5, APPLICATION=6` — and **the integer ordering IS the causal
direction prior** (§4.3 vote #3) as well as the axis the RCA Layer-Stack UI
renders. **[V]** (`layers.py:21-36`)

Wireless breaks it in two directions at once:

1. **RF is below PHYSICAL.** Channel utilization, co-channel interference, SNR
   and retry rate cause link-layer symptoms. They are not `PHYSICAL=1` (optics /
   FCS at the line), and folding them in destroys the distinction that makes
   wireless RCA worth having.
2. **Onboarding is not a layer at all.** Association (L2), 802.1X/EAP (L2 + a AAA
   *service*), DHCP (L3), DNS (L7 service) — an onboarding failure walks *up* the
   stack. The existing ladder orders those four correctly, but only if the auth
   step is not mis-sited.

Three options, none free:

- **(a) Renumber** to insert `RF = 1` and shift the rest. Cleanest semantics, but
  the values feed the direction prior and are embedded in stored snapshots, so
  this is an **engine-major bump** (`ENGINE_SEMVER` 3.0.0 → 4.0.0) plus a fixture
  re-baseline. **[I]**
- **(b) `RF = -1`.** Preserves every existing integer, so replay and the direction
  prior are untouched. Ugly; needs an `_OSI_LABEL` entry. Cheapest correct option. **[I]**
- **(c) Sparse renumber** (×10: `DEVICE=0, RF=5, PHYSICAL=10, …`) with a
  compatibility shim. Most future-proof, largest blast radius.

**Recommendation: (b) for Phase 1**, with (c) deferred to a dedicated
engine-major if a second sub-physical layer ever appears. Owner decision —
Open Question **Q1**.

### B2 — Wireless can rarely reach `confirmed` on controller evidence alone *(fundamental, and correct)*

The independence gate collapses everything arriving `via_controller:<wlc>` into a
single witness. **[V]** A Catalyst 9800 reporting AP-down, client-disconnect, RF
interference *and* the client session record is **one observer**, not four.
Modality diversity does not rescue it, because the gate requires diversity **and**
independence.

Stated plainly: **a wireless-only deployment with one WLC and no other telemetry
will produce `suspected` verdicts, never `confirmed`.** That is the system
working as designed, and the spec's "prefer UNDETERMINED over unsupported
certainty" rule endorses it. But it means the wireless value proposition depends
on a **second independent witness**, and the design must name which:

- **Access-switch port telemetry for the AP uplink** (SNMP/gNMI, `direct` — a
  genuinely different observer). **Strongest and most available.**
- Flow records from the AP uplink or distribution layer (`passive_flow`).
- A client-side or on-prem synthetic agent (`active_probe`).
- RADIUS/AAA server logs for the auth step (an independent authority).

**This promotes the AP uplink from a nice-to-have to a first-class requirement.**
It is why §13's capability model must record which independent witnesses a
deployment actually has, and why the health model must be honest when it has only
one.

### B3 — The service path has no hop before the LAN gateway *(design gap)*

`PathObservation.method` is `traceroute_icmp|traceroute_tcp|stamp|transaction|
flow_stitch` **[V]** (`init.sql:475`). Wireless access is a **single L2
association**, not a routed hop: a traceroute from a wireless client's first
responding hop is already the LAN gateway. The AP, its radio, the BSSID and (in
tunneled deployments) the WLC are invisible to every existing path method. A new
observation method and a hop-synthesis rule are required — §6, §8.

### B4 — No guarded-action subsystem exists at all *(gap, largest single build)*

Spec §25–§26 want guarded auto-healing with remediation verification. The
repository has:

- Iris `PolicyEngine`: `CapWrite`/`CapExecute` **hard-denied** unless
  `AllowActions` (default false), and even lifted, a write tool must additionally
  pass per-tool gates. **[V]** (`ai/policy.go:22-89`) That knob removes a ban; it
  is not an action framework.
- `self_heal.go`: a genuine watch → heal → tell loop, but scoped to **appliance
  self-health** (OpenSearch read-only index blocks under disk pressure), not
  device remediation. **[V]** It is nonetheless the right *shape* to copy.
- `device_ssh.go`: an opt-in `FEATURE_DEVICE_SSH` WebSocket→SSH proxy, dormant by
  default **[V]** — the only device-write-capable transport in the codebase.
- `rca_actions.go` / `rca_action_items.go`: an evidence-validated **ActionPlanner**
  that selects human action steps from *participating* evidence and refuses steps
  whose evidence family did not take part. **[V]**

So the *inputs* to guarded remediation exist and are good; the **executor,
approval workflow, blast-radius model, dry-run, rollback and verification loop do
not exist.** §19 designs them; they are Phase 8 and must not be pulled earlier.

### B5 — Client MAC is PII, and there is no MAC-privacy model *(compliance gap)*

Wireless correlation is *client-centric* in a way no existing Correlix domain is.
A client MAC, its 802.1X username, and its per-AP movement history are personal
data in a way an interface counter is not. The repo has an LLM-egress redaction
hook (`Redactor` **[V]**) and a `DataProtection` page **[V]**, but no field-level
PII policy for a telemetry entity. Randomized/rotating MACs (iOS/Android default
since ~2020 **[A]**) *also* break identity continuity, so this is an accuracy
problem as well as a privacy one. §9 and §16 address both; retention is Open
Question **Q4**.

### B6 — Correlation consumer auto-commits offsets *(pre-existing, inherited, amplified)*

Tracker **126**: `main.py` builds its `AIOKafkaConsumer` with
`enable_auto_commit=True`, so offsets advance on a timer regardless of whether
the ClickHouse write committed. Wireless will be the highest-volume producer into
this consumer (§20). **This should be fixed before wireless volume lands**, not
after. Not a wireless defect — a wireless *amplifier*.

### B7 — No lab wireless hardware *(delivery constraint)*

Consistent with `multi-vendor-wifi-expansion.md` §0's fidelity ladder
(`doc_claimed` → `lab_validated` → `live_validated` **[V]**), everything in this
report is at best `doc_claimed`. There is no WLC, AP or wireless client in the lab
**[V — no wireless config, no wireless env switches, no wireless fixtures exist]**.
§23 plans validation without hardware; §24 gates every `live_validated` claim
behind access the project does not currently have. **[L]**

---

## 6. Proposed relationship between Wireless Access and the existing LAN seam

**The finding that shapes this section: there is no LAN *seam*.** Seam types are
`CHECK (seam_type IN ('DX','VPN','SDWAN','DIA','CLOUD_BACKBONE'))` **[V]**
(`0010_seam_inventory.sql:17`) — every one an *ownership-transition* boundary
where the enterprise hands traffic to someone else. "LAN" is a **coarse rendering
boundary**: `BOUNDARY_OF_KIND = {client: LAN, lan_gateway: LAN, wan_edge: SD-WAN,
transit: CARRIER, nva/cloud_edge/app_endpoint/service_endpoint: CLOUD}` **[V]**
(`path_graph.py:215-225`), plus a `SegmentType.LAN` in the hop classifier **[V]**.

So "how does Wireless Access relate to the LAN seam?" resolves into two decisions.

**Decision 1 — wireless is part of the LAN boundary, not a new boundary and not
a seam type** *(owner direction, 2026-07-26: "wireless and wired both are part of
the LAN seam"; the domain chain is LAN → WAN → CARRIER → CLOUD, with cloud edge
and cloud as ONE zone and DC as its own domain)*.

It is not an ownership transition; the enterprise owns both sides. Adding it to
`seam_type`'s CHECK would corrupt the seam model's meaning and make every
seam-redundancy rule (`seam_groups.redundancy_model`) nonsense for wireless. And
per the owner's chain it is not a separate rendering boundary either — a wireless
client is a LAN endpoint whose access medium happens to be air:

```
BOUNDARY_OF_KIND (proposed additions):
  wireless_client  → "LAN"          (new kind, LAN boundary — owner direction)
  wireless_access  → "LAN"          (new kind, LAN boundary; AP / radio / BSSID)
  client           → "LAN"          (unchanged — wired clients)
  lan_gateway      → "LAN"          (unchanged)
```

The rendered spine stays `LAN → SD-WAN → CARRIER → CLOUD`; wireless hops render
*inside* the LAN boundary group (the endpoint `kind` still distinguishes them for
fault localization — the boundary grain does not need to). **[I]** Related open
item, outside this report's scope: the owner's chain also makes **DC** its own
domain, while `SEGMENT_TO_BOUNDARY` currently folds `dc → "LAN"`
(`segment_classifier.py:83`) — a boundary-layer change independent of wireless.

**Decision 2 — the wireless access "hop" is synthesized, not measured.**
Because of B3, a wireless client's path observation starts at the LAN gateway.
Proposal: a new observation method `wireless_association` producing a **two-hop
prefix** (`wireless_client → wireless_access`) synthesized from the controller's
client-session record, with:

- `state = responding` only when the session record is current; otherwise the hop
  is `missing` and **preserved, not bridged** (contract §8, already enforced **[V]**).
- `resolution_method = wireless_association` — **rank 3**: it is an observed L2
  association reported by the device/controller, exactly parallel to
  `topology_link` for LLDP/CDP.
- `evidence_ref` pointing at the controller observation, **mandatory** (contract §5).
- `data_class` inherited from the producer.

**Why rank 3 and not 1 or 2:** rank 1 is same-resource containment (a client is
not *in* an AP); rank 2 is declared seam membership (there is no seam). Rank 3 is
"path-hop inventory resolution · L2/L3 topology link" — an association *is* an L2
link, learned from the device that terminates it. This keeps wireless edges
**authoritative** (rank ≤ 5) without inventing a new rank tier. **[I]**

**Where the two domains actually meet — the AP uplink is the join.** The AP's
uplink switchport is simultaneously the last wireless-domain object and an
ordinary access-switch interface. That single interface makes wireless↔LAN edges
ground at **rank 1** (resource identity: the same `switch:Gi1/0/12` appears in
both an AP-uplink node and a switch-interface node). **This is the cleanest and
most important structural join in the whole design**, and it is why §13 insists on
modelling the AP uplink even when a controller does not report it.

---

## 7. Exact canonical object schema

Vendor-neutral. Names are proposals; every one is new.

### 7.1 New `EntityType` values

Added to `signals.py:76` **and** both ClickHouse `Enum8` columns:

| Value | Int | Represents |
|---|---|---|
| `wireless_controller` | 10 | A **logical** WLC/gateway cluster (not a member) |
| `access_point` | 11 | A physical AP |
| `radio` | 12 | One AP radio (slot) |
| `bssid` | 13 | One broadcast BSSID (radio × WLAN) |
| `wlan` | 14 | A WLAN profile (configuration object) |
| `wireless_client` | 15 | A client device identity |
| `wireless_session` | 16 | One temporal client association session |

Seven values. **No** new `source` value (`controller`=11 exists **[V]**), **no**
new `observer_type` (`controller`=6 **[V]**), **no** new `modality_class`
(`management_plane`=5 **[V]**) — though see §12 on why some wireless telemetry is
legitimately `device_telemetry`, not `management_plane`.

### 7.2 Canonical entity records (Postgres, new migration `0030_wireless_inventory.sql`)

Following the `topology_nodes` pattern exactly: typed columns for what is
queried + a lossless `data JSONB` + tenant FORCE-RLS. **[I]**

```
wireless_controllers      controller_id, tenant_id, name, vendor, model, os_version,
                          cluster_role, management_address, forwarding_default,
                          visibility, first_seen, last_seen, stale, data JSONB
wireless_controller_members
                          member_id, controller_id, tenant_id, name, serial,
                          member_state, redundancy_role, ap_capacity, data JSONB
access_points             ap_id, tenant_id, name, mac_base, serial, model, vendor,
                          controller_ref, site_id, floor_ref, x, y,
                          uplink_switch_ref, uplink_port_ref, poe_class, poe_draw_w,
                          mgmt_address, mgmt_vlan, forwarding_mode,
                          first_seen, last_seen, stale, data JSONB
ap_radios                 radio_id, ap_id, tenant_id, slot, band, channel,
                          channel_width_mhz, tx_power_dbm, tx_power_max_dbm,
                          admin_state, oper_state, generation, mlo_capable, data JSONB
wlans                     wlan_id, tenant_id, profile_name, ssid_ref, controller_ref,
                          security_mode, auth_method, aaa_ref, vlan_or_pool,
                          forwarding_mode, band_policy, mobility_domain_ref,
                          enabled, data JSONB
ssids                     ssid_id, tenant_id, ssid_name, data JSONB
bssids                    bssid, tenant_id, radio_ref, wlan_ref, ap_ref,
                          first_seen, last_seen, data JSONB
```

**Identity rules — all deterministic, all tenant-prefixed: [I]**

- `ap_id = sha256(tenant | vendor | serial)` when a serial exists, else
  `sha256(tenant | vendor | mac_base)`. **Never the name** — APs are renamed
  routinely and a rename must not fork identity.
- `radio_id = ap_id | slot`. **Slot, not band**: dual-5 GHz and tri-band APs make
  band ambiguous.
- `bssid` is itself the identity (a MAC, unique per radio × WLAN).
- `wlan_id = sha256(tenant | controller_ref | profile_name)` — a WLAN profile is
  controller-scoped. `ssid_id = sha256(tenant | ssid_name)` — an SSID is a
  broadcast string and is deliberately **not** controller-scoped (§9).
- `wireless_client` identity: §9.3 — the hardest one.

### 7.3 `entity_id` string forms in signals

The engine derives grounding from `entity_id` *structure*: `device_part()` splits
on `:`, and `identity_refs()` treats the left of `:` as a device **[V]**
(`engine.py:194-219`). Wireless ids **must** exploit this:

```
access_point         ap:<ap_id>
radio                ap:<ap_id>:radio<slot>       → device_part = "ap:<ap_id>"  ✓
bssid                ap:<ap_id>:bssid:<mac>       → device_part = "ap:<ap_id>"  ✓
ap uplink interface  <switch_id>:<ifname>         → device_part = "<switch_id>" ✓ ← the LAN join
wireless_controller  wlc:<controller_id>
controller member    wlc:<controller_id>:<member> → device_part = "wlc:<...>"   ✓
wireless_client      wcl:<client_id>
wireless_session     wcl:<client_id>:<session_id> → device_part = "wcl:<...>"   ✓
wlan                 wlan:<wlan_id>
```

This is not cosmetic: it means an AP-radio signal and an AP-device signal ground
at **rank 1** with no new code, and an AP-uplink signal grounds at rank 1 against
the access switch. **[I]** Getting these strings wrong is the easiest way to
silently lose all wireless correlation.

⚠️ **`entity_tokens` hazard — a hard rule.** `Signal.__post_init__` rejects
tenant-/org-wide grounding tokens by prefix **[V]** (`signals.py:332-340`). An
SSID is *exactly* the kind of token that looks useful and is catastrophic:
`ssid:corp` spans every AP in the estate, so admitting it as a grounding token
would weld every unrelated wireless incident into one object — the precise bug
class (#99) that guard was written to prevent. **`ssid:` and `wlan:` must be
added to `_FORBIDDEN_TOKEN_PREFIXES`, or never emitted as entity_tokens.** **[I]**
Open Question **Q2** is only about *which* enforcement point.

---

## 8. Exact canonical edge schema

**Reuse `corr_path_edges`, not `corr_edges`.** `corr_edges.grounding_kind` is a
frozen `Enum8('seam','topo')` **[V]**, and `init.sql:460-462` records that the
engine already refused to overload `grounding_ref` for typed edges. But
`corr_path_edges.edge_type` is `LowCardinality(String)` **[V]** — **new wireless
edge types need no migration at all.**

### 8.1 New `EdgeType` values (`path_graph.py:186`)

| Edge | From → To | Rank | Class |
|---|---|---|---|
| `AP_UPLINKS_VIA_PORT` | access_point → interface | 1 | observed |
| `RADIO_ON_AP` | radio → access_point | 1 | observed |
| `BSSID_ON_RADIO` | bssid → radio | 1 | observed |
| `BSSID_SERVES_WLAN` | bssid → wlan | 1 | observed |
| `WLAN_BROADCASTS_SSID` | wlan → ssid | 1 | observed |
| `CLIENT_ASSOCIATED_TO_BSSID` | wireless_session → bssid | 3 | observed |
| `SESSION_OF_CLIENT` | wireless_session → wireless_client | 1 | observed |
| `AP_MANAGED_BY_CONTROLLER` | access_point → wireless_controller | 3 | observed |
| `AP_TUNNELS_TO_CONTROLLER` | access_point → wireless_controller | 3 | observed |
| `CONTROLLER_MEMBER_OF_CLUSTER` | member → wireless_controller | 1 | observed |
| `SESSION_AUTHENTICATED_BY` | wireless_session → service (AAA) | 4 | observed |
| `MLO_LINK_OF_SESSION` | mlo_link → wireless_session | 1 | observed |

**Critical distinction — the spec is right to insist (§12):**
`AP_MANAGED_BY_CONTROLLER` (control/management association) and
`AP_TUNNELS_TO_CONTROLLER` (client **data** encapsulation) are **different edges
that may have different endpoints**. In FlexConnect / local switching the first
exists and the second does not. Collapsing them makes every local-switching
deployment mis-attribute client data-plane faults to the WLC. **[I]**

### 8.2 New `ResolutionMethod` values (`path_graph.py:124`, `RANK`)

```
wireless_association     → rank 3   observed L2 association (controller/device reported)
ap_uplink_binding        → rank 1   resource identity: AP ↔ switchport
wireless_containment     → rank 1   radio / BSSID within AP
capwap_tunnel_binding    → rank 3   observed tunnel endpoint pair
wireless_policy_relation → rank 6   INFERRED: WLAN→VLAN mapping, RF-profile assignment
```

Note `wireless_policy_relation` at **rank 6 (inferred)**. A WLAN's configured VLAN
says traffic *should* land there; only a flow or a DHCP lease says it *did*. Rank
6 means an object held together only by configuration can never be `confirmed` —
exactly the honesty the spec demands. **[I]**

---

## 9. Exact SSID / WLAN / BSSID model

Spec §7 requires these be separate identities. They must be, and the reason is
operational, not pedantic.

```
SSID   — the broadcast NAME. NOT unique, NOT owned. "corp" on two controllers in
         two buildings may be one roaming domain or two unrelated networks.
WLAN   — the CONFIGURATION PROFILE on a controller: SSID + security + auth +
         VLAN/pool + forwarding mode + band policy. Controller-scoped.
BSSID  — the MAC a specific RADIO broadcasts for a specific WLAN. Unique. THE
         only precise "where was this client" identity.
```

**Cardinality:** one SSID → many WLANs (across controllers) → many BSSIDs (per
radio per AP). A 500-AP estate with 4 SSIDs and tri-band radios yields ~6 000
BSSIDs. **[I]**

### 9.1 SSID must never be a grounding token
Restated from §7.3 because it is the highest-consequence rule here: SSID is
estate-wide. As a grounding token it welds unrelated incidents; as a *filter* and
*display grouping* it is essential. Both are true, and the model must keep them
apart. **[I]**

### 9.2 Roaming domains
Two BSSIDs of the same SSID on different APs are a roam **only if** the same WLAN
profile and mobility domain apply. Proposal: `wlans.mobility_domain_ref`,
populated from the controller when it exposes one (Cisco mobility group, Aruba
cluster) and **left null otherwise — never inferred from SSID equality**. A null
mobility domain means roam analysis abstains, which is honest. **[I]**
**[L — needs a real multi-controller estate]**

### 9.3 Wireless client identity — the hardest problem in this design

| Candidate key | Stable? | Problem |
|---|---|---|
| MAC | No | Randomized/rotating per-SSID on modern iOS/Android **[A]** |
| 802.1X username | Per-user | Absent on PSK/open; one user → many devices |
| DHCP client-id / hostname | Weak | Spoofable, often absent |
| Certificate CN (EAP-TLS) | Strong | Only on cert-based enterprises |
| Vendor client-id (Meraki/Mist) | Strong-ish | Proprietary; breaks vendor neutrality |

**Proposal — two-tier identity, mirroring the repo's existing confidence ladder
(`authoritative|strong|candidate|unknown` **[V]**):**

- **`wireless_session`** is the *primary, always-reliable* entity: one
  association, keyed `sha256(tenant | bssid | client_mac | assoc_start_ms)`.
  Deterministic, never ambiguous, sufficient for every single-session RCA.
- **`wireless_client`** is a *derived, confidence-tagged* rollup linking sessions.
  Ladder: EAP-TLS CN (`authoritative`) → 802.1X username (`strong`) → stable
  non-randomized MAC, U/L bit clear (`strong`) → DHCP client-id (`candidate`) →
  randomized MAC (`unknown`, session-scoped only).

**Consequence to accept up front:** for a randomized-MAC client, cross-session
history is `unknown` and the platform must **say so rather than guess**.
Multi-session RCA ("this user's laptop has roamed badly all week") is only
available at `strong`+ confidence. **[I]** That is a real product limitation, and
the owner should see it now rather than in a demo.

---

## 10. Exact Wi-Fi 7 Multi-Link Operation model

MLO breaks the assumption that a session has *one* radio, *one* band and *one*
BSSID: a Wi-Fi 7 client may hold simultaneous links on 2.4/5/6 GHz under one MLD
identity. **[A — from the 802.11be design; not verified against hardware] [L]**

Modelling MLO as "the strongest link" or "the first link" corrupts the canonical
model: a client whose 6 GHz link is failing while 5 GHz carries traffic is *not* a
failing client, and per-link RF metrics must never be averaged.

**Proposal — the session is the MLD; links are children:**

```
wireless_session  + mld_mac (= client MAC for non-MLO), is_mlo, link_count

mlo_links  (new)
  link_id = sha256(session_id | link_index)
  session_ref, link_index, band, radio_ref, bssid_ref,
  link_state (active|idle|disabled|removed),
  rssi_dbm, snr_db, mcs, nss, channel, channel_width_mhz,
  valid_from, valid_to
```

**The compatibility rule that makes this safe: a non-MLO client is an MLO client
with exactly one link.** Every wireless query, signature and health computation is
written against `mlo_links` from day one, so Wi-Fi 7 is not a later schema break.
`link_count = 1` is the overwhelmingly common case and costs one join. **[I]**

Signals attach to the **link** (`entity_id = wcl:<client>:<session>:link<N>`) where
the metric is per-link (RSSI, SNR, MCS, retries) and to the **session** where it
is not (auth result, DHCP outcome, total throughput). Because `device_part()`
splits on the first `:`, both still ground at rank 1 to the client. **[V — the
split behaviour; [I] — the consequence]**

---

## 11. Exact controller, gateway, cluster and member model

Spec §11 insists logical control domains be separate from physical members, and
it is right: an N+1 WLC cluster failing over is not an outage, and a model that
conflates the two reports one.

```
wireless_controller         ← LOGICAL. What APs join and configuration binds to.
  cluster_role: standalone | ha_pair | n_plus_1 | cloud_managed | controllerless
wireless_controller_member  ← PHYSICAL. A real box / VM / instance.
  member_state: active | standby | member | failed | maintenance
  redundancy_role: primary | secondary | tertiary
```

**Rules:**

- APs bind to the **logical** controller. A member failover changes
  `member_state`, **not** any AP edge. **[I]**
- Controller *health* signals attach to the **member** (`wlc:<id>:<member>`);
  controller *capability* signals (AP capacity exhausted, licence limit) attach to
  the **logical** controller.
- `CONTROLLER_MEMBER_OF_CLUSTER` grounds at rank 1 via `device_part()`, so a
  member fault and a cluster-capability fault correlate for free. **[I]**
- **Cloud-managed** (Meraki, Mist, Aruba Central) is a `cluster_role`, not a
  different entity: the logical controller exists, its members are the vendor's
  cloud (opaque), and `visibility` must be recorded as `partial` — mirroring the
  seam model's honest default, where `visibility` defaults to `'partial'` and
  `'full'` is *earned, never assumed* **[V]** (`0010_seam_inventory.sql:24-25`).
- **Controllerless** (autonomous APs, UniFi-without-controller):
  `cluster_role='controllerless'`, zero members, APs bind directly. Every edge
  that would run through a controller simply does not exist — and, importantly,
  **its absence is not a missing-evidence finding.** **[I]**
- **Gateway clusters** (Aruba mobility gateways, tunnel concentrators) use the
  identical two-tier shape with `gateway` semantics; one pair of tables carries
  both with a `kind` discriminator, not a parallel pair. **[I]**

---

## 12. Exact observation and temporal-provenance schema

The engine's non-negotiables, all already enforced: **[V]**

- `ts` is **event time** from the source clock and must be tz-aware, or the record
  dead-letters (`signals.py:323`).
- `Observer` is mandatory; empty `observer_id` ⇒ `DeadLetter` (`signals.py:290`),
  backstopped by ClickHouse `CHECK observer_id != ''` (`init.sql:221`).
- `source_clock_quality` ∈ `ntp|ptp|free_running|unknown` feeds the onset
  uncertainty budget.
- `collection_path` decides independence (§2).

**Wireless-specific temporal hazards and required handling:**

| Hazard | Handling |
|---|---|
| Controller polls every 30–300 s; the event happened earlier | `ts` = the controller's **reported event time**, never poll time. If the vendor gives only "last seen", use it and widen `attrs.onset_uncertainty_s` to the poll interval. **Never** substitute receive time. |
| AP clocks are often free-running | `source_clock_quality='free_running'`; the uncertainty budget absorbs it. |
| Session start/end read from a table *after* the fact | `ts` = association timestamp from the record; `ingest_ts` carries the read time (already a column **[V]**). |
| Cloud-managed APIs return minute buckets | `onset_uncertainty_s ≥ 60`. |
| Roam reported by **both** old and new AP | Dedupe on `(client_mac, new_bssid, ts±uncertainty)` via the existing `nms/dedupe.go` `DedupeKey` pattern **[V]**. |

**Modality assignment — where the obvious answer is wrong.** Not all wireless
telemetry is `management_plane`:

- WLC-reported alarms, client sessions, RF profiles → `management_plane`,
  `collection_path=via_controller:<wlc_id>`. **One witness.**
- AP-sourced SNMP/gNMI read **directly from the AP** (not through the WLC) →
  `device_telemetry`, `direct`. **A different witness.**
- AP-uplink switchport counters from the access switch → `device_telemetry`,
  `direct`. **A genuinely independent witness.**
- Flow from the AP uplink → `passive_flow`. Client-side synthetic → `active_probe`.

Getting this wrong in either direction is harmful: over-claiming `direct` for
controller-relayed data manufactures false `confirmed` verdicts; under-claiming
buries real independence and strands everything at `suspected`. **The rule: the
witness is whoever *measured*; the authority is whoever *vouches*.** **[I]**

---

## 13. Proposed provider interfaces and capability model

`nms.ConnectorSpec` declares `Streams []string` and nothing about *fidelity*
**[V]**. That is adequate when every connector reports a similar alarm shape; it
is inadequate for wireless, where vendors differ enormously in what they expose
(per-client RF history, channel utilization, MLO link detail, roam events, uplink
mapping). Without a capability model the platform cannot distinguish "this vendor
cannot report X" from "X is fine" — and the spec explicitly forbids treating an
unsupported capability as a healthy one.

**Proposal — extend, do not replace:**

```go
// nms/capability.go (new)
type Capability string

const (
    CapAPInventory        Capability = "wireless.ap_inventory"
    CapRadioState         Capability = "wireless.radio_state"
    CapRFMetrics          Capability = "wireless.rf_metrics"
    CapChannelUtil        Capability = "wireless.channel_utilization"
    CapClientSessions     Capability = "wireless.client_sessions"
    CapClientRFMetrics    Capability = "wireless.client_rf_metrics"
    CapRoamEvents         Capability = "wireless.roam_events"
    CapOnboardingFailures Capability = "wireless.onboarding_failures"
    CapAPUplinkMapping    Capability = "wireless.ap_uplink_mapping"
    CapMLOLinks           Capability = "wireless.mlo_links"
    CapRRMActions         Capability = "wireless.rrm_actions"       // remediation
    CapClientDisconnect   Capability = "wireless.client_disconnect" // remediation
)

type Fidelity string

const (
    FidelityNone          Fidelity = "none"           // vendor cannot report it
    FidelityDocClaimed    Fidelity = "doc_claimed"    // per vendor docs; unproven here
    FidelityLabValidated  Fidelity = "lab_validated"  // a fixture replays correctly
    FidelityLiveValidated Fidelity = "live_validated" // confirmed end-to-end
)

type CapabilityDecl struct {
    Capability   Capability
    Fidelity     Fidelity
    PollInterval time.Duration // the vendor's real granularity, not our ask
    Notes        string
}
```

`ConnectorSpec` gains `Capabilities []CapabilityDecl`. **[I]**

**This reuses the fidelity ladder the project already adopted** in
`multi-vendor-wifi-expansion.md` §0 **[V]** — not a new concept, the existing one
made machine-readable. The health model reads it to decide what it may assert;
the UI reads it to grey out what a deployment genuinely cannot see. A capability
at `none` produces an **explicit "not observable here", never a green tile.**

**The provider interface itself** stays the existing `Connector`. Wireless is a
set of new `Streams` (`wireless_aps`, `wireless_radios`, `wireless_clients`,
`wireless_rf`, `wireless_events`) plus a `WirelessTransformer` per vendor
producing canonical objects. Core stays vendor-neutral; vendor packages never
import the correlation engine — the existing rule **[V]**, enforced by
`architecture_guards_test.go` **[V]**.

---

## 14. Cisco Catalyst 9800 source and integration plan

**Correction to a likely assumption: the existing `nms/catalyst.go` is Catalyst
*Center* (DNA Center), NOT Catalyst 9800.** **[V]** It flattens everything to
device/interface (`deviceId`, `deviceName`, `siteId`, `entityType`) with no AP,
WLAN, radio or client concept **[V]** (`nms/catalyst.go:16-73`). It is a useful
*secondary* source and a good code template; it is not a wireless source.

**Sources available on a Catalyst 9800, best first.**
**[A — from Cisco platform documentation; none verified against hardware] [L]**

| Source | Carries | Notes |
|---|---|---|
| **RESTCONF / YANG** (`Cisco-IOS-XE-wireless-*`) | AP oper, radio oper, client oper, RRM, WLAN cfg, rogue | Richest, most structured, model-driven, versioned. **Primary.** |
| **gNMI / dial-out MDT** | Same models, streamed | Removes poll latency; the repo already has a gNMI collector **[V]**. **Strong Phase-2+ target.** |
| **SNMP** (`CISCO-LWAPP-*`, `AIRESPACE-WIRELESS-MIB`) | AP/radio/client tables | Widely available, coarse, heavy per-client. Fallback. |
| **Syslog** | Association/auth/DHCP failure *reasons*, AP join/leave | Best source for onboarding failure detail; repo has a syslog lane **[V]**. |
| **NETCONF** | Config + oper | Overlaps RESTCONF; lower priority. |

**Plan:** a `nms/catalyst9800.go` connector — `Vendor: "catalyst_9800"`,
`SourceSystem: "catalyst_9800"`, `AuthBasic`+`AuthToken`, streams
`wireless_aps|wireless_radios|wireless_clients|wireless_rf|wireless_events`,
RESTCONF-first with SNMP declared at lower fidelity, plus a syslog grammar for
onboarding reasons routed through the existing lane. Rate limiting via the
existing `nms/ratelimit.go`. **[I]**

**Poll budget — a real constraint, not a footnote.** Per-client RF polling on a
500-AP / 5 000-client estate at 30 s is **10 000 client-reads/minute against one
WLC**. That will not be acceptable to most customers. **Proposal:** inventory
(AP/radio/WLAN) at 300 s; client *sessions* at 60 s; per-client RF detail **on
demand only** (Iris troubleshooting, or while an episode is already open on that
client's AP). §20 depends on this. **[I] [L — real WLC rate limits must be measured]**

---

## 15. Multi-vendor architecture-validation plan

Spec §17 asks for proof the canonical model survives contact with vendors that
disagree. The validation is a **paper-and-fixture proof executed before the second
connector is written**, not after.

| Deployment model | Exemplar | What it stresses |
|---|---|---|
| Controller-based CAPWAP, central switching | Catalyst 9800 + CAPWAP data tunnel | `AP_TUNNELS_TO_CONTROLLER` exists; client data runs via WLC |
| Controller-based, **local** switching | Catalyst 9800 FlexConnect | `AP_MANAGED_BY_CONTROLLER` exists, `AP_TUNNELS_TO_CONTROLLER` **absent** |
| Gateway-tunneled | Aruba + mobility gateway cluster | Gateway cluster ≠ controller cluster; two-tier model must hold |
| Cloud-managed, local forwarding | Meraki | Opaque members; `visibility=partial`; capability gaps must show as gaps |
| Cloud-managed, tunneled | Mist + Mist Edge | Cloud control, on-prem data anchor |
| Controllerless | UniFi standalone / autonomous APs | Zero controller edges; absence must not read as missing evidence |
| Mixed forwarding | Per-WLAN split on one controller | Forwarding mode is a **WLAN** property, not a controller property |
| Split tunnelling | FlexConnect + a central WLAN | One AP, two data paths simultaneously |
| Nested encapsulation | CAPWAP inside IPsec inside SD-WAN | The transformation chain must not flatten |

**Proof obligation per row:** a fixture producing the canonical objects + edges,
plus assertions that (a) no edge is invented that the deployment does not have,
and (b) **no absent edge is reported as missing evidence.** Both directions
matter; the second is the one designs usually fail.

**Honest caveat:** with no hardware, every row is `doc_claimed` and the fixtures
are hand-authored from vendor documentation. Per the project's own rule — *"author
only from real, cited OIDs/paths/formats. Never invent an OID to fill a gap"*
**[V]** — every fixture must cite its YANG path / MIB OID / API field, and gaps
must be flagged rather than filled. **[L]**

---

## 16. Client onboarding-episode model

Spec §19 asks for an "applicability-aware" onboarding episode. Applicability is
the whole point: **not every step applies to every client**, and reporting a
skipped step as a failure is the classic wireless-monitoring lie.

```
Onboarding phases (ordered; each independently applicable):
  1. discovery/probe   (always)
  2. authentication    (802.1X | PSK | OWE | open | MAC-auth | captive portal)
  3. association       (always)
  4. key exchange      (4-way handshake — absent on open/OWE-transition)
  5. addressing        (DHCPv4 | DHCPv6 | SLAAC | static | dual-stack)
  6. name resolution   (DNS — applicable only once addressed)
  7. first data        (always)
```

**Applicability rules — derived, never assumed: [I]**

- Phase 2's *method* comes from the WLAN's `security_mode`/`auth_method`. A PSK
  WLAN has no RADIUS step, so a missing RADIUS response is **not a finding**.
- Phase 4 is absent on open networks.
- Phase 5 depends on the WLAN's address policy. **A dual-stack client that gets
  IPv6 but not IPv4 is degraded, not failed** — and a v4-only monitor would report
  success while the user cannot reach a v4-only service. The spec's
  IPv4/IPv6/dual-stack requirement lands exactly here.
- Phase 6 is skipped if addressing failed. **Skipped ≠ failed.**

```
onboarding_episodes
  episode_id = sha256(tenant | client_mac | bssid | attempt_start_ms)
  session_ref (nullable — a failed onboard has no session)
  phases JSONB: [{phase, applicable, outcome(success|failure|timeout|skipped|unknown),
                  started_at, ended_at, duration_ms, reason_code, reason_text,
                  evidence_ref, observer_id}]
  terminal_phase, terminal_outcome, total_duration_ms
```

**Correlation entry point:** an episode with `terminal_outcome=failure` emits
`kind=wireless_onboarding_failure` at the causal layer of the **terminal phase**
(auth → `LINK`, addressing → `NETWORK`, DNS → `SERVICE`), never a generic
"wireless failure". That is what lets the existing layer prior order a
DHCP-scope-exhaustion incident *below* the app symptom it causes, and lets a DHCP
failure correlate with the DHCP server rather than the AP. **[I]**

It is also how "wireless users can't reach SaaS" correctly resolves to a
**non-wireless** root cause: the onboarding episode succeeds, wireless contributes
no fault signal, and the object's authoritative edges lead to the real cause.

---

## 17. Wireless correlation-signature model

Signatures are **data**, added to `catalog.py`'s validated, content-hashed,
CI-fixtured template set (137 built-ins today, verified by import **[V]**). **No engine change.**

Template anatomy is unchanged: `requires` (evidence chain), `discriminators`
(look-alike killers, which force-evaluate a named competitor),
`required_modalities`, `applies_when`, `verdict` (layer + owner + first steps). **[V]**

**Proposed initial set (~14). The discriminator is the load-bearing half:**

| Signature | Requires | Discriminator (`else_prefer`) |
|---|---|---|
| `ap_down_power` | ap_unreachable + uplink port down + PoE draw → 0 | uplink port **up** ⇒ `ap_software_fault` |
| `ap_uplink_saturation` | ap_uplink_util_high + client throughput drop | RF also degraded ⇒ `rf_congestion` |
| `rf_co_channel_interference` | channel_util_high + retry_rate_high + SNR normal | SNR **low** ⇒ `rf_coverage_hole` |
| `rf_coverage_hole` | client RSSI low + retries high + sticky roams | confined to one client ⇒ `client_device_fault` |
| `rf_non_wifi_interference` | channel_util_high + **low** wifi-attributed util | wifi util high ⇒ `rf_co_channel_interference` |
| `dfs_radar_event` | radar detection + channel change + brief outage | no radar event ⇒ `rrm_channel_change` |
| `wlc_failover` | member_state change + AP re-join burst | APs did **not** re-join ⇒ `wlc_capability_exhausted` |
| `capwap_tunnel_instability` | AP join/leave flaps + uplink path loss | uplink clean ⇒ `wlc_resource_exhaustion` |
| `auth_radius_failure` | onboarding failure @ auth + RADIUS timeout | RADIUS healthy ⇒ `auth_credential_failure` |
| `dhcp_scope_exhaustion` | onboarding failure @ addressing, **many clients, one VLAN** | single client ⇒ `client_device_fault` |
| `client_roaming_instability` | rapid BSSID changes + session churn, one client | many clients ⇒ `rf_coverage_hole` |
| `wlan_config_drift` | WLAN config change + onboarding failure onset | no config change ⇒ competitor by terminal phase |
| `ap_oversubscription` | client count high + airtime high + per-client throughput low | airtime **low** ⇒ `ap_uplink_saturation` |
| `wireless_not_the_cause` | wireless nominal + app symptom + authoritative off-path fault | — see below |

**That last one is not a signature; it is the spec's thesis, and it needs no new
machinery.** When wireless telemetry is nominal, wireless nodes contribute no
fault signals, the object's authoritative edges lead elsewhere, and the existing
path-attribution pass (`path_attribution.object_attribution` **[V]**) names the
on-path cause. **The correct implementation of "don't blame wireless" is to add no
code at all** — and to ensure the wireless health model never emits a fault signal
for a healthy wireless domain merely because wireless users are complaining. That
discipline is why this section exists.

**Wireless as root / contributor / affected / unrelated / undetermined** falls out
of the existing model: root = upstream-most authoritative node; contributing = an
authoritative wireless edge with lower-layer onset but insufficient explanation;
affected = wireless entities with symptom-layer signals only; unrelated = no
authoritative edge to the object; undetermined = the verdict gate capped it. All
five are already expressible. **[I]**

---

## 18. Iris troubleshooting architecture

Iris AI is read-only by design and the `PolicyEngine` hard-denies write/execute
**[V]**. Wireless integrates as a **module + read-only tools**, exactly like the
16 existing modules **[V]**.

```go
// ai/registry.go — new module
ID: "wireless", DisplayName: "Wireless",
Freshness: FreshnessLive, Sensitivity: SensitivitySensitive,  // client PII
Availability: AvailabilityStable,
```

`SensitivitySensitive` (not `Operational`) because client MAC/username reach the
prompt; the existing `Redactor` (the LLM06 control **[V]**) must pseudonymize
client identifiers before egress.

**Read-only tools:** `wireless_client_session_history`, `wireless_ap_health`,
`wireless_rf_neighborhood`, `wireless_onboarding_timeline`, `wireless_roam_history`,
`wireless_wlan_config`. Every one tenant-scoped through the existing `DataSource`;
every one returning **cited evidence** (observation ids), never prose.

Per-user location history over time is arguably `SensitivityRestricted` rather
than `Sensitive` — Open Question **Q5**.

**Hard rule, from CLAUDE.md §15 and spec §1 alike:** the LLM never constructs or
executes device commands and never *decides* root cause. It explains the engine's
verdict with citations. Wireless changes nothing here and must not.

---

## 19. Guarded remediation architecture

Nothing exists (B4). This is a build, and it is the part of the programme most
likely to cause a customer outage if rushed.

**Five gates, all mandatory, in order:**

```
1. PROPOSAL     ActionPlanner (rca_actions.go pattern) proposes from PARTICIPATING
                evidence only. An action whose evidence family did not participate is
                never proposed — the existing planner already enforces exactly this. [V]
2. ELIGIBILITY  Action in a per-tenant allowlist; verdict must be `confirmed` (never
                `suspected`/`undetermined`); target inside a declared blast-radius
                bound (≤1 AP, ≤N clients, not during a change freeze).
3. APPROVAL     Human approval by default. Per-tenant, per-action-type auto-approve is
                opt-in, off by default, and audited.
4. EXECUTION    Idempotent, timeout-bounded, rate-limited, via the vendor connector —
                never raw SSH (`device_ssh.go` stays a human terminal). Dry-run first
                where the vendor supports it.
5. VERIFICATION Re-measure the originating signal after a settle window. Not recovered
                ⇒ automatic rollback where possible, and the action is recorded failed.
                Never fire-and-forget.
```

**Initial action set — deliberately the three lowest-risk: [I]**

| Action | Blast radius | Reversible |
|---|---|---|
| RRM channel change on one radio | 1 radio; brief client re-assoc | Yes (restore channel) |
| AP radio reset | 1 AP; its clients briefly | Yes (implicit) |
| Deauthenticate one client session | 1 client | N/A (client re-onboards) |

**Explicitly out of scope for Phase 8:** WLAN config changes, controller failover,
power changes across an RF group, and anything touching more than one AP in one
action. Those are where auto-healing turns an incident into an outage.

Every action is an auditable event through the existing audit lane, and
`FEATURE_WIRELESS_ACTIONS` defaults **false** — matching the platform's
dormant-by-default convention for `FEATURE_DEVICE_SSH` and `FEATURE_TRACEROUTE`
**[V]**.

---

## 20. High-cardinality storage and retention plan

The second-largest technical risk after B1, and the spec is right to call it out (§22).

**Cardinality for a 500-AP / 5 000-client estate: [I]**

| Entity | Count |
|---|---|
| APs | 500 |
| Radios | 1 500 (tri-band) |
| BSSIDs | ~6 000 (4 SSIDs × 1 500 radios) |
| Concurrent sessions | ~5 000 |
| Sessions/day | ~25 000 (5× churn **[A]**) |
| MLO links | ~5 000–15 000 |

**Per-client RF metrics are the cardinality bomb.** 5 000 clients × 6 series
(RSSI, SNR, MCS, NSS, retries, tx-rate) at 30 s = **60 000 samples/minute**, and
in VictoriaMetrics each client MAC is a **label value** — 5 000 new series/day
from randomized MACs alone. Unacceptable; must not be built.

**Three-tier split, by what each store is good at: [I]**

| Tier | Store | Contents | Retention |
|---|---|---|---|
| **Inventory** | Postgres | APs, radios, WLANs, SSIDs, BSSIDs, controllers, members | Current + history via `first_seen`/`last_seen`/`stale` — the `topology_nodes` pattern **[V]** |
| **Aggregate series** | VictoriaMetrics | Per-**AP** and per-**radio** only (channel util, client count, airtime, noise, uplink) | Existing profile TTLs |
| **Per-client events** | ClickHouse | Sessions, onboarding episodes, roams, MLO links, per-client RF **snapshots at event boundaries** | 30 d hot, cold Parquet |

**The rule: no per-client series in VictoriaMetrics, ever.** Client MAC is a
ClickHouse *column* (plain `String` in a sorted key — `LowCardinality` would be
wrong here), never a metric label. Per-client RF is sampled **at event boundaries**
(association, roam, disassociation, onboarding-phase transition) and **on demand**
during an open episode — never continuously. **[I]**

New ClickHouse tables (`netops.wireless_sessions`, `wireless_onboarding_episodes`,
`wireless_roams`, `wireless_mlo_links`, `wireless_client_rf`), all following the
established pattern: `PARTITION BY (tenant_id, toYYYYMMDD(...))`,
`ORDER BY (tenant_id, ...)`, TTL, `ttl_only_drop_parts=1`, and a `tenant_iso_*`
row policy per table (`init.sql:562-572` **[V]**).

**Signal volume into `corr_signals` must be bounded upstream.** A 500-AP estate can
trivially out-produce the entire existing platform. Existing storm damping and the
`corr_tenant_write_amp` rollup **[V]** apply, but the real control is at the
source: **onboarding *failures* become signals; onboarding *successes* do not.**
Successes live in ClickHouse for troubleshooting and never enter correlation. Same
for roams — only anomalous roam patterns become signals. **[I]**

**This is where tracker item 126 (B6) becomes urgent**: auto-committed offsets,
under the highest-volume producer the platform will have.

---

## 21. Database and migration impact

| Change | Object | Risk |
|---|---|---|
| **`ALTER … MODIFY COLUMN entity_type`** (+7 values) | CH `corr_signals` **and** `corr_signals_archive` | **Medium.** Precedent exists (`corr_schema.go:135-142` **[V]**), converges on boot. Both tables, or replay breaks. |
| New CH tables ×5 + row policies | `netops.wireless_*` | Low — established pattern |
| New PG migration `0030_wireless_inventory.sql` (7 tables) + FORCE-RLS + rollback | Postgres | Low — established pattern; **rollback file mandatory** (`migrations/rollback/` **[V]**) |
| `CausalLayer` change | `layers.py` | **HIGH — B1; engine-version implications** |
| `_KIND_LAYER` additions | `layers.py` | None (additive) |
| `EdgeType`/`ResolutionMethod`/`RANK` additions | `path_graph.py` | Low — `corr_path_edges.edge_type` is a free string **[V]**, so **no CH migration** |
| `BOUNDARY_OF_KIND` additions (new kinds → `LAN`) | `path_graph.py` | Low — spine shape unchanged (owner: wireless renders inside LAN) |
| New signature templates | `catalog.py` | **Changes `catalog_version` content hash** — expected and versioned **[V]** |
| `_FORBIDDEN_TOKEN_PREFIXES` += `ssid`,`wlan` | `signals.py` | Low, and **required** (§7.3) |

**No change to** `corr_edges`, `corr_objects`, `corr_current`, `corr_evidence`,
`source`, `observer_type`, `modality_class`, the seam tables, or the existing
Kafka topic set.

**New Kafka topics:** `netops.wireless_events`, `netops.wireless_sessions`.
Wireless controller events could ride the existing `netops.controller_events`
**[V]**, but a separate topic is preferred so wireless volume cannot starve
SD-WAN/fabric controller events on a shared partition set. **[I]** — Q7.

**Replay-contract compliance — the rule for every wireless change:** additive enum
values and new templates are safe (the version/hash pins them). Anything that
changes the *meaning* of an existing value (B1 option (a)) requires an
`ENGINE_SEMVER` major bump and a fixture re-baseline. Every new engine input must
be embedded in the snapshot, as `seams`/`orientations`/`adjacency_pairs`/`paths`
already are **[V]**, or replay silently diverges.

---

## 22. Exact repository files and packages expected to change

**New — Go**
```
src/backend/wireless/                  model.go identity.go inventory.go store.go
                                       capability.go health.go
src/backend/nms/capability.go          capability + fidelity declarations
src/backend/nms/catalyst9800.go        Catalyst 9800 connector + transformer
src/backend/nms/aruba.go               (Phase 5)
src/backend/nms/mist.go                (Phase 5)
src/backend/wireless_http.go           read APIs
src/backend/wireless_store.go          PG store (+ RLS via withTenant)
src/backend/wireless_isolation_test.go MANDATORY (CLAUDE.md §3a.5)
src/backend/migrations/0030_wireless_inventory.sql
src/backend/migrations/rollback/0030_wireless_inventory.down.sql
src/backend/wireless_actions.go        (Phase 8, gated)
```

**New — Python**
```
src/correlation/wireless_normalize.py    controller/AP records → canonical Signals
src/correlation/wireless_onboarding.py   onboarding episode assembly
src/correlation/test_wireless_*.py       unit + isolation + golden-wire
src/correlation/fixtures/wireless/       per-vendor fixtures (cited sources only)
```

**New — Frontend**
```
src/frontend/src/pages/Wireless.tsx
src/frontend/src/pages/WirelessClientDetail.tsx
src/frontend/src/features/wireless/
```

**Modified — Python (the sensitive set)**
```
src/correlation/signals.py            EntityType +7; _FORBIDDEN_TOKEN_PREFIXES +ssid,wlan
src/correlation/layers.py             CausalLayer RF (B1); _KIND_LAYER +~25 kinds
src/correlation/path_graph.py         EdgeType, ResolutionMethod, RANK, BOUNDARY_OF_KIND
src/correlation/catalog.py            +14 signature templates
src/correlation/main.py               wireless consumer wiring
src/correlation/segment_classifier.py wireless segment type
```

**Modified — Go**
```
src/backend/corr_schema.go            entity_type ALTER (BOTH tables)
src/backend/topology/types.go         node kinds: access_point, wireless_controller
src/backend/topology/roles.go         DevRoleAccessPoint, DevRoleWirelessController
src/backend/devicetype.go             AP/WLC classification
src/backend/collectors/unifi.go       UN-PARK the wireless metric family
src/backend/nms/connector.go          ConnectorSpec.Capabilities
src/backend/nms/specs.go              new specs + wireless streams
src/backend/nms/topics.go             wireless topics
src/backend/ai/registry.go            wireless module
src/backend/ai/tools.go               wireless read-only tools
src/backend/main.go                   routes + FEATURE_WIRELESS* flags
deployment/docker/clickhouse/init.sql new tables + row policies
```

**Modified — docs / config**
```
docs/ARCHITECTURE.md, docs/INGESTION.md, docs/TRACKER.md (item 128)
docs/design/multi-vendor-wifi-expansion.md   §3 → superseded pointer
docs/audit/INVARIANTS.md                     new standing gaps
telemetry-catalog/                           wireless metric/event families
deployment/docker/.env.example               FEATURE_WIRELESS*, WLC_* vars
```

**Order of magnitude:** ~25 new files, ~20 modified, across 4 languages and 6
bounded contexts. **This cannot be one change** — CLAUDE.md §7 requires one
bounded context per change. Hence §24.

---

## 23. Test and fault-injection plan

**Unit (every module — CLAUDE.md §11):** identity determinism (same input ⇒ same
`ap_id`/`session_id`); **rename stability** (an AP rename must not fork identity);
canonical transforms per vendor fixture; capability honesty (a `none` capability
must never yield a metric).

**Isolation (MANDATORY — CLAUDE.md §3a.5):** `wireless_isolation_test.go` modelled
on `org_isolation_test.go` **[V]**, asserting own-only list, cross-tenant
get/put/delete → **404**, and `as_tenant` into another org ignored. Plus a
correlation-side test that a wireless window never spans tenants.

**Contract / golden-wire:** wireless fixtures added to the existing golden-wire
lane (`test_golden_wire_all_lanes.py` **[V]**), asserting byte-identical snapshots
across replays.

**Failure-class tests (spec §29 — classes, not examples):**

| Class | Assertion |
|---|---|
| Controller unreachable | No wireless signals; **no false "all APs down"** |
| Partial controller response | Partial data ingested, gaps declared, nothing invented |
| Clock skew (AP free-running) | Onset uncertainty widens; causal order preserved |
| Late events | Object updates; **no spurious reopen** |
| Duplicate roam reports (both APs) | Deduped to one |
| Randomized MAC | Session correct; client rollup `unknown`, **not guessed** |
| Vendor lacks a capability | Explicit "not observable"; **never green** |
| Single-witness wireless | Caps at `suspected`; **never `confirmed`** |
| Wireless healthy + app broken | Wireless not blamed; off-path cause named |
| Controller failover | `member_state` changes; **AP edges unchanged**; no AP-down storm |
| Local switching | No `AP_TUNNELS_TO_CONTROLLER` edge, and its absence is **not** missing evidence |
| MLO one link down | Session degraded, not failed; per-link metrics not averaged |
| Dual-stack, v6-only success | Reported **degraded**, not success |

**Physical fault injection (requires hardware — [L]):** AP power removal (PoE port
shutdown); uplink port shutdown; controlled RF interference; DFS radar simulation;
RADIUS server stop; DHCP scope exhaustion; controller member failover; forced
client roam. **None are executable in the current lab (B7).** They are the
acceptance battery for `live_validated` and must be tagged in
`docs/runbooks/first-customer-acceptance.md` the way `TAG:OFFHOST-DR` already is
**[V]**.

---

## 24. Phased delivery plan

Each phase is independently reviewable and shippable, per CLAUDE.md §7 (one
bounded context per change) and spec §34.

| Ph | Scope | Gate to exit |
|---|---|---|
| **0** | **This report + owner sign-off.** Resolve Q1–Q8. | Owner approves; B1 decided |
| **1** | **Canonical model, no telemetry.** Entity types, PG migration + rollback, CH tables + row policies, identity functions, isolation test. | Isolation test green; migrations reversible; **no data flowing** |
| **2** | **Catalyst 9800 read-only ingestion.** Connector, capability declarations, fixtures, normalizer → canonical objects. Inventory + radio state only. | Fixtures replay; capability-honesty test green |
| **3** | **Correlation integration.** Layer change (B1), edge types, resolution methods, boundary, AP-uplink join, first 6 signatures. | Golden-wire byte-identical; single-witness caps at `suspected` |
| **4** | **Client sessions + onboarding episodes.** Session/MLO model, applicability rules, remaining signatures. | Failure-class battery green; **no per-client VM series** |
| **5** | **Multi-vendor proof.** Aruba + Mist + controllerless fixtures; the §15 matrix. | All 9 models produce correct edges **and correct absences** |
| **6** | **Iris module + read-only tools.** | Redaction verified; tenant scoping verified |
| **7** | **UI.** Wireless views, RF neighbourhood, client timeline. | — |
| **8** | **Guarded remediation** (`FEATURE_WIRELESS_ACTIONS=false` default). | Five gates enforced; verification loop proven; blast radius bounded |
| **9** | **Live validation.** Physical fault injection on real hardware. | `live_validated` fidelity **earned**, not claimed |

**Phases 1–5 are the product.** 6–8 are leverage. **Phase 9 cannot start without
hardware the project does not have (B7).**

**Prerequisite, not a phase:** fix tracker **126** (auto-commit offsets, B6) before
Phase 4 puts wireless volume on that consumer.

---

## 25. Open questions requiring approval

| # | Question | Recommendation |
|---|---|---|
| **Q1** | **`CausalLayer` and RF (B1)** — renumber (engine-major), `RF = -1`, or sparse renumber? | **`RF = -1`** for Phase 1. Preserves every stored integer, no replay re-baseline, reversible if a second sub-physical layer appears. |
| **Q2** | **SSID token enforcement** — add `ssid`/`wlan` to `_FORBIDDEN_TOKEN_PREFIXES` (hard, model-level) or rely on producer discipline? | **Hard, model-level.** Producer discipline is how #99 happened. |
| **Q3** | **Wireless as `Source`** — reuse `Source.CONTROLLER` or add `Source.WIRELESS`? | **Reuse `CONTROLLER`.** Correct semantics (a WLC *is* a controller) and it avoids a second enum migration. AP-direct telemetry uses `metric`/`syslog`/`trap` as today. |
| **Q4** | **Client MAC retention & PII (B5)** — how long, pseudonymized at rest or in flight, per-tenant opt-out? | 30 d hot as today; **pseudonymize at Iris egress minimum**. Needs an owner/legal call, not an engineering default. |
| **Q5** | **Iris sensitivity for client location history** — `Sensitive` or `Restricted`? | Start `Sensitive`; revisit with Q4. |
| **Q6** | **Per-client RF polling budget (§14, §20)** — is on-demand-only acceptable, or do customers expect continuous per-client RF? | **On-demand only.** Continuous is unaffordable at estate scale and the value is at the event boundaries. |
| **Q7** | **Wireless Kafka topics** — dedicated `netops.wireless_*` or ride `netops.controller_events`? | **Dedicated.** Volume isolation; wireless must not starve SD-WAN/fabric events. |
| **Q8** | **Hardware for Phase 9 (B7)** — can any WLC + AP + client be made available (lab, loaner, or first customer)? | Blocking for `live_validated`. Everything else proceeds without it. |

---

## 26. §36 stop-gate self-assessment

The spec forbids proceeding "merely because the proposed architecture appears
reasonable". Honest scoring against §36's 17 required demonstrations:

| # | Requirement | State |
|---|---|---|
| 1 | Exact reuse of discovery abstractions | ✅ §3, §13 — the `nms` framework is reused, not replaced |
| 2 | Exact reuse of the correlation lifecycle | ✅ §2 — stages [1]–[8] traced to code |
| 3 | Exact mapping to signals/objects/edges/evidence/verdicts | ✅ §7, §8, §17 |
| 4 | Exact incident merge/resolution/reopen behaviour | ✅ §2 — engine merge + Go incident lifecycle + ticketing reopen protection |
| 5 | Exact database and migration impact | ✅ §21 |
| 6 | Event-time & timestamp-uncertainty handling | ✅ §12 |
| 7 | Wi-Fi 7 MLO compatibility | ⚠️ §10 — model is sound; **unvalidated against hardware [L]** |
| 8 | Separate SSID/WLAN/BSSID identities | ✅ §9 |
| 9 | Local/central/mixed forwarding | ✅ §8, §15 — distinct management vs data edges |
| 10 | Controller- and gateway-cluster compatibility | ✅ §11 |
| 11 | Cloud-managed compatibility | ✅ §11 — `partial` visibility, honest capability gaps |
| 12 | Ordered service-path integration | ✅ §6 — wireless inside the LAN boundary (owner direction) + synthesized association hop |
| 13 | Storage and cardinality feasibility | ✅ §20 — three-tier split; **no per-client VM series** |
| 14 | Tenant-isolation enforcement | ✅ §21, §23 — RLS + row policies + mandatory isolation test |
| 15 | Remediation safety architecture | ✅ §19 — five gates, default-off |
| 16 | Realistic live-controller validation plan | ⚠️ §15, §24 Ph 9 — **plan exists, access does not (B7/Q8)** |
| 17 | Realistic physical fault-injection plan | ⚠️ §23 — **battery defined, no hardware to run it (B7/Q8)** |

**15 of 17 satisfied on paper. Three (7, 16, 17) are gated on hardware the project
does not have** — the honest state, and the reason Phase 9 is a separate phase
rather than folded into earlier ones.

**Recommendation: the stop gate is satisfied for Phases 0–8 and NOT satisfied for
Phase 9.** Implementation may begin on Phase 1 once **Q1–Q3** are answered (those
three change the schema); Q4–Q8 can be settled during Phases 1–3.

**What would make this report wrong**, in descending likelihood:

1. Real Catalyst 9800 YANG models do not carry the fields §14 assumes. **[L]**
2. Per-client polling limits are far tighter than §20 budgets. **[L]**
3. MLO reporting differs materially from §10's model. **[L]**
4. A customer's WLC is genuinely the only witness available — making §5's B2 a
   *product* problem rather than a design property.

Every one is a **fidelity** question, and every one is answered by hardware, not
by more design.
