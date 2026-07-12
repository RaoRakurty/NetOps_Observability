# Service Path Graph — Frozen Domain Contract (v1.0)

**Status:** FROZEN for implementation. Changes require a version bump and a migration.
**Scope:** the LAN → SD-WAN → carrier/cloud → application RCA graph.
**Owner direction (2026-07-12):** *"Implement this as a contract-led change rather than a
demonstration-specific patch… Do not solve this by copying IP addresses into token lists."*

---

## 0. Why this exists

RCA today renders a **star**, not a path. Two independent causes:

1. **Edge admission is token-overlap based.** `engine.resolve_grounding()` admits an edge only
   when two nodes share a token, share a seam endpoint *value*, or are LLDP/BGP adjacent. Cloud
   application nodes carry **application-name** tokens (`store-api`); network and seam objects
   carry **addresses and device names**. The sets never intersect ⇒ **no cloud↔network edge can
   ever form**, regardless of how true the relationship is.
2. **There is no first-class ordered PATH object.** The renderer infers a spine from an ad-hoc
   `entity_id` containing `"->"`, and otherwise falls back to a degree-based star layout.

Widening tokens (copying IPs into the cloud node's token list) would make the demo path light up
while making the model *worse*: token overlap is a coincidence detector, not a relationship. It
cannot express validity windows, direction, NAT, or tenancy, and it silently produces false edges
whenever two tenants share an address. **This contract replaces token overlap with explicit,
ranked, time-bounded, tenant-scoped relationships.**

---

## 1. Provenance — on EVERY object in this contract

Immutable, set at creation, never rewritten:

| Field | Type | Rule |
|---|---|---|
| `tenant_id` | string | **Immutable.** Every join requires equality. Never inferred from an address. |
| `data_class` | enum | `live` \| `synthetic` \| `replay` \| `lab` |
| `environment` | string | e.g. `prod`, `lab` |
| `scenario_id` | string? | fault-injection scenario, when applicable |
| `run_id` | string? | measurement/scenario run |
| `producer_id` | string | who emitted it (prober id, collector id, connector id) |
| `provenance_id` | uuid | unique per emitted record; the evidence handle |

**Rules (binding):**
- Customer/default APIs **exclude** every record whose `data_class != 'live'`.
- `synthetic`, `replay`, `lab` evidence **can never produce a customer-confirmed verdict.** It may
  support, contradict, or illustrate — never confirm.
- **Cleanup operates on `tenant_id` + `scenario_id`/`run_id` only.** Never on naming conventions,
  IP patterns, or substring matches.

---

## 2. Entities

### 2.1 `Endpoint` — a network endpoint, tenant-scoped, time-bounded

```
endpoint_id        uuid            # stable identity of the BINDING, not of the address
tenant_id          string          # immutable
address            string          # IP
address_family     enum            # ipv4 | ipv6
network_context    string          # VRF / VPC id / VNet id / LAN segment — REQUIRED.
                                   # An address is meaningless without it (overlapping tenants).
kind               enum            # client | lan_gateway | wan_edge | nva | cloud_edge |
                                   # app_endpoint | service_endpoint | transit | unknown
resolved_entity_ref string?        # device_id | cloud_resource_id | interface_id | ""
resolution_method  enum            # see §3 ranking
confidence         enum            # authoritative | strong | candidate | unknown
valid_from         timestamp       # the binding's validity window — bindings MOVE
valid_to           timestamp?      # null = currently valid
evidence_ref       string          # provenance_id of the record that established it
+ provenance (§1)
```

An `Endpoint` is **a binding of an address to an entity, within a network context, over a time
window** — not merely an IP. The same address in two tenants is two Endpoints and they never join.

### 2.2 `PathDefinition` — the logical path being measured

```
path_id            string          # deterministic: hash(identity fields below)
tenant_id          string
src_endpoint_ref   endpoint_id
dst_endpoint_ref   endpoint_id
direction          enum            # forward | reverse
protocol           enum            # icmp | tcp | udp
dst_port           int?            # required for tcp/udp
vantage_id         string          # who measures (prober/agent id)
network_context    string
+ provenance (§1)
```

**Path identity = (`tenant_id`, `src`, `dst`, `direction`, `protocol`, `dst_port`, `vantage`,
`network_context`).** Any difference is a *different path* — a TCP:443 path and an ICMP path to the
same destination are not the same object, and must be allowed to disagree (§8).

### 2.3 `PathObservation` — IMMUTABLE, one per measurement run

```
observation_id     uuid
path_id            string
tenant_id          string
observed_at        timestamp
method             enum            # traceroute_icmp | traceroute_tcp | stamp | transaction |
                                   # flow_stitch
vantage_id         string
status             enum            # complete | partial | failed
hop_count          int
+ provenance (§1)                  # run_id REQUIRED here
```

**Every measurement run produces a NEW PathObservation.** Observations are never updated in place —
history is the point (route changes, §8). "Current path" is a *query* (latest observation per
path_id), never a mutable row.

### 2.4 `PathHop` — ordered, one row per hop

```
observation_id     uuid
hop_index          int             # 1-based, ORDERED — the spine order is DATA, not layout
state              enum            # responding | missing | filtered
observed_address   string?         # null when state != responding — the hop is PRESERVED
resolved_entity_ref string?        # device_id | cloud_resource_id | interface_id
resolution_method  enum            # §3
confidence         enum            # authoritative | strong | candidate | unknown
seam_id            string?         # seam membership, when the hop crosses/sits on a seam
rtt_ms             float?
transformation     enum            # none | nat | proxy | load_balancer |
                                   # tunnel_ingress | tunnel_egress
evidence_ref       string          # provenance_id
observed_at        timestamp
+ tenant_id (denormalized for RLS)
```

**Unknown hops are preserved.** A `missing`/`filtered` hop is a fact about the path and must render
as an explicit unknown segment — never dropped, never silently bridged.

---

## 3. Endpoint & hop resolution — RANKED (this replaces token overlap)

A relationship may be used as an **authoritative graph edge** only from ranks 1–5. Rank 6 is
*inferred/supporting*. Rank 7 is *candidate only* and may **never** create an authoritative edge.

| Rank | Method | Class | May create authoritative edge |
|---|---|---|---|
| 1 | **Immutable resource identity** (same `resource_id`) | observed | ✅ |
| 2 | **Tenant-scoped endpoint→interface/resource binding**, valid during the observation (cloud NIC/ENI inventory, agent registration, orchestration inventory, deployment metadata) | observed | ✅ |
| 3 | **Path-hop inventory resolution** (hop address resolves to a known interface/resource in this tenant + network context, within the validity window) | observed | ✅ |
| 4 | **Application→endpoint binding** (app agent registration, orchestration/deployment metadata, application telemetry that names its own listen endpoint) | observed | ✅ |
| 5 | **Flow / NAT-session stitching** (a session record ties pre- and post-translation tuples) | observed | ✅ |
| 6 | **Cloud route/resource relationship** (AWS route tables, Azure UDRs, BGP, SD-WAN policy) | **inferred** | ⚠️ supporting only — see §4 |
| 7 | **Shared tokens / reverse DNS / name similarity** | candidate | ❌ **never** |

**Binding `10.60.10.10` → the AWS application** is therefore done by rank 2 (the ENI/NIC inventory
we now discover from the AWS API says which resource owns that private IP) and rank 4 (the app's own
telemetry declares its service and host) — **not** by any token overlap between `store-api` and a
seam endpoint.

---

## 4. Observed vs inferred — kept separate, always

| Class | Sources | Use |
|---|---|---|
| **Observed (data plane)** | traceroute hops, application transactions, probe RTT/loss, flow/NAT session records | Can establish a hop, an edge, and (with an independent second observer) a **confirmed** verdict |
| **Inferred (control plane)** | AWS/Azure route tables + cloud inventory relations, BGP, SD-WAN policy | **Supporting/explanatory only.** May *predict* an edge and may *explain* an observed one. May NOT alone assert that traffic took it, and may NOT alone confirm a verdict, unless independently validated by an observation |

Example from the live lab: the AWS route table says the app subnet's `0.0.0.0/0` → the NVA's ENI.
That is **inferred** — strong, useful, renders as a supporting edge. The traceroute that shows
`10.60.1.10` as hop 3 is **observed** — that is what makes the NVA hop authoritative.

---

## 5. Edge types (explicit)

```
PATH_HAS_HOP                observation → hop            (ordered by hop_index)
HOP_RESOLVES_TO             hop         → entity/interface/resource
CROSSES_SEAM                hop/edge    → seam
TERMINATES_AT_ENDPOINT      observation → endpoint
ENDPOINT_HOSTED_ON          endpoint    → resource/host
SERVICE_EXPOSED_BY_ENDPOINT service/app → endpoint
EVIDENCE_SUPPORTS           evidence    → hypothesis/object
EVIDENCE_CONTRADICTS        evidence    → hypothesis/object
EVIDENCE_MISSING            gap         → hypothesis/object   (an honest absence is an edge)
```

Every edge carries: `evidence_ref`, `observation_method`, `confidence`, `observed_at`,
`data_class`. **An edge that cannot state its evidence is not rendered.**

---

## 6. Join rules (mandatory for every graph join)

A join between two objects is legal **only** when ALL hold:

1. **Same immutable `tenant_id`.** (No cross-tenant join, ever — §9.)
2. **Compatible time ranges** — the binding/observation windows overlap.
3. **Explicit path/endpoint membership** — the objects are related through a declared edge (§5),
   not through incidental attribute equality.
4. **Compatible network context** — same VRF/VPC/VNet/segment, or an explicitly modelled transition
   (a seam or a NAT transformation).
5. **Compatible direction/protocol** where applicable.

---

## 7. RCA API — the backend returns an ORDERED SPINE

`GET /api/rca/{correlation_id}/path` (and the path block embedded in the RCA object):

```jsonc
{
  "spine": [                       // ORDERED. The backend decides hop order — not React.
    { "index": 0, "kind": "client",       "label": "…", "address": "172.40.40.92",
      "boundary": "LAN", "entity_ref": "…", "state": "responding",
      "evidence": { "ref": "…", "method": "transaction", "confidence": "authoritative",
                    "observed_at": "…", "data_class": "live" } }
    // … lan_gateway → wan_edge → cloud_edge(NVA) → app_endpoint → application
  ],
  "edges": [
    { "from": 2, "to": 3, "type": "CROSSES_SEAM", "seam_id": "sm-…",
      "transformation": "tunnel_ingress",
      "evidence": { "ref": "…", "method": "traceroute_icmp", "confidence": "strong",
                    "observed_at": "…", "data_class": "live" } }
  ],
  "boundaries": [                  // grouping for the renderer, computed server-side
    { "name": "LAN",     "from": 0, "to": 1 },
    { "name": "SD-WAN",  "from": 2, "to": 2 },
    { "name": "CARRIER", "from": 2, "to": 3 },
    { "name": "CLOUD",   "from": 3, "to": 5 }
  ],
  "evidence_branches": [ /* metrics, logs, flows, alerts, traces attach HERE, off the spine */ ]
}
```

**Renderer contract:** the UI is a **dumb layout** of this spine. It MUST NOT compute hop order,
MUST NOT lay out from node degree, and MUST NOT fall back to a star for a path-focused RCA. If the
backend supplies no spine, the UI says so — it does not invent one.

---

## 8. Required behaviours (each is a test, §9)

- **Missing hops** preserved and rendered as explicit unknown segments.
- **Asymmetric paths**: forward and reverse are distinct `PathDefinition`s; never merged.
- **Route changes**: a new `PathObservation` per run; the spine can change between runs and the
  history is queryable.
- **Multiple vantages**: distinct `vantage_id` ⇒ distinct paths; they may agree or disagree.
- **TCP vs ICMP divergence**: distinct protocol ⇒ distinct paths; divergence is a finding, not a bug.
- **NAT / proxy / LB / tunnel**: rendered explicitly as a `transformation` on the hop/edge; the
  pre/post tuples are stitched by rank 5, never by address coincidence.
- **Stale observations**: an observation outside its freshness window is `stale` and cannot anchor a
  live verdict.
- **Unresolved endpoints**: `confidence=unknown`, rendered as unresolved — never guessed.
- **Overlapping tenant IP space**: identical addresses in two tenants never resolve to each other.
- **Synthetic-data exclusion**: `data_class != live` excluded from customer APIs.
- **Graph replay**: a `replay` run reproduces a historical graph without polluting live.

---

## 9. Tenant isolation (MANDATORY — CLAUDE.md §3a)

Two-tenant test fixture: Tenant A and Tenant B with **overlapping addresses, identical application
names, and identical path shapes**. Assert that **none** of the following ever crosses tenants:
endpoint resolution · graph edge · path observation · cache entry · cleanup operation · API response
· WebSocket event · evidence lineage · UI deep link.

Storage: PG tables carry the `tenant_iso` FORCE-RLS policy and are queried via `withTenant`;
ClickHouse tables are read with `chTenantScope`.

---

## 10. Primary acceptance case

The RCA graph for the live lab incident must render EXACTLY this ordered spine:

```
172.40.40.92 (client)
  → 172.40.40.1  (LAN gateway)
  → 10.70.245.122 (WAN edge)
  → 10.60.1.10   (AWS NVA / cloud seam)
  → 10.60.10.10  (AWS application endpoint)
  → AWS application (service)
```

…**with no shared token between the application and the seam**, and with every displayed edge
exposing its evidence reference, observation method, confidence and timestamp.

---

## 11. Versioning

`contract_version = 1`. Stamped on every emitted path object. A breaking change bumps this and
ships a migration + rollback.
