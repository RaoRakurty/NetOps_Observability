# CORRELIX Network Digital Twin — design (tracker 152)

**Status:** DESIGN — approved scope from `docs/TRACKER.md` row 152 (GA plan §3,
2026-08-16). Implementation not started; this document is the implementable spec.
**Feeds:** tracker 153 (GA scale ladder L2–L6) — the twin is the load- and
truth-generator the ladder runs against.
**Example scenario:** [`examples/twin-scenario-example.yaml`](examples/twin-scenario-example.yaml).

Every stack fact in this document (ports, topics, env vars, event shapes, signal
kinds, measured ceilings) was verified against the repo at design time; sources
are cited inline. Component names are OUR stack's — Kafka-KRaft (never Redpanda),
VictoriaMetrics + vmalert (never Prometheus), Valkey (never Redis), per
`docs/ops/OBSERVABILITY_AUDIT.md` §0 and licensing #97.

---

## 1. Goals / non-goals

### 1.1 Goals — close the "still unproven" GA list

`docs/scale/SCALE_TEST_FINDINGS.md` (2026-08-16 live-verification section) and
`CORRELIX_SCALE_TEST_REPORT.md` §8 leave exactly these unproven. Each is a twin
deliverable:

| # | Unproven today | Twin deliverable |
|---|---|---|
| G-1 | **Multi-tenant partition spread under sustained load.** The 2026-08-16 verification proved co-partitioning mechanics (2 replicas × `BUS_PARTITIONS=4`, range assignor, replica-1 = partitions [0,1], replica-2 = [2,3]) but the mini-ladder's single-tenant workload keys to ONE partition/replica by design. | A T-tenant workload whose tenant keys deterministically cover all P partitions, plus the per-replica balance measurement (§6). |
| G-2 | **RCA accuracy has no ground truth.** `correlation_e2e.py` proves the value path works (5/8 seam scenarios PASS live) but there is no labeled corpus to compute an accuracy SLO against. | The fault-story engine (§5): seeded, reproducible stories each carrying `{expected verdict, expected seam attribution}` labels; accuracy = engine output vs labels. |
| G-3 | **L2+ ladder feeds.** Tracker 153's L2–L6 levels (1k–10k+ devices, readiness plan §4) need realistic multi-protocol load; raw-text syslog injection provably generates zero signals (findings: "correlation only emits signals from events matching its structured producer patterns"). | Protocol emitters (§4) that speak the proven wire shapes at ladder rates, sharded across load hosts in T2. |
| G-4 | **Clean-slate compatibility.** Scale runs must leave the stack as found (`scripts/clean-slate.sh --verify` must still pass). | Namespaced entities (`twx-` prefix, dedicated address space) + verified teardown (§7), following the mini-ladder's proven cleanup pattern. |

Secondary goal: the twin must **compose with `scripts/scale-miniladder.py`** (the
G2 nightly harness). Division of labor: **the twin generates realistic load; the
mini-ladder judges it** (linearity, drain, accounting, memflat). The twin never
re-implements the harness's verdict logic (§8.3).

### 1.2 Non-goals

- **Perfect device emulation fidelity.** The twin emits the telemetry *shapes
  the engine detects* (§4, §5) — it is not a control-plane simulator; no real
  BGP FSM, no routing computation, no packet forwarding. Fidelity target:
  "indistinguishable to our collectors and producers", nothing deeper.
- **Hardware wireless.** Tracker 128 Phase 9 owns wireless hardware work and is
  ON HOLD by owner decision (2026-07-27). The twin does not emit
  `netops.wireless_sessions` / `netops.wireless_events` in T1; a T2 extension
  is listed as an open question (§10) and gated on that owner.
- **Being a stress-maximizer.** Raw EPS ceilings were already measured with dumb
  injection (report §4); the twin optimizes for *realism + labels*, not maximum
  rate. Where the ladder needs 250k-EPS storms, the readiness plan's dedicated
  storm tools (loggen etc., readiness §2c) remain the right instrument.
- **Production shipping.** The twin is test tooling. It never enters the product
  dependency graph, default compose profile, or the Go backend (§4.1).
- Reintroducing Redpanda / Redis / Prometheus in any role (licensing #97).

---

## 2. Two-phase delivery

### Phase T1 — single-host twin (this 4-CPU lab box, alongside the stack)

Runs on the current rig (4 vCPU / 16 GiB, ~2–3 GiB real headroom at idle per
findings' idle baseline) **without invalidating the measurement it feeds**:

- **200–500 simulated devices across 5–10 tenants** (the sweet spot where
  per-record onboarding is proven O(1) and OpenSearch/correlation stay inside
  their healthy envelope).
- Steady-state emission budget **≤ 200 EPS aggregate** (10% of the box's ~2k EPS
  healthy ingest ceiling) with story bursts **≤ 1k EPS for ≤ 2 min** (below the
  ~1k evt/s single-replica correlation ceiling × 2 replicas, so drain stays
  bounded).
- Protocols in T1: syslog, SNMP agents (discovery + 30 s polling), SNMP traps,
  IPFIX/NetFlow, simulated cloud events. gNMI targets are a T1 stretch item and
  NETCONF is T2-only (§4.6, §10).
- Fault-story engine + ground-truth emission is **fully delivered in T1** — RCA
  accuracy measurement must not wait for the rig.

### Phase T2 — rig twin (thousands of devices, VM fleet)

The readiness plan §1/§4 rig: dedicated load-generation hosts (never the stack
host — readiness §2b), external multi-broker Kafka via `BROKER_URLS`, external
ClickHouse cluster, ladder levels L2 (1k) → L5 (10k+) → L6 (break) → 72 h soak.
T2 adds: sharded snmpsim fleets, NETCONF two-tier (Netopeer2 fidelity tier +
lightweight responders, readiness §2c), gNMI target fleet, per-level workload fed
into `correlix-sizing.yaml` before each run (§9).

**T1 ⊂ T2 (strict subset, not a throwaway):** same scenario DSL, same emitters,
same story engine, same ground-truth format, same CLI. T2 changes only the
*deployment shape* (N twin workers sharded by device range, a coordinator, real
Kafka clients instead of the console-producer path) and the *scale knobs*. Every
T1 scenario file must run unmodified on T2; T2 adds fields (worker sharding,
rate multipliers) that T1 ignores. This is enforced by keeping deployment
parameters out of the scenario DSL (§3.3): scenarios describe the *network*,
CLI/env describe the *rig*.

---

## 3. Topology & tenancy model

### 3.1 Entity model

The scenario DSL declares a **topology** (tenants → sites → devices → links /
BGP sessions → seams) and **stories** that run against it.

**Device spec** (all fields serialized into the DSL, §3.3):

| Field | Meaning | Grounding |
|---|---|---|
| `name` | inventory id/name; twin prefixes it `twx-<runid>-` at registration | mini-ladder `mlx-<runid>-` precedent; enables verified cleanup |
| `tenant` | owning tenant (scenario-local alias, resolved to a real tenant id at start) | devices are registered `as_tenant` (§7.1) |
| `site` | site tag (feeds `Signal.site` semantics, groups the blast radius) | |
| `role` | `edge` \| `core` \| `spine` \| `leaf` \| `wan` | drives story templates (an ISP brownout touches `edge`, a fabric fault touches `spine/leaf`) |
| `address` | management IP from the twin's address plan (§3.4) | registered as the device address; drives source-IP attribution |
| `interfaces[]` | `{ name, speed_mbps, description, peer? }` | interface names appear verbatim in `%LINK-3-UPDOWN` text and `device_if_*` metrics — the engine builds `device:ifname` entities from them |
| `bgp_neighbors[]` | `{ peer_ip, peer_device?, asn, description }` | peer IPs appear in `%BGP-5-ADJCHANGE` text and BGP trap varbinds → `bgp_adjacency_change` entities `device:peer_ip` |
| `snmp` | `{ version: v2c\|v3, community?/usm? }` | which snmpsim flavor answers for it |
| `seams[]` | seam memberships: `{ seam_id, role }` | binds the device to declared seam instances (§3.2) |

**Links** are declared once (`{a: device:if, b: device:if}`) and expanded to both
ends — a link-down story emits the down on both sides plus the LLDP/adjacency
consequences, which is what lets the engine's topology grounding correlate them.

### 3.2 Seams — the vocabulary is owner-final

Seam semantics follow `docs/design/cloud-ingestion.md` §4.0/§4 exactly (FINAL,
owner-specified): a **seam is an ownership handoff in packet-forwarding
responsibility**; the five canonical `seam_type`s are **`DX` | `VPN` | `SDWAN` |
`DIA` | `CLOUD_BACKBONE`** (DIA displays as "ISP"). LAN (wired *and* wireless)
is a **domain, not a seam** — no seam rows for it; TGW/VGW/NVA/NAT/LB are
instrumentation *on* seams, never seam types.

The DSL's `seams:` block declares seam instances in the platform's unified seam
object shape (`seam_id`, `seam_type`, members with roles) and the twin registers
them through the real API (`/api/seams`, `/api/seams/groups` —
`src/backend/main.go:1827-1830`) so the engine's seam views load through the
production enrichment path (`SEAM_ENRICHMENT_FILE` →
`/data/enrichment/seams.json`, `src/correlation/main.py:840`). **Seam
attribution ground truth (§5) is expressed against these declared seams** —
`expected_seam: {seam_id, seam_type, owner}` — matching the RCA product rule
that ownership is seam-level, never a generic "NOC".

### 3.3 Scenario DSL

Declarative YAML, one file per scenario. Top-level keys:

```yaml
twin: 1                # DSL schema version (integer, strict)
meta: { name, description, seed }
tenants: [...]         # scenario-local tenant aliases + partition-spread intent
sites: [...]
devices: [...]         # §3.1 spec
links: [...]
seams: [...]           # §3.2
baseline: {...}        # steady-state emission profile (rates per protocol)
stories: [...]         # §5 fault stories with ground-truth labels
```

Rules:
- **No rig/deployment parameters in the DSL** (worker count, broker addresses,
  EPS multipliers are CLI/env) — this is what keeps T1 files valid on T2.
- **Unknown top-level or story-step keys are a hard parse error** (zero-trust on
  our own inputs; a typo'd label must never silently weaken ground truth).
- Deterministic expansion: `(scenario, seed)` fully determines every emitted
  event's content and relative timing. Absolute time is anchored at story start.
- JSON-schema for the file ships with the twin (§8.2) and validates in CI.

The complete worked example (3 tenants, 11 devices, one DX story + one negative
control) is [`examples/twin-scenario-example.yaml`](examples/twin-scenario-example.yaml).

### 3.4 Address plan & network fidelity

Tenant attribution in Vector is registry-driven: the API exports
`device_tenant.csv` (one row per device NAME and per ADDRESS) and both Vector
instances stamp `.tenant_id` from hostname/IP lookups (findings, "RESOLVED:
tenant tagging"); goflow2 flows are re-keyed from `sampler_address`
(`vector-router/vector.yaml` `flows_rekey`); the trap receiver attributes by
source-IP/sysName/agent-addr (producers.py G2a note). Two fidelity modes:

- **`source_ip` (T1 default, full fidelity):** a dedicated compose overlay
  network `twinnet` with subnet **`198.19.0.0/16`** (inside RFC 2544 benchmark
  space `198.18.0.0/15`, unroutable — mini-ladder precedent — but disjoint from
  the mini-ladder's own `198.18.x.y` allocations so both can run on one stack).
  The twin container (alone) gets `CAP_NET_ADMIN` and adds one IP alias per
  simulated device; sockets bind per-device, so syslog source-IP, trap
  agent-addr, SNMP-poll target and IPFIX `sampler_address` are all genuinely
  per-device. The overlay attaches `api`, `syslog-ng`, `goflow2` (and `gnmic`
  when the stretch item lands) to `twinnet` alongside the twin.
- **`hostname` (fallback):** no extra network; attribution rides the per-NAME
  CSV rows (syslog `hostname`, trap `sysName` varbind). Proven by the
  mini-ladder burst path; loses flow-sampler and source-IP realism.

---

## 4. Protocol emitters

Ground rule (findings, "Correlation SIGNAL GENERATION — test-realism gate"): the
engine emits signals **only** from producer-recognized shapes. Every emitter
below therefore states (a) the real intake it targets, (b) the exact wire shape,
(c) the recognized signatures it exercises — all verified in the repo.

### 4.0 Detected-signature inventory (what stories may claim)

From `src/correlation/producers.py` / `episodes.py` / `cloud_producers.py` —
stories are **forbidden** from depending on any signature not in this table:

| Lane | Recognized input | Signal kind |
|---|---|---|
| syslog | `%LINK-…-UPDOWN` / `%LINEPROTO-…-UPDOWN` tag + `Interface <if> … state to down/up` | `link_state_change` (entity `device:if`) |
| syslog | `%BGP-…-ADJCHANGE` / `%OSPF-…-ADJCHG` + peer IP + up/down keywords | `bgp_adjacency_change` / `ospf_adjacency_change` (peer-scoped) |
| syslog | `isisAdjacencyChange` (SR Linux, nil appname) / `%CLNS-5-ADJCHANGE` | `isis_adjacency_change` |
| syslog | LLDP neighbor add/remove; STP TC; VTEP; EVPN MAC move; FHRP; MAC flap | `lldp_neighbor_change`, `stp_topology_change`, `vtep_state_change`, `evpn_mac_move`, `fhrp_state_change`, `mac_flap` |
| syslog | optics/DOM pattern table (~line 977): `RX_POWER_LOW`, `TEMP_HIGH`, `BIAS_HIGH`, FEC uncorrectable, pre-FEC BER, `LOCAL_FAULT`/`REMOTE_FAULT`, deskew, hi-BER, LOS, transceiver flap/unqualified | optics/DOM signal family (per-pattern kinds, e.g. `pcs_local_fault`) |
| syslog | any severity ≥ floor with recognized envelope, unmatched | `device_alarm` (generic, still correlatable) |
| trap | `linkDown`/`linkUp` OIDs (+ ifName/ifDescr/ifIndex varbinds) | `link_state_change` |
| trap | `coldStart`/`warmStart` | `device_restart` |
| trap | BGP4-MIB backward/established (+ legacy OIDs; vendor `event_type` fallback) | `bgp_adjacency_change` |
| trap | unclassified but MIB-severity ≥ floor | `device_alarm` |
| metrics | `signal_family: device_resource` stream — CUSUM needs **≥ 20 baseline samples then a sustained step** (`episodes.py`; `correlation_e2e.cpu_stream` uses 26 + 10) | `device_resource_anomaly` |
| metrics | canonical families from `collectors/metric_events.go` (`device_if_oper_status`, `device_if_in/out_octets/errors/discards`, `device_if_fcs_errors`, `device_bgp_peer_state`, …) | interface / bgp / device_resource telemetry evidence |
| probes | probe events with `loss_pct`, `probe_intent`, `vantage_type` | `probe_loss` (lab intent/vantage → `probe_authority: debug_only`, never customer RCA) |
| cloud | `kind ∈ CLOUD_KINDS` (`cloud_producers.py`): `cloud_bgp_session_down/up`, `cloud_bgp_flap`, `cloud_route_count_drop`, `cloud_vpn_tunnel_down/up`, `cloud_vpn_packet_drop`, `cloud_physical_link_down`, `cloud_link_error`, `cloud_nat_port_exhaustion`, health/metric/flow/dns/waf kinds, … | corresponding cloud signal (explicit `tenant_id` required — cloud events have no device to infer from) |

Guardrail behaviors the stories may (and do, §5.8) assert: metric events older
than `METRIC_MAX_AGE` (3600 s) are dropped; duplicate events dedupe on
deterministic `native_id`; unrelated same-window entities never merge
(no temporal-only correlation) — all live-proven by `correlation_e2e.py`.

### 4.1 Where the twin lives (dependency-rule decision)

CLAUDE.md §6's allowlist governs the **product Go dependency graph** — its
purpose is a clean offline build and minimal product attack surface. The twin is
a **test tool** and must not move that surface. Decision:

- Code at **`scripts/lab/twin/`** with its **own Dockerfile + pinned
  `requirements.txt`** — the exact precedent of
  `scripts/lab/traffic-generator/` (own Dockerfile/requirements) and
  `scripts/lab/flowgen/` (stdlib generator + compose overlay).
- Launched only via a compose **overlay** `deployment/docker/docker-compose.twin.yml`
  (mirroring `docker-compose.flowgen.yml`): `docker compose -f docker-compose.yml
  -f docker-compose.twin.yml up -d twin`. Never in the base file, never in a
  default profile, never in `install.py`'s bring-up.
- Third-party Python deps allowed **inside the twin container only**, pinned by
  hash: `snmpsim-lextudio` (SNMP agents, §4.3) and — T2 only — a Kafka client
  for rate (§4.7). **Nothing enters `go.mod`, product images, or the runtime
  compose graph.** Offline posture: `pip download` wheels are cached in-repo
  or on the rig, matching the offline-build spirit of §6 without amending the
  product allowlist (no amendment is needed because the product graph is
  untouched).

### 4.2 Syslog

- **Intake (verified):** host `:5514` and `:514` (UDP+TCP) → `syslog-ng` (container
  `:514`) → RFC5424 forward → `vector-aggregator` TCP `:6601` → Kafka
  `netops.syslog` (keyed `__key` = tenant, Java-murmur2). TLS variant: the
  syslog-ng→aggregator hop is mesh-mTLS (`compose.tls.yml` swaps in
  `syslog-ng-tls.conf`; aggregator `:6601` requires a mesh client cert). The
  device→syslog-ng edge stays plain UDP/TCP syslog in both variants — the twin
  therefore always emits standard syslog to `syslog-ng:514` (via `twinnet`) or
  host `:5514`, with **per-device source IPs** in `source_ip` mode.
- **Wire shape (proven):** the mnemonic rides as the RFC5424 **APP-NAME/tag**
  (e.g. tag `LINK-3-UPDOWN`), message text carries the Cisco/EOS/SR Linux body —
  the exact shapes documented in `producers.py` (§4.0) and used by
  `correlation_e2e.syslog()` and the mini-ladder's `_syslog_event`. Free-text
  without the tag generates nothing (measured), so the emitter refuses to send
  untagged control-plane events.
- Rates: per-device baseline chatter (low-sev `device_alarm`-class lines) +
  story-driven control-plane events.

### 4.3 SNMP agents (discovery + polling)

- **Intake (verified):** the Go backend's SNMP collectors poll registered
  devices on `:161` every **30 s** (`collectors/snmp.go`: `snmpv2c`/`snmpv3`
  pollers), emit canonical `MetricEvent`s (families in `metric_events.go`) to
  `vector-aggregator :8690` (HTTP Basic, `INGEST_TOKEN_METRICS`, ndjson) →
  `netops.metrics`, and remote-write the full sample set to VictoriaMetrics.
  Subnet discovery (`ENABLE_SNMP_DISCOVERY`, live config store
  `DISCOVERY_CONFIG_FILE`) can discover the twin's `198.19.0.0/16` range once an
  operator narrows the scan CIDR to it.
- **Engine choice — honest evaluation:**
  - *snmpsim (snmpsim-lextudio)* — real BER/USM wire behavior, recorded-walk
    data files, v2c + v3 (auth/priv), maintained; the readiness plan §2c already
    recommends it sharded. Cost: a Python dependency + per-process memory
    (mitigated by sharding: one process serving ~125 agents × 4 processes at
    T1's 500 devices).
  - *Custom lightweight UDP responder* — zero deps, but hand-rolls ASN.1/BER
    framing and, worse, SNMPv3 USM auth/priv **crypto** — exactly the
    error-prone wire/crypto code CLAUDE.md §6 exists to keep out. Rejected for
    v3; not worth building for v2c alone.
  - **Decision: snmpsim-lextudio, pinned, twin-container-only** (§4.1). If T2
    profiling shows snmpsim can't hold the poll rate at 10k agents, the
    readiness plan's fallback (a small Go responder, still outside the product
    tree) is the named escape hatch — a T2 decision, not a T1 one.
- Data files are generated from the scenario (ifTable/ifXTable rows from
  `interfaces[]`, HC counters advancing per the baseline profile, sysName =
  device name for trap-fallback attribution).

### 4.4 SNMP traps

- **Intake (verified):** host UDP `:162` → api container `:1162`
  (`collectors/snmptrap.go`, active when `FEATURE_SNMP_TRAPS=true`) → decoded
  JSON POST to `vector-aggregator :8688` (`INGEST_TOKEN_TRAPS`) →
  `netops.snmptrap`. The receiver performs G2a attribution
  (source-IP / sysName / agent-addr against inventory); an unattributed trap
  stays searchable but **never becomes an RCA signal** — so the twin must send
  from registered device addresses (`source_ip` mode) or carry the device's
  sysName varbind (`hostname` mode).
- Twin sends real v2c/v3 traps (via snmpsim's notification originator or the
  pysnmp API underneath it — same pinned dependency, no new module):
  `linkDown`/`linkUp` with ifName/ifDescr varbinds, `coldStart`/`warmStart`,
  BGP4-MIB backward/established with peer-address varbinds (§4.0 trap rows).
  v2c traps are recorded `authenticated=false` and weighted accordingly by the
  engine (producers.py) — stories that need trustworthy trap evidence use v3.

### 4.5 IPFIX / NetFlow

- **Intake (verified):** goflow2 listens `netflow://:2055` (v5/v9),
  `netflow://:4739` (IPFIX), `sflow://:6343`; produces JSON to Kafka topic
  **`netops.flows.raw`** (native kafka transport, snappy); `vector-router`'s
  `flows_rekey` re-keys byte-identical payloads onto **`netops.flows`** with
  `__key` = tenant looked up from `sampler_address` in the device_tenant
  registry (miss → `"global"`).
- **Emitter:** extend the in-repo, stdlib `scripts/lab/flowgen/flowgen.py`
  (already speaks NetFlow v5, IPFIX RFC 7011 with template 256, sFlow v5,
  overlay-composed onto goflow2's listeners) into the twin: per-device exporter
  state (sequence numbers, uptime), `sampler_address` = the device's twin IP,
  flow mix derived from the scenario's links + story steps (e.g. a DX story
  shifts flow next-hops off the failed path). This is reuse of a proven
  in-house generator, not a new dependency.

### 4.6 gNMI (T1 stretch) and NETCONF (T2 only)

- **Reality (verified):** `gnmic` is **dial-in** — it subscribes to targets
  statically listed in `deployment/docker/gnmic/gnmic.yaml` (SR Linux `:57400`
  TLS, cEOS `:6030` insecure; subscriptions: interface counters/oper-status
  sampled 30 s, BGP `session-state` on-change, …) and remote-writes to
  VictoriaMetrics (`VICTORIA_WRITE_URL`, vmauth-fronted on the TLS variant).
  gNMI feeds the **metrics store**, not the correlation lane directly.
- **T1 stretch:** the twin renders an additional gnmic targets file for its
  devices; the operator merges it (gnmic has no dynamic target discovery in our
  pinned config). Serving gNMI requires a target-side gRPC server —
  readiness §2c names the two options (gnmic target mode vs a small OpenConfig
  fake). **Decision deferred to implementation** with a hard boundary: whatever
  serves gNMI lives in the twin container. T1 ships without it; no story in §5
  depends on gNMI evidence (link/BGP stories are proven on syslog+trap+metric
  evidence alone).
- **NETCONF:** collector exists (`collectors/netconf.go`, 120 s `:830` banner
  probe). Full NETCONF emulation (Netopeer2 tier + lightweight responders) is
  T2 per readiness §2c; T1 twin devices simply don't advertise NETCONF.

### 4.7 Cloud events

- **Intake (verified):** topic `netops.cloud`. Producers today: the
  profile-gated `cloud-ingest` service (fixtures under
  `deployment/docker/cloud-fixtures/{aws,azure,gcp}[-topology].json`, runtime
  output dir `CLOUD_RUNTIME_OUT`) and the aggregator's cloud lanes. Events must
  carry `kind ∈ CLOUD_KINDS` and an **explicit `tenant_id`** (cloud events have
  no device for registry inference — findings' 3,000-event experiment consumed
  clean but stored 0 precisely because tenant was empty).
- **T1 decision — simulated-only:** the twin produces labeled cloud seam events
  (`cloud_bgp_session_down`, `cloud_route_count_drop`, `cloud_vpn_tunnel_down`,
  …) directly onto `netops.cloud`, tenant-stamped, representing the provider
  side of declared DX/VPN/CLOUD_BACKBONE seams. Live-provider stories (real
  AWS/Azure/GCP accounts through `cloud-ingest`) are **blocked on the owner
  credential decisions O1–O4** (§10) and are additive when they land — the story
  format doesn't change, only the transport.
- **Bus-direct transport (also used for probe events):** T1 reuses the
  **proven** injection path — the embedded broker's console producer
  (`docker exec kafka kafka-console-producer.sh`, `--producer.config` SSL
  client config on the TLS variant) exactly as `correlation_e2e.py` and the
  mini-ladder do. Zero new credentials, adequate for T1 rates. T2 replaces it
  with a pinned Kafka client in the twin container + a provisioned mesh SVID,
  keyed identically (tenant key, Java-murmur2 — the partitioner contract every
  producer on this bus must honor, per the goflow2/vector comments).
- Probe events (story corroboration) use the `correlation_e2e.probe()` shape on
  `netops.probes`: customer stories set `probe_intent: customer_path`,
  `vantage_type: public_cloud_agent`; negative-control stories use `lab_test` /
  `local_container` and must stay `debug_only`.

---

## 5. Fault-story engine

A **story** is a scripted, seeded, reproducible event sequence with labeled
ground truth. Story spec (DSL `stories[]`):

```yaml
- id: dx-flap-1
  template: dx_circuit_flap          # one of §5.1–§5.10
  trigger: { at: "+120s" }           # offset from run start; or cron/manual
  affected: { seam: dal-dx-1, devices: [edge-a1], tenants: [acme] }
  params: { flap_count: 3, hold_s: 45 }
  expect:                            # THE GROUND TRUTH LABEL
    rca:
      verdict_tier_at_least: suspected      # suspected | confirmed
      hypothesis_matches: "private-interconnect|interconnect-bgp"  # regex over top_hypothesis
      affected_includes: [edge-a1]
      single_incident: true                 # cascade folds to ONE object
    seam:
      seam_id: dal-dx-1
      seam_type: DX
      owner: carrier                        # seam-level ownership, never "NOC"
    forbid:
      cross_tenant_merge: true              # no object may span tenants
      confirmed: false                      # (only on stories that must NOT confirm)
```

**Accuracy is computable because both sides are machine-readable:** the scorer
(§8.4) joins `netops.corr_objects_latest` (`verdict_tier`, `top_hypothesis`,
`top_confidence`, `node_count`, `affected` — the columns `correlation_e2e.py`
already validates) against `expect` blocks. Story PASS = every `expect` clause
holds and no `forbid` clause fires; **RCA accuracy SLO = passing stories /
total stories**, reported per template and per seam type. Entities are
run-tagged by naming (`twx-<runid>-…`), the same isolation trick as
`correlation_e2e` (`corr_signals` has no test-run column).

### Story templates (all grounded in §4.0 signatures — nothing invented)

1. **`link_down_cascade`** — `%LINK-3-UPDOWN` + `%LINEPROTO-5-UPDOWN` on both
   link ends, `linkDown` trap, LLDP neighbor-removed on peers, downstream
   `%BGP-5-ADJCHANGE` Down on sessions riding the link, `probe_loss ≥ 80%` on
   the customer path. Expect: ONE suspected/confirmed incident rooted at the
   link (the e2e scenario-1 shape), not N per-symptom incidents.
2. **`bgp_flap`** — repeated `%BGP-5-ADJCHANGE` Down/Up (`Hold timer expired`) +
   BGP4-MIB backward/established traps + partial `probe_loss` (~40%). Expect:
   routing/bgp hypothesis (e2e scenario-3 shape); seam attribution when the
   peer is a declared seam member.
3. **`dx_circuit_flap_cloud_withdrawal`** — the two-sided seam story: on-prem
   edge `%BGP-5-ADJCHANGE` Down toward the DX peer + v3 BGP trap, **plus**
   provider-side `cloud_bgp_session_down` + `cloud_route_count_drop` on
   `netops.cloud` (same tenant), + hybrid-path `probe_loss`. Expect: ONE
   private-interconnect root cause (`sig.ent.middle-mile.private-interconnect-bgp-down`
   / `-missing-prefix` family in the catalog), seam_type `DX`, owner `carrier`
   — the readiness plan's "one root cause, not N" GA behavior, now labeled.
4. **`isp_brownout_multi_tenant`** — DIA seam: sustained `probe_loss`/latency
   from several tenants' edge devices toward SaaS targets, **no** device-fault
   syslog. Expect per-tenant: DIA/ISP-side attribution (displayed "ISP");
   forbid: any single object spanning tenants (isolation is the SLO's
   zero-leak clause) — this story doubles as the noisy-seam isolation probe.
5. **`cpu_exhaustion`** — `device_resource` metric stream: ≥ 26 baseline
   samples then sustained ~98% step (the proven CUSUM shape). Base variant
   expects `device_resource_anomaly` as **contributor only** (no multi-node
   incident — e2e scenario-2); the `with_impact` variant adds control-plane
   syslog from the same device and expects promotion to an incident.
6. **`optics_degradation`** — DOM syslog ramp (`RX_POWER_LOW` → pre-FEC BER →
   `LOCAL_FAULT`) + `device_if_fcs_errors` metric events + terminal
   `%LINK-3-UPDOWN`. Expect: optics-layer hypothesis on the interface entity,
   not a generic link story.
7. **`device_restart`** — `coldStart` trap + emission silence for the reboot
   window + interface-up storm on return. Expect: `device_restart`-rooted
   single incident; forbid: per-interface incident spray.
8. **`vpn_tunnel_down`** — VPN seam: `cloud_vpn_tunnel_down` (+
   `cloud_vpn_packet_drop`) on the provider side + `%BGP-5-ADJCHANGE` Down for
   the overlay session + both-end `probe_loss`. Expect: VPN seam attribution.
9. **`negative_debug_probe`** (guardrail control) — lab-intent probe storm
   (`probe_intent: lab_test`, `vantage_type: local_container`). Expect:
   signals carry `probe_authority: debug_only`; forbid: any confirmed
   customer-facing object (e2e scenario-5).
10. **`negative_unrelated_concurrency`** (guardrail control) — the e2e
    scenario-6 shape across **different tenants**: CPU step on tenant A, probe
    loss on tenant B, BGP down on tenant C, same window. Forbid: any merged
    object; this is the labeled false-correlation floor for the accuracy SLO.

Stories 9–10 count toward accuracy as **specificity** (a false-positive there is
an accuracy failure exactly like a miss on 1–8).

---

## 6. Multi-tenant proof workload (closing G-1)

What must be proven (findings, "Still unproven"): **partition spread under
sustained multi-tenant load** — i.e. R correlation replicas each sustain their
share when T tenants key across P partitions.

Mechanics (all live-verified 2026-08-16): `kafka-init` sizes every `netops.*`
topic to `BUS_PARTITIONS` (=4 on the lab stack); every producer keys by tenant
with Java-compatible murmur2; the consumer group uses the range assignor so each
replica owns the **same partition set across all 12 topics** (replica-1 [0,1],
replica-2 [2,3]); `/healthz` exposes the assignment (`CONSUMER_ASSIGNMENT`) and
`tenant_verification.registry_identities`, and the engine logs
`CO-PARTITIONING BROKEN` if per-topic sets diverge.

Twin workload design:

1. **Tenant→partition placement is computed, not hoped for.** At scenario start
   the twin computes `murmur2(tenant_key) mod P` for each scenario tenant
   (the same hash contract the bus uses) and **fails fast** unless the tenant
   set covers every partition 0..P-1; the example scenario's 3 tenants are
   chosen this way for P=4 ≥ min-coverage, and the spread workload uses
   T ≥ 2P tenants for per-partition pairs.
2. **Sustained balanced load:** baseline emission per tenant is equal by
   construction, so expected per-replica consumption ≈ (tenants on its
   partitions / T) of total EPS. Run length ≥ 30 min at T1 (≥ ladder-level
   window at T2).
3. **Measurement:**
   - per-replica `/healthz` → owned partitions + failure counters (the
     mini-ladder's `corr_healthz()` accessor already reads this);
   - per-partition consumed offsets over time via the broker's
     `kafka-consumer-groups.sh --describe` (the mini-ladder's proven lag
     tooling) → per-replica consumed-rate series;
   - **balance gate:** over the steady window, each replica's consumed share
     within ±20% of its expected share, no partition starved, and lag on every
     partition drains to baseline after emission stops (the mini-ladder drain
     gate, now exercised on ALL partitions instead of one).
   - **isolation cross-check:** story 10 runs concurrently; per-tenant
     ClickHouse counts (`SETTINGS tenant_scope='__all__'` from the ops catalog)
     confirm every signal landed under its own tenant.

This turns the 2026-08-16 "mechanics proven, spread unproven" note into a
repeatable PASS/FAIL measurement on both T1 and T2.

---

## 7. Lifecycle

### 7.1 Start (production-path registration — like the mini-ladder, more so)

1. **Preflight:** stack healthy (reuse the mini-ladder's watchdog-style checks);
   verify `BUS_PARTITIONS`/replica count matches the scenario's spread intent;
   refuse to start if a previous `twx-` namespace survives (stale-run guard).
2. **Tenancy:** resolve scenario tenant aliases to real org/tenant ids —
   created via the admin API if absent (the findings' proven org+tenant flow).
3. **Devices:** `POST /api/devices` per device **acting into its tenant**
   (`as_tenant` query param / `X-Acting-Tenant` header, `src/backend/tenancy.go`;
   TenantID is stamped from the effective principal per §3a — never the body),
   names `twx-<runid>-…`, addresses from §3.4. This drives the O(1) per-record
   store and regenerates `device_tenant.csv` → Vector auto-reloads → enrichment
   and tenancy flow the production path.
4. **Registry gate:** wait until correlation `/healthz`
   `tenant_verification.registry_identities` ≥ baseline + created-count (the
   mini-ladder's Gate-1, verbatim) — else every event tenant-refuses into the
   DLQ.
5. **Seams:** register scenario seams via `/api/seams` (+ groups) and wait for
   the engine's seam-enrichment reload.
6. **Agents up:** snmpsim shards bound to per-device IPs; flow exporters armed;
   baseline emission starts; canary event proves the pipe (mini-ladder pattern)
   before any story fires.

### 7.2 Run / stop / reset

- Stories fire on their triggers; every emitted event is journaled to the run
  dir (`events.jsonl`) with its story id — the emission-side half of accounting.
- `twin stop` = stop emission, keep entities (for post-hoc API/UI inspection).
- `twin reset` = **verified teardown**, ALWAYS runnable (also after crash/^C,
  the mini-ladder cleanup contract): delete every `twx-<runid>-` device via the
  API and verify zero remain; delete twin-created seams/tenants (only those the
  run created); purge run-tagged telemetry from ClickHouse (`corr_signals`
  et al. by entity LIKE) and OpenSearch syslog indices; drop IP aliases. Exit
  criterion: **`scripts/clean-slate.sh --verify` passes** on a stack that was
  clean before the run.

---

## 8. Interfaces

### 8.1 CLI

```
twin up      --scenario FILE [--runid X] [--fidelity source_ip|hostname]
twin run     --scenario FILE [--story ID|--all] [--speed 1.0]
twin status  [--runid X]           # emission rates, story phase, gate states
twin stop    [--runid X]
twin reset   [--runid X] [--force]
twin verify  --scenario FILE       # schema + partition-coverage + signature lint (no stack access)
```

Same binary/entrypoint at T1 and T2; T2 adds `--role coordinator|worker
--shard i/N` (deployment shape only, §2). Credentials follow the mini-ladder
contract: never on argv, read from `MLX_ADMIN_*`/`ADMIN_*` in
`deployment/docker/.env`; OpenSearch/broker access via in-container exec with
config-on-stdin (the ops-catalog idiom).

### 8.2 Scenario schema (JSON-schema sketch)

```json
{ "$id": "correlix.twin.scenario.v1",
  "type": "object", "additionalProperties": false,
  "required": ["twin", "meta", "tenants", "devices", "baseline"],
  "properties": {
    "twin":   { "const": 1 },
    "meta":   { "type": "object", "required": ["name", "seed"],
                "properties": { "name": {"type": "string"},
                                "description": {"type": "string"},
                                "seed": {"type": "integer"} } },
    "tenants":{ "type": "array", "minItems": 1, "items": { "type": "object",
                "required": ["alias"], "properties": {
                  "alias": {"type": "string"}, "org": {"type": "string"},
                  "partition_pin": {"type": "integer"} } } },
    "sites":  { "type": "array", "items": {"type": "object"} },
    "devices":{ "type": "array", "minItems": 1, "items": { "type": "object",
                "required": ["name", "tenant", "role", "interfaces"],
                "properties": {
                  "name": {"type": "string"}, "tenant": {"type": "string"},
                  "site": {"type": "string"},
                  "role": {"enum": ["edge","core","spine","leaf","wan"]},
                  "interfaces": {"type": "array"},
                  "bgp_neighbors": {"type": "array"},
                  "snmp": {"type": "object"},
                  "seams": {"type": "array"} } } },
    "links":  { "type": "array" },
    "seams":  { "type": "array", "items": { "type": "object",
                "required": ["seam_id", "seam_type"],
                "properties": { "seam_type":
                  {"enum": ["DX","VPN","SDWAN","DIA","CLOUD_BACKBONE"] } } } },
    "baseline": { "type": "object" },
    "stories":  { "type": "array", "items": { "type": "object",
                "required": ["id", "template", "trigger", "affected", "expect"] } }
  } }
```

(`twin verify` additionally lints: every story template is one of §5.1–.10;
every referenced device/seam/tenant exists; tenant keys cover partitions.)

### 8.3 Mini-ladder composition

The mini-ladder gains a **future** `--load-generator twin --twin-scenario FILE`
flag: its burst phase delegates emission to `twin run` instead of its internal
`_syslog_event` loop, while **preflight / onboard-linearity / drain /
accounting / memflat / cleanup verdicts stay the mini-ladder's** (the twin
reports exact emitted counts per lane in `twin-report.json`, which the
accounting phase consumes as the "injected" side of its
injected == persisted + DLQ + counted-loss balance). Until that flag lands,
the two tools already coexist: disjoint prefixes (`mlx-`/`twx-`) and disjoint
address blocks (§3.4).

### 8.4 Outputs (report + ground truth for the scorer)

Per run dir (`data/twin/<runid>/`, gitignored like `data/miniladder/`):

- `events.jsonl` — every emitted event: `{ts, lane, topic/intake, story_id?,
  device, payload_digest}`.
- `ground_truth.jsonl` — one record per story instance: the full `expect`
  block + fired-at timestamps + involved entities (the label file).
- `twin-report.json` — machine-readable run summary: per-lane emitted counts
  (for mini-ladder accounting), gate outcomes, partition-coverage map,
  per-tenant EPS.
- `accuracy-report.{json,md}` — from `twin score`: per-story verdict join
  against `corr_objects_latest`/`corr_signals`, the accuracy SLO number, and
  the per-seam-type breakdown. This artifact is the tracker-152 "RCA-accuracy
  SLO" evidence and the input tracker 153's ladder gates cite.

---

## 9. Sizing & phasing

### 9.1 T1 on this box (derived from measured footprints)

Budget principle: the twin must fit inside the **~2–3 GiB / ~1.5-core real
headroom** the findings measured on the idle stack (5.5/15.6 GiB used, OpenSearch
the tightest container), while keeping total ingest inside the healthy envelope
(≤ 2k EPS; correlation 2 × ~1k evt/s ceilings).

| Component | T1 budget | Basis |
|---|---|---|
| twin orchestrator + emitters (syslog/flows/traps/bus) | ≤ 0.5 CPU, ≤ 256 MiB | flowgen precedent (stdlib UDP writers are cheap); event build is string work |
| snmpsim shards (4 × ~125 agents) | ≤ 0.5 CPU, ≤ 512 MiB total | poll load is 500 dev / 30 s ≈ 17 poll/s against pre-baked walk data |
| headroom left for the stack under story load | ≥ 1 GiB | OpenSearch idles at 62% of its 3.69 GiB cap — the first thing T1 must not squeeze |
| **workload** | 200–500 devices, 5–10 tenants, ≤ 200 EPS steady, ≤ 1k EPS ≤ 2 min bursts | §2 rationale; onboarding at proven ~100 dev/s O(1) rate finishes in seconds |

Enforced, not hoped: the overlay sets `mem_limit`/`cpus` on the twin service
(every neighbor in `docker-compose.yml` does), and `twin up` refuses scenarios
whose computed steady EPS exceeds the budget unless `--force`.

### 9.2 T2 rig (readiness plan §4, translated to OUR components)

Ladder levels and rigs are the readiness plan's, with the component mapping the
tracker mandates (Kafka not Redpanda, Valkey not Redis, VictoriaMetrics not
Prometheus):

| Level | Devices | Twin shape | Stack rig (scale-report §7) |
|---|---|---|---|
| L2 | 1,000 | 1 load host, 1 twin worker, 8 snmpsim shards | 16 vCPU / 64 GiB single host |
| L3 | 2,500 | 1–2 load hosts, sharded workers | 24 vCPU / 96 GiB |
| L4 | 5,000 | 2 load hosts, worker per host | 32 vCPU / 128 GiB, storage tiers split |
| L5 | 10,000+ | coordinator + N workers, real Kafka clients (§4.7), external multi-broker Kafka via `BROKER_URLS` | clustered per report §7 (OpenSearch 3+ data nodes; correlation ~1 instance per 1k sustained evt/s; CH keeper+replicas) |
| L6/soak | to break / 72 h | L5 shape + story schedules | GA cluster |

Before each level: feed the level's workload into `correlix-sizing.yaml`
(`install.py --replan --sizing-file`) — the readiness plan's standing rule.
Load hosts are always separate from the stack host so twin CPU never pollutes
the measurement (readiness §2b).

---

## 10. Risks & open questions

| # | Item | Owner decision needed? |
|---|---|---|
| R-1 | **Cloud creds O1–O4:** live-provider stories (real AWS/Azure/GCP via `cloud-ingest`) vs T1's simulated-only `netops.cloud` events. Simulated-only is fully sufficient for the RCA-accuracy SLO (the engine sees identical kinds); live accounts add provider-API realism (throttling, Health lanes) for T2 §27–40. | **Yes** — account provisioning + credential custody (readiness §2b names ≥3 accounts/subs/projects per provider). |
| R-2 | **gNMI target server** (§4.6): gnmic-target-mode vs minimal OpenConfig fake; and gnmic's static target file means twin targets need a config merge step. | No — implementation decision inside the twin boundary; T1 ships without it. |
| R-3 | **snmpsim rate ceiling at L5** (10k agents): may need the readiness plan's Go-responder fallback. Measure at L2 before betting L5 on it. | No — pre-named escape hatch, still outside the product tree. |
| R-4 | **`source_ip` mode mechanics** (per-device aliases on a `198.19.0.0/16` overlay network + attaching api/syslog-ng/goflow2 to it) is new compose surface; the `hostname` fallback keeps every story runnable if it fights back. | No. |
| R-5 | **Accuracy-SLO target number** (what % of stories must pass for GA). The twin produces the measurement; the target itself is a product call (readiness §5 SLO table has no RCA-accuracy row yet). | **Yes** — ratify alongside the §5 SLO table. |
| R-6 | **Wireless lanes** (`netops.wireless_*`): excluded per tracker 128 Phase 9 hold; revisit only on that owner's go. | Blocked on 128 owner. |
| R-7 | **Story/catalog drift:** producers/catalog evolve; a story could silently assert a retired hypothesis id. Mitigation: `twin verify` lints `hypothesis_matches` patterns against the live catalog export, and the accuracy report marks "no-such-hypothesis" as scenario rot, not engine failure. | No. |
| R-8 | **Two-generator collisions:** twin + mini-ladder on one stack are namespace-disjoint (§8.3), but concurrent heavy runs on the 4-CPU box can still breach the EPS envelope — the nightly cron and twin schedules must not overlap on T1 (documented operational rule; T2 rigs make it moot). | No. |
