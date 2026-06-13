<!--
  Deep-research report: telemetry-collection baseline (SNMP/NMS correctness).
  Provenance: deep-research run wf_e22a0959-745 (2026-06-12, 103 agents, rate-limit
  killed verification+synthesis) + continuation wf_6e232ed2-e26 (2026-06-13,
  55 agents): 25/25 claims adversarially verified (18 re-verified after abstention),
  0 refuted. Companion: the gNMI normalization research (separate run) and the
  single-contract normalization layer in deployment/docker/gnmic/gnmic.yaml.
-->
# Telemetry-Collection Baseline for a Self-Hosted Multi-Vendor NMS — Best Practice & Validation Report

> Evidence tiers used below: **[confirmed]** = adversarially verified claim against a primary source (RFC, official docs, project README); **[primary]** = fetched/cited primary source; **[thin]** = blog/forum-grade or unverifiable source — flagged honestly where used. One listed source (Prometheus remote-write backpressure blog) returned HTTP 403 and could not be verified; statements in §5 on backpressure rest on general bounded-queue principles and the verified dead-man's-switch/absent-alerting sources, and are marked accordingly.

## Executive verdict

The architecture under review — curated per-vendor OID profiles selected by `sysObjectID`, gNMI streaming, goflow2 flows, STAMP/synthetics/traceroute active measurement, syslog + traps, with VictoriaMetrics/ClickHouse/OpenSearch storage — **matches the architecture of every mature open-source NMS examined** (LibreNMS, Observium, Prometheus snmp_exporter, Telegraf). None of these tools compiles vendor MIBs at runtime; all use curated, pre-resolved OID definitions, and `sysObjectID`-based vendor detection is the documented standard [S8][S10][S5]. The interface data-model decisions (ifXTable 64-bit counters, ifIndex→ifName translation with ifDescr fallback, index retained for series stability) follow RFC 2863's requirements precisely [S1][S2].

The material risks are not architectural — they are **coverage completeness** (ifAlias, ENTITY-MIB physical inventory, EtherLike-MIB FCS errors, generic HOST-RESOURCES storage, counter-discontinuity handling) and **test depth** (recorded-device fixture replay à la LibreNMS snmpsim, per-pipeline absent-data alerting for every one of the five ingest paths, not just aggregate liveness). The dead-man's-switch watchdog, disk-watermark monitoring, and panel↔metric contract audit already in the repo are exactly what the literature prescribes [S13][S12][S11]; the gap list below is about extending them to full coverage, not redesigning them.

---

## 1. Coverage — what a complete L1–L3 baseline must collect

### The reference MIB set

Observium — a production NMS with two decades of multi-vendor deployment — documents its device-agnostic standard-MIB baseline explicitly, and it is the best single checklist available [confirmed, S4]:

| Domain | MIB | Key objects |
|---|---|---|
| Host resources | HOST-RESOURCES-MIB | `hrProcessorLoad` (CPU), `hrStorageTable` (memory/storage) |
| Physical inventory | ENTITY-MIB | `entPhysicalTable` (chassis/modules/serials/FRUs) |
| Environmental | ENTITY-SENSOR-MIB | `entPhySensorValue` + type/scale/precision columns (temp, volts, fans, optical power) |
| Interfaces | IF-MIB — **both** `ifEntry` and `ifXEntry` | octets/pkts/errors/discards, status, speed, identity columns [confirmed, S4][S5] |
| Ethernet L1/L2 | EtherLike-MIB | `dot3StatsTable` (FCS/alignment errors, duplex) |
| Network stack | IP-MIB, IPV6-MIB, TCP-MIB, UDP-MIB, ICMP-MIB, SNMP-MIB | stack counters, agent self-stats |
| Routing | BGP4-MIB (`bgpPeerState`, `bgpPeerFsmEstablishedTransitions`), OSPF-MIB (`ospfNbrState`) | session/adjacency state |
| L2 domain | Q-BRIDGE-MIB | VLANs, FDB |

Critically, Observium notes that **standardized-MIB discovery/polling works on any hardware implementing the MIB regardless of explicit vendor support** [confirmed, S4] — i.e., the correct layering is *standard MIBs first, vendor OIDs as overlays* (e.g., Cisco `ciscoMemoryPoolUsed`, Juniper `jnxOperatingBuffer` where HOST-RESOURCES is absent or wrong).

### Beyond SNMP

SNMP polling alone is not a complete baseline. The Google SRE framing: a complete monitoring baseline covers the four golden signals — **latency, traffic, errors, saturation** [confirmed, S21→S11] — and combines **white-box** (device-exposed counters: SNMP/gNMI) with **black-box** (externally observed behavior: synthetics, active probing), because black-box catches *active* problems as a user would experience them [confirmed, S11]. Mapped to a network:

- **Traffic** → interface octet/packet counters (SNMP/gNMI) + flow records (NetFlow/IPFIX/sFlow) for the *who/what* dimension.
- **Errors** → ifInErrors/ifOutErrors/discards, FCS errors, protocol-session flaps, syslog severity events, trap linkDown.
- **Latency** → active measurement (STAMP/TWAMP-Light, ICMP/TCP synthetics, traceroute for path).
- **Saturation** → utilization vs `ifHighSpeed`, queue drops (discards), CPU/memory, optics thresholds.

The platform's five-path design (poll + stream + flow + active + event) covers all four signals with both white-box and black-box vantage points — structurally complete.

### What's commonly missed

- **ifAlias** — the operator-assigned circuit description and the *only* identity object the RFC requires to persist across reboots (see §2) [confirmed, S1]. Skipping it discards the field NOC operators actually key on.
- **EtherLike-MIB `dot3StatsFCSErrors`** — distinguishes L1 (bad cable/optic) from L2/L3 errors; `ifInErrors` alone can't.
- **ENTITY-MIB inventory** (serials, part numbers, FRU hierarchy) — required for "what hardware is failing," not just "what counter moved" [S4].
- **Counter discontinuities** — `ifCounterDiscontinuityTime` / `sysUpTime` regression detection so an agent restart doesn't render as a giant negative rate (RFC 2863 defines the discontinuity object precisely because counters legitimately reset) [S1].
- **Optical DOM** (light levels via ENTITY-SENSOR or vendor MIBs) — the leading indicator for fiber-link death.
- **BGP4-MIB is IPv4-AFI only** — IPv6/VPN peer state needs vendor MIBs or gNMI; an NMS showing "all BGP green" while only seeing v4 peers is a classic silent gap.
- **The SNMP agent's own health** (SNMP-MIB) and **stack counters** (ICMP/TCP-MIB) [S4].

## 2. Interface identity & data model

### Identity: ifIndex is not a key

RFC 2863 is unambiguous: ifIndex values are constant only **between re-initializations of the agent** — "it is necessary at certain times for the assignment of ifIndex values to change on a re-initialization of the agent (such as a reboot)" [confirmed, S1][S2]. The three name objects have distinct roles [confirmed, S1]:

- **ifDescr** — vendor/product description text; fallback identity only.
- **ifName** — the device's local console name (`Ethernet1/1`); the natural human-stable key.
- **ifAlias** — manager-assigned; the RFC **requires** it to "retain its assigned ifAlias value across reboots, even if an agent chooses a new ifIndex value" [confirmed, S1] — making it the strongest persistence guarantee in the MIB.

Practice consequence: poll by ifIndex (it's the table index — you have no choice within one agent epoch), but **store and display by ifName/ifAlias**, and re-walk the identity columns after any `sysUpTime` regression or coldStart trap so a reshuffled ifIndex doesn't silently re-label history onto the wrong port. Prometheus snmp_exporter models this by attaching *all four* identity labels (`ifIndex`, `ifDescr`, `ifName`, `ifAlias`) to each interface series [confirmed, S10] — index for joinability, names for stability and humans.

### Counters: ifXTable HC is mandatory above 20 Mbps

RFC 2863/2233 set hard thresholds: ≤20 Mbps → 32-bit counters suffice; >20 Mbps → 64-bit octet counters **MUST** be supported; ≥650 Mbps → 64-bit octet **and** packet counters [confirmed, S1][S2]. The reason is wrap arithmetic: a saturated 32-bit `ifInOctets` wraps in ~57 min at 10 Mbps, ~5.7 min at 100 Mbps, **~34 seconds at 1 Gbps** [confirmed, S3] — at modern speeds, 32-bit octet counters can wrap multiple times per polling interval, producing undetectable corruption rather than visible errors. The HC objects live in ifXTable (`ifHCInOctets`/`ifHCOutOctets`, `ifHCIn/OutUcastPkts`, plus HC multicast/broadcast) [confirmed, S3]; errors/discards exist only as 32-bit `ifEntry` objects, which is acceptable because their rates are low. Mature NMSs poll **both tables** (Observium: "ifEntry and ifXEntry") [confirmed, S5]. Use `ifHighSpeed` (Mbps) rather than 32-bit `ifSpeed`, which caps at ~4.29 Gbps.

### Metric naming & cardinality

The snmp_exporter pattern is the de-facto model: one metric name per MIB object, table INDEX values auto-promoted to labels [confirmed, S10], identity strings as labels on the series rather than baked into metric names [confirmed, S10]. Discipline rules drawn from that model and Prometheus practice:

- Stable, unit-suffixed metric names (`_octets_total`, `_bytes`); counters as raw monotonic values, rates computed at query time.
- Labels = identity dimensions only (device, vendor, ifName, index). **Never** put unbounded values (timestamps, flow tuples, ephemeral session IDs) in labels — flow-level cardinality belongs in the OLAP store (ClickHouse), not the TSDB. The split TSDB/OLAP storage in our context is itself the cardinality-discipline mechanism.
- Keep ifIndex as a label *alongside* ifName so series survive interface renames but remain joinable to other tables indexed by ifIndex [S10].

## 3. Curated OID profiles vs MIB compiler

**Verdict: curated profiles are the industry-standard architecture; no surveyed mature tool compiles MIBs at runtime.** Evidence per tool:

- **Prometheus snmp_exporter** — runs from a pre-generated static `snmp.yml`; MIB compilation happens **offline** in a separate generator utility, and the shipped default config "covers most use cases" [confirmed, S10]. Runtime is pure numeric-OID walking with curated metric/label mappings.
- **LibreNMS** — per-OS curated YAML definition files: detection in `os_detection/<os>.yaml` keyed primarily on **sysObjectID** (preferred) with sysDescr fallback [confirmed, S8]; sensors/health declared in `os_discovery/$os.yaml` with hand-specified `MIB::object` references, explicitly so contributors write data not code [confirmed, S7]. Modules are toggled per-device/globally [confirmed, S6].
- **Observium** — built-in curated OID definitions drive automatic discovery; the escape hatch for uncovered objects is admins typing **raw numeric OID strings** into config — still no MIB compiler in the loop [confirmed, S5].
- **Telegraf** — config-driven SNMP input with explicit field/table OID lists (uses net-snmp for name translation at config time, not tree compilation) [thin: S15, vendor blog].

Tradeoffs, honestly stated:

| Curated profiles (our model) | Full MIB import |
|---|---|
| ✅ Deterministic, reviewable, testable per-OID; small attack/maintenance surface; no MIB-parser CVE class; fast polls (walk only what you graph) | ✅ Long-tail coverage of obscure vendor objects without code changes |
| ✅ Matches snmp_exporter/LibreNMS/Observium architecture exactly [S10][S7][S5] | ❌ MIB files are licensed, broken, mutually inconsistent; SMI parsing is a notorious complexity sink |
| ❌ A new vendor/object requires a profile edit (mitigate: LibreNMS-style declarative YAML + a raw-OID escape hatch like Observium's statics [S5]) | ❌ Walking full trees hammers device control planes |
| ❌ Risk of *silent under-coverage* — the profile defines what "complete" means, so completeness must be tested (→ §4) | — |

The honest cost of the curated approach is that **coverage correctness moves from the MIB into your test suite** — which is why §4 matters more for this architecture than for any other.

## 4. Testing telemetry pipelines

### Recorded-device fixture replay (the LibreNMS pattern)

LibreNMS unit-tests its entire SNMP collection path against **snmpsim**, a simulated SNMP agent, instead of real devices [confirmed, S9]. Real-device walks are captured into `.snmprec` files (`tests/snmpsim/*.snmprec`) and replayed as deterministic fixtures: every OS profile ships with a recorded device, and CI asserts discovery + polling produce the expected parsed output from that recording [confirmed, S9]. This is the single highest-leverage test pattern for a curated-profile NMS: it converts "does our Nokia SRL profile actually parse what a real SRL returns?" into a repeatable offline test, and regression-protects against profile edits. The equivalent for our stack: capture per-vendor walk transcripts from the containerlab fabric, replay them against the poller in `go test`.

### Contract testing: dashboards ↔ emitted metrics

The "silent empty panel" failure has a specific mechanic: a panel queries a metric name/label set that the collector no longer (or never) emits, and the query layer returns *empty*, not *error* — aggregators "produce no output" on no input [confirmed, S12]. Two defenses:

1. **Static contract audit** — extract every metric/label referenced by panels and assert each is produced by a collector (build-time, no stack needed). This is rare in OSS tooling but directly motivated by the absent-data literature [S12]; our repo's CI "panel↔metric contract audit" is precisely this.
2. **Runtime absence alerting** — `absent(up{job=...})`-style rules per expected series family, because threshold alerts can never fire on missing data [confirmed, S12]. One rule per job/source is required; Prometheus cannot infer which label sets *should* exist [S12].

### Synthetic vs real-device validation

Layered, in order of cheapness: (a) unit tests on parsers/encoders (BER, USM, gNMI decode); (b) recorded-fixture replay [S9]; (c) live integration against lab devices (our clos-multivendor containerlab) for end-to-end truth — noting the lab's own limits (e.g., cEOS/SRL containers can't packet-sample sFlow; per-flow truth requires VM PFEs); (d) **black-box validation in production**: inject known traffic/events and assert they appear end-to-end, the SRE black-box principle ("symptom-oriented... catches active problems") [confirmed, S11]. A demo-fill/traffic-generator that exercises *every* pipeline is a black-box probe of the whole ingest chain, not just a demo tool.

### Golden signals / USE applied to the telemetry pipeline itself

Treat the pipeline as a service: **latency** (poll-cycle duration, ingest lag), **traffic** (samples/flows/logs per second per source), **errors** (SNMP timeouts, gNMI stream resets, decode failures), **saturation** (queue depth, consumer lag, disk) [confirmed, S11]. The SRE error rule generalizes directly: an HTTP 200 with wrong content is still an error [confirmed, S11] — for an NMS, *a poll that succeeds but returns zero rows for a table that had 48 rows yesterday is an error*, and must be counted, not silently accepted. LibreNMS exposing per-module poller resource consumption is the same meta-monitoring instinct [confirmed, S6].

## 5. Pipeline reliability

### Silent ingestion failure & dead-man's-switch

Telemetry pipelines fail *silently* by construction: absence of data triggers nothing, and empty query results read as "no data," not "failure" [primary, S13]. The verified three-layer defense [S13]:

1. **Pipeline-level heartbeats** — alert on `absent_over_time()` of the pipeline's own throughput metrics (e.g., Vector/Redpanda/collector internal counters), firing after 2–5 min of silence [S13].
2. **Per-source freshness** — detect when an individual device/pipeline stops sending, per expected series family [S12][S13].
3. **External dead-man's-switch** — an *always-firing* signal routed to a watchdog **outside the monitored stack**; when the watchdog stops hearing it, the alerting chain itself is dead. "The watchdog must live outside your primary monitoring infrastructure" [primary, S13]. The stack's own notifiers can never report their own death — exactly the rationale for our external cron watchdog + healthchecks.io ping.

### Backpressure & bounded queues

*(Evidence note: the one listed backpressure-specific source returned 403 and is unverifiable; the following is principle-level, anchored in the bounded-queue/observability rules rather than that source.)* Every hop must have **bounded buffers with observable depth** and an explicit overflow policy (block vs drop vs spill-to-disk), and the bus (Redpanda) decouples producers from slow sinks — but only if **consumer lag is itself alerted on**; lag growing monotonically is the canonical silent-backpressure signature. Dropped-event and buffer-utilization counters from the aggregator (Vector) are the white-box backpressure signals; absent-data rules on downstream stores are the black-box confirmation [S12][S13].

### Disk & retention watermarks

A full disk in the log/TSDB tier doesn't crash the pipeline — it flips indices read-only and ingestion *appears* to continue while everything is dropped (our own 2026-06-10 OpenSearch flows-flood outage is the live proof of this failure class). Required controls: free-space watermark alerts **below** the store's own read-only thresholds, explicit TTL/retention per high-volume table (e.g., flows), and sampling at the source for unbounded streams. Watermark alerting is meta-monitoring in the SRE sense — white-box on the monitor itself [S11].

---

## Validation against our implementation

### Matches best practice (verified in repo/source where noted)

- **Curated OID profiles + sysObjectID vendor detection** — identical architecture to snmp_exporter (offline-generated static config) [S10], LibreNMS (per-OS YAML, sysObjectID-preferred detection) [S7][S8], and Observium (built-in curated OIDs, raw-OID escape hatch) [S5]. Not a shortcut; the industry standard.
- **ifXTable HC counters** — `profiles.go` polls `ifHCInOctets`/`ifHCOutOctets` and HC ucast/mcast/bcast packet counters, satisfying the RFC's >20 Mbps and ≥650 Mbps requirements [S1][S2][S3]; errors/discards correctly from `ifEntry` (their only home); `ifHighSpeed` not `ifSpeed`.
- **ifIndex→ifName translation with ifDescr fallback, index kept for series stability + ifName label for humans** (`snmpmetrics.go`) — matches snmp_exporter's multi-identity-label model [S10] and RFC 2863 identity semantics [S1].
- **MIB-domain coverage** — IF-MIB, HOST-RESOURCES (`hrProcessorLoad`), ENTITY-SENSOR (`entPhySensorValue`), BGP4-MIB (peer state + FSM transitions + InUpdates), OSPF-MIB (ifState/nbrState), sysUpTime, plus vendor memory overlays (Cisco/Juniper) — covers most of the Observium standard set [S4].
- **White-box + black-box mix** — SNMP/gNMI (white) + STAMP/synthetics/traceroute/flows (black) covers all four golden signals from both vantage points [S11][S21].
- **Cardinality discipline by storage split** — flow tuples in ClickHouse, bounded-label metrics in VictoriaMetrics; matches the model in §2.
- **Contract audit in CI** (panel↔metric, Tier 1) — directly implements the §4 static defense against silent empty panels [S12].
- **External watchdog with dead-man's-switch (healthchecks.io) + ntfy transitions + disk-watermark + ingestion-liveness monitors** — implements all three layers of the verified heartbeat pattern, including the "watcher outside the stack" requirement [S13][S12].
- **Trap + syslog event paths, SNMPv3 USM, per-vendor credential profiles** — standard NMS event baseline [S4].

### Gap list to verify (concrete, ordered by risk)

1. **ifAlias is not collected** (`profiles.go`/`snmpmetrics.go` walk ifName/ifDescr only). It is the *only* RFC-guaranteed reboot-persistent identity object and carries operator circuit IDs [S1]. Add it as a label and as the third fallback/primary display key.
2. **No ifIndex-reshuffle handling**: identity map is "walked lazily once per device" — a reboot that renumbers ifIndex [S1] will mislabel series until process restart. Invalidate the ifName cache on `sysUpTime` regression or coldStart trap; add counter-discontinuity detection (`ifCounterDiscontinuityTime` or sysUpTime check) so resets don't poison rates.
3. **ENTITY-MIB physical inventory** (`entPhysicalTable`: serials/models/FRU tree) — we poll the sensor MIB but verify inventory itself; Observium treats it as baseline [S4].
4. **EtherLike-MIB `dot3StatsFCSErrors`** — absent from profiles; the canonical L1-fault discriminator. Commonly missed (§1).
5. **Generic memory/storage**: memory is vendor-OID-only (Cisco/Juniper). Nokia SRL/Arista paths and any future vendor need either `hrStorageTable` (HOST-RESOURCES, per Observium baseline [S4]) or gNMI equivalents — verify per-vendor memory actually populates for all four vendors.
6. **BGP IPv6/VPN AFI blindness** — BGP4-MIB is v4-only; verify v6/VPNv4 peers are covered via gNMI or vendor MIBs, or the BGP panel is silently partial.
7. **Recorded-fixture replay tests** — LibreNMS's `.snmprec` snmpsim pattern [S9] has no equivalent here yet (unit tests exist; deterministic real-walk replays per vendor profile do not, as far as verified). Capture walks from the clos lab and replay in `go test` — this is the highest-leverage missing test layer for a curated-profile design.
8. **Per-pipeline absence alerting granularity** — ingestion-liveness exists; verify it is per *source family* (metrics AND flows AND logs AND traps AND synthetics, ideally per-device-class), since absent-data rules must be enumerated per expected series [S12].
9. **Backpressure observability** — verify Redpanda consumer-lag and Vector buffer/drop metrics are alerted on, not just collected (evidence tier thin here; principle-level, §5).
10. **"Successful-but-empty poll" as an error** — count table walks returning anomalously fewer rows than last cycle [S11's implicit-error rule]; today a half-dead agent likely reads as healthy.
11. **Stack-counter / agent-health MIBs** (SNMP-MIB, ICMP/TCP-MIB) and **Q-BRIDGE VLANs** — lowest priority; part of the Observium baseline [S4] but rarely load-bearing for L1–L3 fault detection.

## Sources

- [S1] RFC 2863, *The Interfaces Group MIB* — https://www.rfc-editor.org/rfc/rfc2863.html (primary; claims confirmed 3-0)
- [S2] RFC 2233 (IF-MIB predecessor, identical counter/ifIndex language) — https://www.ietf.org/rfc/rfc2233.txt (primary; confirmed 3-of-3)
- [S3] Cisco, *SNMP Counters FAQ* (32/64-bit wrap times, ifXTable HC objects) — https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/26007-faq-snmpcounter.html (primary; confirmed 3-of-3)
- [S4] Observium, *Supported Devices* (standard-MIB baseline; device-agnostic generic-MIB polling) — https://docs.observium.org/supported_devices/ (primary; confirmed 3-0)
- [S5] Observium, *Static Monitoring* (curated OIDs default; raw-OID escape hatch) — https://docs.observium.org/statics/ (primary; confirmed 3-of-3)
- [S6] LibreNMS, *Performance* (module-based polling, per-module observability) — https://docs.librenms.org/Support/Performance/ (primary; confirmed 3-0)
- [S7] LibreNMS, *Health Information* (declarative per-OS YAML OID mapping) — https://docs.librenms.org/Developing/os/Health-Information/ (primary; confirmed 3-of-3)
- [S8] LibreNMS, *Initial OS Detection* (sysObjectID-preferred detection; per-OS curated definitions) — https://docs.librenms.org/Developing/os/Initial-Detection/ (primary; confirmed 3-of-3)
- [S9] LibreNMS, *Test Units* (snmpsim + .snmprec recorded-device fixtures) — https://docs.librenms.org/Developing/os/Test-Units/ (primary; confirmed 3-of-3)
- [S10] prometheus/snmp_exporter README (offline generator → static snmp.yml; index→label mapping; multi-identity interface labels) — https://github.com/prometheus/snmp_exporter (primary; confirmed 3-of-3)
- [S11] Google SRE Book, *Monitoring Distributed Systems* (golden signals; implicit errors; white-box/black-box) — https://sre.google/sre-book/monitoring-distributed-systems/ (primary; confirmed 3-of-3)
- [S12] Robust Perception, *Absent Alerting for Jobs* (absent() pattern; aggregators silent on no input; per-job enumeration) — https://www.robustperception.io/absent-alerting-for-jobs/ (blog, fetched & verified)
- [S13] OneUptime, *Heartbeat / Dead Man's Switch for Telemetry Pipelines* (three-layer pattern; watcher outside the stack) — https://oneuptime.com/blog/post/2026-02-06-heartbeat-dead-man-switch-opentelemetry-pipeline/view (blog, fetched & verified)
- [S14] W. Hegedus, *Alerting on Missing Data in Prometheus* — https://wbhegedus.me/alerting-on-missing-data-in-prometheus/ (blog; not independently fetched — corroborative of S12 only)
- [S15] InfluxData, *Monitor SNMP Devices with Telegraf* — https://www.influxdata.com/blog/monitor-your-snmp-devices-with-telegraf/ (vendor blog; thin — used only for Telegraf config-driven characterization)
- [S16] M. Drozd, *Prometheus Remote-Write Backpressure* — https://www.michal-drozd.com/en/blog/prometheus-remote-write-backpressure/ (**unverifiable — HTTP 403 at fetch time**; no claims rest on it)
- [S17] Cisco, *ifIndex Persistence* — https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/28420-ifIndex-Persistence.html (listed as unreliable; not relied upon — RFC 2863 [S1] covers the same ground authoritatively)
- [S21] (alias of S11 application) golden-signals mapping to network telemetry — analyst synthesis over [S11]; flagged as interpretation, not direct quotation

*Repo-grounded observations (validation section): `src/backend/collectors/profiles.go`, `src/backend/collectors/snmpmetrics.go`, and recent commits (panel↔metric contract audit; disk-watermark + ingestion-liveness watchdog; ifIndex→ifName translation) were read directly from the working tree at `/home/rao/Projects/NetOps_Observability/NetOps_Observability/src/backend/`.*