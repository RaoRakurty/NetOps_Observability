# Enterprise-grade parsing and enrichment: final plan

**Date:** 2026-11-09. **Tracker:** row 387. **Status:** plan, with owner decisions in §9 still open.

**Sources merged:** the owner's research (`/var/tmp/Ent-grade-parsing.md`), a Fable research pass over this code base, and live measurements on the lab. Where they disagreed, the code and the lab data decided. §10 records what was adopted and what was not, and why.

**The measure of every item (owner rule):** what it gives correlation and RCA first, operator readability second.

---

## 1. The problem in one paragraph

Collection works: records arrive, are attributed and are stored. Understanding does not. The parsers know almost nothing about Cisco SD-WAN, the only vendor in the lab, so syslog is 100% unparsed, Viptela traps stay numeric, and a line saying "critically high" reaches the engine as a routine notice. Nothing measured any of this, because `parser_status` was checked for presence and it is present on every record, including when its value is `unparsed`.

## 2. Measured on the lab, 2026-11-09

All single-vendor Cisco SD-WAN. Numbers move; the shape is the finding.

| Lane | Measurement |
|---|---|
| Syslog | ~119,000 docs today: `parser_status=unparsed` 100%, `vendor=unknown` 100%, `parser_id` and `summary` 0% |
| Syslog | 89% is one app (`confd`), mostly audit records caused by polling |
| Engine prefilter | Rejected 124,569, passed 5,129 (96% rejected) |
| Traps | ~2,080 today: 21% `enterpriseSpecific`, all one OID (`1.3.6.1.4.1.41916.100.2.114`); the other 79% decode by name |
| Traps | `snmp_community` is stored in `_source` and returned by the Logs API |
| Flows | 29,875 rows in an hour from 4 exporters: tenant, AS numbers and `sampling_rate` all empty; `exporter_app` empty in the hour measured (the research pass reports one exporter sends it; not reconfirmed); 97% involve port 161 |
| Tenant | `tenant_attribution=unmatched` on all lanes, including devices the registry knows |

## 3. Root causes

Ordered by RCA impact.

### 3.1 The engine cannot see Cisco SD-WAN syslog faults

Proven by running live lines through `producers.syslog_promotable`. It rejected:

- `%Viptela-vEdge-20-SYSMGR-2-CRIT-200069: System cpu usage is above 90% (critically high)`
- `%Viptela-vEdge-52-SYSMGR-4-WARN-200070: System cpu usage is above 75%`
- `%Viptela-vEdge-52-FTMD-3-ERRO-1000003: ...`
- `DNS lookup failed for 0/vbond...`

Cause: devices send every line at PRI `notice` and carry the real severity in the text. Neither parser reads that format:

- `_TAG_SEV_RE` (`src/correlation/producers.py:196`) searches only the appname tag and expects `%FAC-N-MNEMONIC`.
- The Vector regex (`deployment/docker/vector/vector.yaml`, vendor test ~580 and Stage B ~658) expects an uppercase facility and one hyphen.

Neither matches `%Viptela-<host>-<PROC>-<n>-<WORD>-<id>:`. Vector leaves `facility` and `event_type` empty, and the engine's marker rules read those fields, so typed rules cannot fire even once written until the grammar lands.

Some Viptela lines do pass on a matching literal, so "the engine sees none" would overstate it. The sample was 60 lines per app.

**The prefilter is correct.** It rejects lines no rule can promote. The gap is the rules and the severity parsing.

### 3.2 Viptela traps are not decoded

Enterprise 41916 has no entries in `collectors/mibs/index/oididx.json` (5,749 nodes), so `trapMeta` returns `enterpriseSpecific`/`notice`, and `events.yaml` has no rule for it.

The owner's OID table is **correct** against `VIPTELA-TRAPS` 20.12 (revision 2023-07-01): `traps 114` = `viptelaSystemCpuUsage`; `fields 1` eventTime, `2` netconfNotificationSeverity, `54` viptelaSystemWarning, `190/191/192` CPU user/system/idle; severity enum `critical(1) major(2) minor(3)`. Checked against the Cisco file directly. A third-party mirror the research pass used disagreed and should not be used.

The MIB defines 124 notifications, including the faults that matter: `viptelaBfdBfdStateChange`, `viptelaSecurityControlConnectionStateChange`, `viptelaSecurityControlNoActiveVsmart`, `viptelaSecurityControlNoActiveVbond`, `viptelaOmpOmpPeerStateChange`, `viptelaOmpOmpTlocStateChange`, `viptelaVpnInterfaceStateChange`, `viptelaVpnBgpPeerStateChange`, `viptelaSystemMemoryUsage`. Only the CPU trap has been seen in the lab, so the others need real captures (§6).

### 3.3 Syslog framing

`deployment/docker/syslog-ng/core.conf` uses the default legacy `syslog-parser()`, which ends PROGRAM at a space, so `confd 2939 - - audit...` becomes program `confd` and message `2939 - - audit...`. This matches the owner's diagnosis. What the device actually sends is **unverified** and needs a raw capture first. On cEdge the IOS-XE mnemonic (`%DMI-5-AUTH_PASSED`) never reaches storage and the hostname falls back to the sender address; the mechanism is also unverified.

### 3.4 Storage and API defects

Found by the research pass and spot-checked here. PR-3 must confirm the details it relies on.

- **`message_key` is overwritten.** The router's Kafka sources keep Vector's default `key_field`, so trap docs show `message_key: "global"` and the receiver's dedup key is lost. Only the flows lane deletes it (`vector-router/vector.yaml:1086`).
- **Trap fields are not searchable.** The `netops-snmptrap` template is `dynamic: false` and omits `parser_status`, `enrichment_status`, `event_type`, `category`, `family`, `summary`, `vendor`, so these exist in `_source` but cannot be filtered or aggregated.
- **Pipeline metadata reaches operators.** `partition`, `offset`, `topic`, `source_type`, `headers` and others are stored on log lanes; the flows lane strips them.
- **The Logs API returns `_source` untouched** (`src/backend/logs.go:36-41`), which is how the community string reaches clients.

### 3.5 Misleading labels

`tenant_attribution` is set to `unmatched` whenever the segment is untagged (`vector-router/vector.yaml:524-525`), even on a registry hit. A registry hit with a blank tenant means the device is platform-owned, by design. The label wrongly reads as a failure.

### 3.6 Enrichment is thin by construction

`device_tenant.csv` has only `identity,tenant_id`, so vendor is guessed from message text although inventory knows it. Flows carry ifIndex with no names, and `entity_resolver.json` currently has 0 interface rows (tracker 334).

### 3.7 Self-inflicted volume

Most `confd` lines and 97% of flow rows appear to be caused by polling: ours over SNMP and vManage's over NETCONF. The research pass measured ~4,000 SNMP session records per vEdge per hour. This is strong correlation, not a controlled test. It costs storage, not RCA accuracy.

## 4. Corrections to earlier statements

- **Flows are not understated 50×.** An earlier status message said they probably were. That was wrong, and this plan **must not** multiply anything. `sample_rate=50` is the router's own 1:50 sample of the OpenSearch flow index (`vector-router/vector.yaml:1355-1372`), already disclosed in the UI. `sampling_rate=0` comes from goflow2, which leaves it at 0 when the exporter reports no sampling, and queries treat 0 as 1:1 (`flows.go:70`). ClickHouse totals are therefore right **if the exporters are not sampling**. vEdge documentation says cflowd does not sample. cEdge can be configured to, and then reports the rate in option records, so check the lab's cflowd policy to close this.
- **The MIB path is `sdwan/controller/<release>/` and `sdwan/device/<release>/`** in `github.com/cisco/cisco-mibs`, not `viptela-mibs`.

## 5. Design decisions

1. **One catalogue, two executors.** Add vendor grammars to `telemetry-catalog/events.yaml` and generate the Vector Stage B branch, its tests and the engine's severity parsing from them, the way the admission stamp is already generated. This stops the two parsers disagreeing again.
2. **Keep the flat event format.** OpenSearch templates are `dynamic: false` and the engine reads flat fields, so nesting would mean rewriting both for no RCA gain. Add flat fields using OpenTelemetry and ECS meanings, with a mapping table for export: `event_action`, `event_state` (`raise|clear|point`), `severity_native_text`, `severity_native_code`, `observed_ts`, `mib_module`, `mib_bundle_version`.
3. **Three separate ideas stay separate:** native severity, normalized severity, and whether the event raises or clears. A recovery can be `minor` natively and still be a clear.
4. **No new alarm state machine.** The engine already handles object lifecycle and skips `<kind>_clear` nodes. The lanes only need to emit clears. Tracker 380 owns the device-lane recovery audit.
5. **Tenant stays channel-derived** (owner decision 2026-11-01). No address-based mapping. Tracker 371 and 373 remain with the collector tier.
6. **Enrichment placement.** Inventory facts for syslog and traps go on the existing O(1) registry lookup. Interface, device, protocol and service names for flows are resolved at query time through ClickHouse dictionaries, which also covers stored rows and adds no per-row ingest cost on the 4-core box.
7. **MIBs are fetched, pinned and never vendored,** following tracker 377. The `cisco-mibs` repo shows no licence file, so it gets the same treatment as Arista. Pin the MIB release to the deployed software, and rank further coverage by the unknown trap OIDs actually seen.
8. **Engine boundary.** New rules touch stage [1] only. A device's own trap and SNMP episode remain one observation under E1, so these rules **corroborate; they cannot confirm by themselves**. `verdicts.py` still decides.

## 6. Delivery plan

Each item is a separate PR. Rule changes re-pin `BAKED_RULES_HASH`, the admission VRL, `coverage_matrix` and `telemetry-catalog/test_bake_rules.py`, and land after P6-E (#149) or rebase onto it. `canon.py` is off limits here.

### Tranche 0: independent fixes

| PR | Change | Stage | State |
|---|---|---|---|
| 1 | Stop storing community strings; hide stored values on every read path | ingest, API | **In progress** |
| 2 | Logs page redesign (§7) | UI | **In progress** |
| 3 | Keep `message_key`; declare trap fields in the template; strip pipeline metadata at the sink after `cx_event_id` is derived | router, storage | Queued |
| 4 | Add `platform_owned` to `tenant_attribution`; update `TenantEnrichmentMissRateJumped` and its promtool test | router | Queued; D6 |
| 5 | Label flow sampling honestly: `sampling_status` of `reported` or `not_reported_1to1`, no change to totals | router, UI | Queued |
| 6 | Telemetry Coverage page: rename "Prefilter rejected" and drop its warning colour; warn on high-severity lines that were skipped once PR 8 can see them | UI, engine | Queued |

### Tranche 1: RCA

| PR | Change | Stage | Notes |
|---|---|---|---|
| 7 | Viptela MIB through `FETCH_PINS`, trap names, typed values, native severity, enums, `oidindex_test` | receiver | Verified MIB; correct the stale "seed" paragraph in `mibs/README.md` |
| 8 | Cisco SD-WAN grammar in the catalogue: `%Viptela-...` and `%Cisco-SDWAN-...`, `vendor`, `facility`, `event_type`, `summary`, embedded severity, in both Vector and the engine | Vector, engine [1] | **Admit by severity for critical only (D3)** |
| 9 | Typed rules: control connection, BFD, OMP peer, TLOC, CPU and memory raise/clear, vBond DNS failure; `known_benign` row for `FTMD-3-ERRO-1000003` | engine [1] | Each rule needs a captured fixture; see the warning below |
| 10 | Raw frame capture, then fix syslog framing for vEdge and cEdge | syslog-ng | Capture first. The fix changes PROGRAM and MESSAGE for all vendors, so it needs fixtures per vendor, the admission suite and the storm parity leg |
| 11 | Classify poll-induced audit records as management-plane, non-alarm, with a dedup key. Never drop them | catalogue | D2 |

**Warning on PR 8/9.** Reading severity correctly without typed rules would create false incidents. `FTMD-3-ERRO-1000003` repeats about every 20 seconds per vEdge and may be harmless; error maps to `high`, and a lone `high` signal opens an object. So typed rules and the benign row ship with the grammar, and blanket admission stays critical-only until the message IDs are reviewed.

**Capturing fixtures.** The lab shows only CPU and DNS events so far. Cisco's syslog message catalogue was not retrievable. Trigger BFD, control-connection and OMP events on the lab, or take fixtures from controller-reported incidents, and record the unverified ones as `doc_claimed`, per the catalogue's fidelity rule.

### Tranche 2: enrichment

| PR | Change | Stage |
|---|---|---|
| 12 | Registry columns `device_id, vendor, model, site, role` on syslog and traps, with §3a test | API, Vector |
| 13 | ifIndex to name for traps in the receiver; ClickHouse dictionaries for flow interface, device, protocol and service names, keyed by tenant and queried under `chTenantScope`. Real values need tracker 334 | receiver, API |

### Tranche 3: so it never goes silent again

| PR | Change |
|---|---|
| 14 | Metrics for parse status per lane and vendor, trap varbind resolution and flow enrichment outcome; rules for a rise and for a lane stuck at ≥99% unparsed; a `deploy-qualify` question; a CI ratchet in which each grammar's fixture must assert `parser_status == "parsed"` and a specific `event_type` |

**The rule behind PR 14:** test the value, never the presence. A field present on 100% of records with the value `unparsed` is the failure this plan exists to fix. PR 14 can start as soon as PR 8 lands.

### Multi-vendor (binding)

Every fix covers Cisco, Juniper, Nokia, Arista, SONiC and others, standard MIBs first:

- `HOST-RESOURCES-MIB`, `CISCO-PROCESS-MIB`, `TIMETRA-SYSTEM-MIB` and `JUNIPER-MIB` are already indexed, so CPU-threshold rows can cover them when the OID resolves.
- `BFD-STD-MIB` (RFC 7331) is the standard BFD path and is not yet indexed.
- cEdge uses separate `sdwan/device/<release>/` MIBs.
- Only Cisco can be verified on the lab; everything else ships as `doc_claimed`.

## 7. Logs page design

**Direction:** normalized meaning first, raw one click away, in Correlix's existing visual language. No new fonts or colours.

| Element | Rule |
|---|---|
| Summary, labels, controls | `--font-ui` (Inter), at least 14px |
| Time, addresses, ports, OIDs, raw values | `--font-mono` (JetBrains Mono) only |
| Page title | `--font-display` at most |
| Size floor | Body ≥ 14px, headings ≥ 16px, nothing < 12.5px |
| Colour | Existing tokens only; severity from `theme/severity.ts` as the single authority |
| Severity | Text and colour together, never colour alone |
| Themes and widths | Light, all dark themes, phone width, no sideways page scroll at 1366 or 1920 |

Defects being fixed: all row text is monospaced at 11.5–12.5px, below the floor; `notice` uses the accent colour and `critical` and `error` share one colour, so a level can show two colours; the message tokenizer paints a rainbow; details open on a raw JSON dump.

**Stream:** two-line rows of time, severity, signal, device with address, then a plain title and muted detail. Flows show source → destination, protocol and bytes.

**Filters:** segmented signal control, with chips counted over loaded rows and labelled so they are not read as totals. A chip only appears if its field is searchable.

**Details:** tabs Summary, Fields, Raw.
- Trap: varbind table.
- Flow: exporter above a source → destination strip, observed counters, and sampling as reported.
- Syslog: envelope pills then the clean message.
- Pipeline fields sit in a collapsed section.
- Credential-like fields are never shown, as defence in depth.

**Honesty rules:** no semantics invented in the browser. An undecoded trap shows "Not decoded yet" with its OID, and no bandwidth is estimated. The page picks up richer fields automatically as tranches land.

**Later, once the data exists:** parser provenance ("why this field exists"), correlated signals ±5 minutes, and a filter by raise or clear.

## 8. What the UI can rely on

| After | Fields |
|---|---|
| Now | Syslog `hostname, appname, severity, message`; traps `trap_oid, trap_name, varbinds, device`; flows' observed counters |
| PR 3, 4 | `tenant_attribution` with `platform_owned`; searchable trap `parser_status, event_type, summary, vendor` |
| PR 7, 8 | Syslog `vendor, facility, event_type, summary, parser_id`; trap names, enums, native severity, `event_state`, typed values |
| PR 12, 13 | `vendor, model, site, role` on all lanes; interface and device names on flows through the API |

## 9. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| D1 | Community string: drop it, or keep a keyed fingerprint to answer "same credential?" | **Drop, keep a present/absent flag.** The fingerprint adds a key to manage for little value |
| D2 | `confd` audit volume: classify and deduplicate only, or also document device-side suppression | **Classify and deduplicate.** A customer guide can follow if storage becomes a complaint |
| D3 | Viptela severity admission: typed rules plus critical-only, or everything warning and above | **Typed rules plus critical-only**, because of the false-incident risk |
| D4 | MIB source: pinned `cisco-mibs` fetch, or a software.cisco.com download | **Pinned fetch.** The Cisco download needs a login and cannot be automated |
| D5 | Raw retention: Kafka 72 h plus stored `message`, or an immutable raw store | **No raw store now**, as it doesn't fit the single-box goal. Add an optional stored-only raw frame for syslog if needed |
| D6 | Wording for platform-owned devices | **`platform_owned`** in data, "Platform device" in the UI |
| D7 | Usernames inside audit messages: keep or redact | **Keep for now**, access-controlled, and include in a later PII policy |
| D8 | Rotate the lab community string, since it was stored in clear | **Rotate.** Treat as exposed |

## 10. Owner research: what was adopted

| Proposal | Outcome | Reason |
|---|---|---|
| Separate decode, parse, enrich and normalize stages | **Adopted** | The stages exist; the plan adds a status where one can fail silently |
| Native vs normalized severity vs lifecycle | **Adopted** | §5.3 |
| Community redaction, normalized-first viewer, varbind table, flow strip, envelope pills | **Adopted** | §6, §7 |
| Coverage metrics and fixture-driven QA | **Adopted** | PR 14 |
| Signed, versioned MIB bundle with recorded version | **Adopted**, on existing pins | `FETCH_PINS` + `mib_bundle_version` |
| Viptela OID table | **Adopted, verified** | §3.2 |
| Syslog header diagnosis | **Adopted**, capture first | §3.3 |
| Namespaced schema | **Adapted** to flat fields with a mapping | §5.2 |
| Per-stage status | **Adapted** to `envelope`, `parser`, `enrichment`, `sampling`, tenant | Not all eight stages exist here |
| HMAC community fingerprint | **Optional** | D1 |
| Sampling status `ambiguous` | **Replaced** | Semantics are settled, §4 |
| Tenant by IP or exporter, with confidence | **Rejected** | Conflicts with the 2026-11-01 decision |
| Immutable raw object store and replay | **Not now** | Single-box goal; D5. Kafka allows re-consumption within retention |
| New alarm state machine | **Rejected** | Engine already does it, §5.4 |
| Parser confidence floats | **Rejected** | False precision; nothing consumes them. Use `parser_status` and the fidelity ladder |
| IPFIX template registry and fingerprints | **Rejected** | goflow2 owns templates |

## 11. Still unverified

- What vEdge and cEdge send on the wire (PR 10 captures it).
- Whether the lab's exporters sample (check the cflowd policy, §4).
- That polling causes the `confd` and port-161 volume (strong correlation only).
- The full Viptela syslog message-ID list, and the recovery wording for each.
- Which lab devices emit which traps, including `BFD-STD-MIB`.
- Whether cEdge needs `sdwan/device` MIBs rather than `sdwan/controller`.
- Internals of ThousandEyes, SolarWinds and Catalyst SD-WAN Analytics: no citable page was retrieved, so they are not used as benchmarks.

## 12. External references

- [Elastic ECS event.type values](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type)
- [OpenTelemetry logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry network attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/)
- [Splunk Connect for Syslog: Cisco IOS](https://splunk.github.io/splunk-connect-for-syslog/3.0.0/sources/vendor/Cisco/cisco_ios)
- [Datadog NetFlow](https://docs.datadoghq.com/network_monitoring/devices/netflow)
- [Kentik interfaces](https://kb.kentik.com/docs/interfaces)
- [LogicMonitor trap MIBs](https://www.logicmonitor.com/support/supported-mibs-for-snmp-trap-translation)
- [goflow2 producer_nf.go](https://raw.githubusercontent.com/netsampler/goflow2/main/producer/proto/producer_nf.go)
- [Cisco MIBs: sdwan](https://github.com/cisco/cisco-mibs/tree/main/sdwan)
