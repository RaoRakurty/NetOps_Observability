# Enterprise-grade parsing and enrichment: final plan

**Date:** 2026-11-09. **Tracker:** row 387. **Status:** approved. All owner decisions in §9 are final (2026-11-09).

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

Cause: every line reaches storage at PRI `notice`, and the real severity survives only in the text. Devices do send real PRI (§3.3); our own syslog-ng resets it. Neither parser reads the text format:

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

**Corrected 2026-11-09 from a 120 s capture of the lab's syslog stream.** Devices send real PRI. Syslog-ng throws it away.

| Device | On the wire |
|---|---|
| vEdge | True RFC 5424 with real severity: `<187>1 <ts> vEdge-N FTMD 3875 - - %Viptela-...` (`<187>` is err, `<188>` warning, `<142>` and `<190>` info) |
| cEdge | `<189>25165: <ts>: %DMI-5-AUTH_PASSED: R0/0: dmiauthd: ...`, with no hostname in the frame |

The cause is two parses in `deployment/docker/syslog-ng/core.conf`. The `udp()` source parses once, then `parser(p_syslog)` re-parses `$MSG`, which no longer has a PRI, so every message becomes PRI 13 (`notice`). Run through the shipped config in an isolated container:

- vEdge becomes program `FTMD`, message `3875 - - %Viptela-...`.
- cEdge becomes host = sender address, program `R0/0`, and the `%DMI-5-AUTH_PASSED` mnemonic is discarded.

Removing the second parser keeps PRI and the mnemonic, but RFC 5424 frames then become program `1` with host = sender, so the fix needs a real RFC 5424 parser, not just that deletion.

**This is why PR 10 moves up, and it affects every vendor,** since all syslog passes through the same two parses.

**Built in PR 10 (2026-11-09).** `core.conf` reads every frame with `no-parse` and branches on its bytes: a strict RFC 5424 parser for `<PRI>1 `, the legacy parser for the rest, after data-driven shape rewrites (`edge_shapes` in the packs). Vector's own parser was evaluated and rejected: it produced no record for 12 of 31 fixtures and let a structured-data element overwrite the hostname. Also found while fixing it, and fixed:

- **One non-UTF-8 byte stalled the whole lane.** Vector's octet decoder treats it as a broken stream and syslog-ng waits 60 s to reconnect. The source now sanitises.
- **Every RFC 3164 timestamp was the receive time,** since the second parse found no date, and that accident is what let a fleet logging local time correlate. Device time now survives within the 300 s skew tolerance. Past it a zone-less claim is not believed: event time is the edge's receive time, the claim stays as `device_timestamp`, `ts_source` says `edge_receive` and `clock_skew_s` is stamped. A frame stating `Z` or an offset keeps its time and is flagged: it can truly be old.
- **`<>` reads as PRI 0, `kern.emerg`,** and a failed parse injects text at `err`. A frame with no valid PRI is now kept unparsed at `notice` and counted.
- **Sender-written structured data reaches no field.** It travels as one text value, `structured_data`.

The `NNNN - - ` envelope row is deleted: over 3,825 frames of real lab traffic it fired on 3,785 before the fix and on none after. `sshd error: kex_exchange_identification` got its row first. Result on real traffic: the same 113 signals and 3 objects before and after. Bad frames are counted in `netops_ingest_syslog_bad_frames{reason}`.

**The generic net:** only emerg, alert and crit open an object alone; err arrives below the floor (D3). **Link lines:** `%LINEPROTO-*-UPDOWN` from a sender with no process tag is `warn`, because IOS logs it after a fault and after a `shutdown`; `%LINK-3-UPDOWN` opens. Telling a protocol-only fault from a shutdown needs both lines (tracker 388).

**Still wrong, on purpose, for later streams:** IOS-XR, NX-OS `%ETHPORT-*`, Junos, SR OS and SONiC bodies stay `parser_status=unparsed` or generic, so their real link faults reach the engine as `device_alarm` at `warn` or not at all. The envelope is right; the grammar is theirs. SONiC's `{{os_version}}` template variant is not handled. The storm parity leg (§6 row 10) has not run: the rig injects directly to Kafka and never reaches syslog-ng or the aggregator.

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
2. **Keep the flat event format.** OpenSearch templates are `dynamic: false` and the engine reads flat fields, so nesting would mean rewriting both for no RCA gain. Add flat fields using OpenTelemetry and ECS meanings, with a mapping table for export: `event_action`, `event_state` (`raise|clear|point`), `severity_native_text`, `severity_native_code`, `observed_ts`, `mib_module`, `mib_bundle_version`, and `parser_confidence` as a level, not a number.
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
| 4 | Add `platform_owned` to `tenant_attribution`; update `TenantEnrichmentMissRateJumped` and its promtool test | router | Queued |
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

## 6a. All vendors (owner, 2026-11-09, binding)

Cisco SD-WAN is the first vendor because it is the one the lab has. It is not the scope. The programme covers Cisco (IOS, IOS-XE, NX-OS, IOS-XR, ASA, Catalyst SD-WAN), Juniper, Nokia (SR OS, SR Linux), HPE and Aruba, Dell, Arista, SONiC, Extreme, and the other vendors Correlix detects: Huawei, Fortinet, Palo Alto, Check Point, F5, MikroTik, Ruckus, Sophos, Ubiquiti. Each fix must be a mechanism that a new vendor plugs into, with no vendor names in engine logic.

### Coverage measured on 2026-11-09

| Layer | Today |
|---|---|
| Detection | 20 vendor profiles (`internal/vendorprofile/profiles`) |
| Enterprise MIBs in the OID index | **4**: Nokia (3,061 nodes), Cisco (700), Juniper (366), Arista (122), plus 1,500 standard nodes |
| Vector syslog body grammars | **3**: `%FAC-SEV-MNEMONIC`, SR Linux, FortiGate key-value. Nothing else sets `parser_id` |
| Engine syslog rules naming a vendor | Cisco 13, Arista 9, Juniper 4, Nokia 2; Fortinet and Palo Alto in the catalogue lane only |
| Engine trap rules naming a vendor | Cisco 6, Juniper 4, Nokia 3, Arista 3; standard and any-vendor 11 |
| HPE/Aruba, Dell, Extreme, SONiC | **No enterprise MIB, no grammar, no vendor rule.** Only standard-MIB traps and generic rules reach the engine |

### Three layers, in order

1. **Standard layer, every vendor at once.** RFC 5424 and 3164 envelope parsing, `IF-MIB`, `BGP4-MIB`, `OSPF-MIB`, `ISIS-MIB`, `ENTITY-MIB`, `LLDP-MIB`, `BFD-STD-MIB` (RFC 7331, not yet indexed), `HOST-RESOURCES-MIB`, flows. This gives every vendor, SONiC especially, useful results without a vendor pack.
2. **Inventory-driven vendor.** Vendor comes from discovery (`sysObjectID` and the vendor profiles), not from guessing at message text. This moves PR 12 up: it now lands right after Tranche 0, because grammar selection and the coverage scorecard both depend on it. A sender not in inventory falls back to format matching, recorded as such.
3. **Vendor packs.** One format per vendor: envelope and body grammars, pinned MIBs, rule rows, a severity map and fixtures, each row carrying its fidelity. Adding a vendor means adding a pack, not changing engine or pipeline code. Cisco SD-WAN (PRs 7 to 9) is the first pack and proves the format. Other vendors' packs follow PR 8's mechanism.

### Priority

By market relevance and owner's list, and re-ranked by the unknown trap OIDs and unparsed formats customers actually send (PR 14 measures both):

1. **First wave:** Cisco classic IOS/XE/NX-OS/XR (syslog grammar exists, MIB and rule gaps), Juniper, Arista, Nokia.
2. **Second wave:** HPE/Aruba, Dell, Extreme, SONiC.
3. **Third wave:** Huawei, Fortinet, Palo Alto, Check Point, F5, then the rest.

### Honest fidelity

Only Cisco can be proven on the lab. Every other row ships `doc_claimed`, labelled so in the UI, and it can never be part of the confirming pair when `CORR_FIDELITY_WEIGHTING` is on. A row needs a cited vendor source and a fixture. Promotion needs a real capture. Tracker 249 and the owner's hardware rule still apply, so no device purchase is implied. Containerised network OSes could supply real captures with no hardware; the vendor research reports which are usable.

### Vendor sources and order

Per-vendor formats, MIB sources, licences and capture options are in `docs/design/research/VENDOR_PACK_SOURCES_2026-11-09.md`.

Defects that report found, confirmed against the code:

- **RFC 5424 is not auto-detected.** `core.conf` runs `syslog-parser()` with no flags, and syslog-ng only uses its RFC 5424 parser when `syslog-protocol` is set. Junos structured-data frames, and any other sender using RFC 5424, go through the legacy parser. This is an all-vendor defect, so PR 10 comes first in the vendor order, and its capture decides the fix.
- **IOS-XR does not parse.** `%ROUTING-BGP-5-MAXPFX :` has four parts and a space before the colon, and fails both the vendor test and the grammar. Nokia SR OS, Comware and Extreme EXOS formats also match nothing.
- **Arista is mislabelled.** Real agents such as `Rib` are not in the Arista app list, so `Rib: %BGP-3-NOTIFICATION` is labelled Cisco. Inventory-driven vendor (PR 12) fixes this.
- **Indexed MIBs have silent gaps.** `ARISTA-MLAG-MIB`, `TIMETRA-PORT-MIB` and `TIMETRA-VRTR-MIB` contribute 0 nodes, and `BFD-STD-MIB` and `CISCO-BFD-MIB` are absent.
- **SONiC:** no vendor profile; it reports the net-snmp enterprise number. Upstream ships no traps today (the report cites an unmerged PR), so SONiC relies on polling, syslog and sFlow. Its rsyslog template puts the severity word where syslog-ng expects the program name.
- **Flows:** an exporter that samples but reports no rate, reportedly including Nokia SR OS cflowd, reads as 1:1. PR 5's `sampling_status` should later say "vendor known to sample, none reported".

Order after PR 8's mechanism lands: syslog envelope (PR 10), Nokia SR OS, Cisco IOS-XR and missing Cisco MIBs, Juniper, Arista, SONiC, Extreme EXOS, then AOS-CX, Comware, Dell OS10, VOSS, then the third wave. Nokia SR OS goes first because its event tables were verified from vendor documentation.

Applied recommendations (owner directive: proceed on best recommendation):

- **MIBs:** fetch-only, sha256-pinned, commit-pinned where the host allows, never vendored; vendor source first.
- **Mirrors:** Nokia and Arista are fetched from a LibreNMS commit or an unversioned vendor URL today. D4's official-source rule is met for Cisco; the others stay as they are until the owner decides on portal accounts.
- **Elastic integrations** (Elastic License 2.0) are a format reference only, never copied. SC4S and napalm-logs (Apache-2.0) may be reused with attribution.

**Open for the owner, nothing blocked meanwhile:**

- Vendor portal accounts for login-gated MIBs. Recommendation: yes for Nokia, Juniper and Extreme, defer Dell, HPE and Huawei. Where there is no account, the vendor gets standard MIBs only, labelled as such.
- Free network OS images for real captures, software only. SR Linux needs no registration; cEOS and vJunos need accounts. Recommendation: approve, starting with SR Linux, once the host is less loaded. Until then these rows stay `doc_claimed` (tracker 249 is unchanged).

### Coverage scorecard

PR 14 reports per vendor and per lane: MIBs present, grammar present, rules by fidelity, live parse rate, unknown OIDs. CI ratchets the row count and fixtures, so coverage cannot silently regress. It can be shown on the Telemetry Coverage page.

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

## 9. Owner decisions (approved 2026-11-09, binding)

| # | Decision | Final direction |
|---|---|---|
| D1 | Community string | Drop it. Store only present/absent. Never expose it in logs, errors or the UI |
| D2 | `confd` audit noise | Classify and deduplicate; no suppression on devices. Individual audit records are preserved, and the UI groups repeats with occurrence counts |
| D3 | Viptela severity | Vendor-aware rules. Only qualifying critical events create incidents automatically. Lower-severity telemetry is retained for investigation and correlation |
| D4 | MIB source | Cisco's official GitHub repo: exact commit pinned, checksums verified, licensing and OID mappings validated before deployment |
| D5 | Raw storage | No separate raw store in v1. Kafka's 72 hours gives replay, and original payloads are kept beside normalized records where feasible. The forensic limit is documented |
| D6 | Ownership label | `platform_owned` internally, "Platform device" in the UI, consistent across filters, APIs and dashboards |
| D7 | Audit usernames | Retained for security attribution, with role-based access, tenant isolation, audit trails, controlled exports and retention limits **now**, not after a later PII policy |
| D8 | Lab community string | Rotate and treat the old value as compromised. Verify collectors and devices afterwards. Prefer SNMPv3 where supported |

### Implementation rules (owner)

1. **Event ingestion is not incident creation.** A warning or informational event can matter once correlated with another. Ingest relevant events, assign vendor-specific severity, and let correlation and confidence decide incidents.
2. **Deduplication must not destroy evidence.** Repeated traps, syslog and audit events keep `first_seen`, `last_seen`, `occurrence_count`, device identity and correlation identifiers. Original security audit events stay accessible for their retention period.
3. **The 72-hour Kafka limit is a deliberate v1 tradeoff,** not a forensic archive. Storage sits behind an interface so durable raw retention can be added later without redesigning parsing.

**Final directive:** a single-box, enterprise-quality enrichment engine. Do not sacrifice parsing correctness, tenant isolation, security or forensic integrity for a simpler deployment; reduce infrastructure complexity instead.

### How the decisions change the plan

- **PR 11 (D2, rule 2):** deduplication is at read time over a stable key, so every stored audit document survives. The Logs page groups repeats with first seen, last seen and count.
- **PR 8/9 (D3, rule 1):** a typed rule's catalogue severity decides whether a lone event can open an object. Only qualifying critical events carry `crit`; lower ones reach the engine below the open floor, where they can still join a component.
- **PR 7 (D4):** `FETCH_PINS` URLs name a commit, not a branch. The licence question is resolved in that PR's report: `cisco-mibs` shows no licence file, so nothing is redistributed until it is settled.
- **New PR 15 (D5):** keep the original syslog payload as a stored, unindexed field after the capture in PR 10, and document the forensic limit in the operator docs. PR 10 delivers the field: `message_original` on every syslog frame, accepted at about +11.5% mean JSON per document on the lab (808 to 901 bytes over 3,825 frames). Still owed: the operator docs.
- **New PR 16 (D7):** audit and close gaps in access, audit trail, export control and retention for syslog carrying usernames, with a §3a test.
- **PR 4 (D6):** the label change also covers API filters and dashboards.

### Lab rotation order (D8)

Rotating before PR 1 is live would write the new value to OpenSearch in clear as well, so the order is:

1. Deploy PR 1 and confirm new trap documents carry no community value.
2. On each device, add the new credential alongside the old one, ideally SNMPv3 where supported. Devices are controller-managed, so use the vManage template rather than the CLI.
3. Update Correlix's per-device credentials and confirm polling and trap attribution. `guardTrapCommunity` drops the device identity on a mismatch, so a wrong value shows up as `inventory_missing` traps.
4. Remove the old credential from every device and verify again.
5. Delete the old lab trap indices, which the owner's lab-data rule allows.

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
| HMAC community fingerprint | **Not built** | D1 |
| Sampling status `ambiguous` | **Replaced** | Semantics are settled, §4 |
| Tenant by IP or exporter, with confidence | **Rejected** | Conflicts with the 2026-11-01 decision |
| Immutable raw object store and replay | **Not in v1** | D5: original payloads kept where feasible, Kafka replay for 72 hours, storage interface left open |
| New alarm state machine | **Rejected** | Engine already does it, §5.4 |
| Parser confidence | **Adapted** to levels | The owner's directive asks for parser confidence. A float would be false precision, so expose levels derived from `parser_status` and the rule's fidelity |
| IPFIX template registry and fingerprints | **Rejected** | goflow2 owns templates |

## 11. Still unverified

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
