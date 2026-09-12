<!--
  P5 — Firewall / security telemetry families (research pass, tracker #73).
  Status 2026-06-15: COMPLETE re-run of the previously rate-limited P5 pass
  (which had 0 verified claims). This document captures the adversarially
  primary-source-VERIFIED security/firewall telemetry families across Palo Alto
  (PAN-OS), Fortinet (FortiOS), Cisco (ASA + Firepower/FTD), and Versa (SD-WAN/
  SASE), mapped to the platform's source-agnostic canonical signal contract.

  Method: WebSearch + WebFetch, primary sources only (vendor MIB source, vendor
  syslog/log-field references, official admin guides, RFCs). Every load-bearing
  claim is tagged VERIFIED (with source URL) or UNVERIFIED. Negative results
  (a feature confirmed ABSENT) are themselves marked VERIFIED ABSENT.

  Feeds: docs/design/telemetry-coverage-reference.md §"Firewall / NGFW (P5)".
  Methodology companion: memory netops-firewall-onboarding-methodology.
  NO code in this pass — research only (CLAUDE.md guardrail).
-->
# P5 — Firewall / Security Telemetry Families (Foundation, #73)

**Goal.** Extend the source-agnostic single-contract (`device_*{device,vendor,…}`)
to the firewall/security plane across the four GTM-relevant vendor families, for
the RCA/correlation engine. Two planes, as everywhere:

- **Metric plane** → canonical `device_fw_*` / `device_sdwan_*` names (SNMP poll,
  controller-API fallback).
- **Event plane** → a normalized `fw_event` schema (vendor syslog → Vector
  per-vendor parser → OpenSearch; high-value events also onto the correlation
  bus, mirroring the metric+trap lane).

**Verification scorecard (this pass):** ~70 load-bearing claims adjudicated.
**~52 VERIFIED** (incl. 5 VERIFIED-ABSENT negative results), **~18 UNVERIFIED /
gap**. The biggest single finding: **per-event threat/deny detail is syslog-only
on every vendor** — SNMP gives volume (counters/gauges), not forensics — so the
event plane is the load-bearing one for firewall RCA, exactly as the onboarding
methodology already asserts.

**Cross-vendor truth (VERIFIED on ≥3 vendors):**
- Site-to-site IPsec **per-tunnel up/down is not reliably an SNMP gauge** —
  PAN has no object at all; Cisco models it as row-presence (down = row gone, not
  a value transition); FortiGate is the exception with a real `down(1)/up(2)`
  enum. Build tunnel-state collectors around **row-presence diffing + the up-count
  aggregate**, not value transitions.
- **"Policy denies" is event-derived, never an SNMP counter** — FortiGate's
  `fgFwPolPktCount/ByteCount` are *total* pass-through counters (a prior-note
  error, corrected below); PAN/Cisco have no per-policy deny gauge. Denies = count
  of `action=deny` log events.
- **CPU/memory on appliances often rides standard MIBs, not the vendor MIB** —
  PAN and Versa both expose CPU/mem via **HOST-RESOURCES-MIB** (`1.3.6.1.2.1.25`),
  not an enterprise `panSys*`/`versa*` object. Cisco uses CISCO-PROCESS-MIB /
  CISCO-MEMORY-POOL-MIB (with a 32-bit wrap caveat on large-RAM boxes).

---

## 1. Palo Alto — PAN-OS

PAN-COMMON-MIB enterprise root **`1.3.6.1.4.1.25461`**. Numeric OIDs corroborated
against the canonical MIB file (LibreNMS mirror) + oidref/mibbrowser; PAN prose
docs publish object *names*, not numbers (verify against the bundled MIB zip
before shipping a collector).

### SNMP (metric plane)
- **Sessions** (`panSession` subtree `…25461.2.1.2.3`) — VERIFIED:
  `panSessionUtilization` `.3.1` (% gauge, the alert signal), `panSessionMax`
  `.3.2`, `panSessionActive` `.3.3`, per-proto `.3.4/.5/.6` (TCP/UDP/ICMP),
  `panSessionActiveSslProxy` `.3.7`, `panSessionSslProxyUtilization` `.3.8`.
- **HA** (`panSys` subtree `…25461.2.1.2.1`) — VERIFIED:
  `panSysHAState` `.1.11`, `panSysHAPeerState` `.1.12`, `panSysHAMode` `.1.13`
  (disabled / active-passive / active-active). All DisplayString → enum-map.
- **GlobalProtect remote-access tunnels** (`panGlobalProtect` `…2.1.2.5`) —
  VERIFIED: `panGPGWUtilizationPct` `.5.1.1`, `…MaxTunnels` `.5.1.2`,
  `…ActiveTunnels` `.5.1.3`. Aggregate gateway counts/util, **not** per-tunnel.
- **CPU/memory** — VERIFIED via **HOST-RESOURCES-MIB** (`hrProcessorLoad`
  `1.3.6.1.2.1.25.3.3.1.2`, an average of packet-processing cores;
  `hrStorage` `1.3.6.1.2.1.25.2` for memory). `hrDeviceDescr` distinguishes
  MP-System vs DP-System. **No `panSys` CPU/mem objects exist.**
- **Site-to-site IPsec per-tunnel state** — **VERIFIED ABSENT**: no
  `panVpnFlow*`/IPsec-SA-status object in PAN-COMMON-MIB. Must come from XML-API
  op-commands (`show vpn ipsec-sa` / `show vpn flow`) or the THREAT/SYSTEM logs.
- **Threat/IPS counters** — **VERIFIED ABSENT** via SNMP. Threat telemetry =
  THREAT syslog only.
- **Traps** — VERIFIED coarse: essentially one notification `panCommonEventLog`;
  no dedicated HA/failover trap OID. Prefer polling `panSysHAState`.

### Syslog (event plane)
- VERIFIED: comma-separated **CSV**, classified on field **index 3 (`Type`)** +
  **index 4 (subtype `Threat/Content Type`)**. Preamble: `FUTURE_USE, Receive
  Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, …`.
- Log types (17, VERIFIED): Traffic, Threat, URL Filtering, Data Filtering,
  HIP Match, GlobalProtect, IP-Tag, User-ID, Decryption, Tunnel Inspection, SCTP,
  Config, Authentication, System, Correlated Events, GTP, Audit. **URL Filtering /
  WildFire / Data Filtering are SUBTYPES of the Threat log** (shared schema).
- **TRAFFIC fields** (VERIFIED, exact PAN identifiers): `action`, `src`, `dst`,
  `sport`, `dport`, `proto`, `app`, `rule`, `from` (src zone), `to` (dst zone),
  `srcuser`, `bytes` / `bytes_sent` / `bytes_received`, `sessionid`.
- **THREAT fields** (VERIFIED): Traffic base + `threatid` (name + numeric ID in
  parentheses — **not** a separate numeric field), `thr_category`, `severity`
  (informational/low/medium/high/critical), `direction`. **THREAT does NOT carry
  byte fields** (Traffic-only — corrects a prior assumption).

### API / streaming
- **XML API `/api/`** (VERIFIED mechanism): `type=keygen` → `X-PAN-KEY`;
  `type=op` runs any op CLI as XML (the right plane for IPsec tunnel state + HA
  detail that SNMP omits); `type=log` = async job-id-poll bulk log query.
- **Log forwarding** (VERIFIED): Syslog profiles (≤4 servers, TCP/UDP/SSL=TLS1.2,
  **BSD RFC3164 or IETF RFC5424**, custom templates) — the high-volume firehose.
  HTTP/S forwarding is event-driven and **"not recommended for high volume."**
- **REST API `/restapi/`** (VERIFIED config-only): Objects/Policies/Network/Device
  CRUD; commit via XML API. Not a telemetry plane.
- **Plane choice:** metrics = SNMP poll; state gaps (IPsec/HA detail) = XML-API
  `type=op`; events = syslog RFC5424/TCP → Vector parser.

---

## 2. Fortinet — FortiOS / FortiGate  (deepened; prior notes corrected)

FORTINET-FORTIGATE-MIB enterprise root **`1.3.6.1.4.1.12356.101`** (VERIFIED).
OIDs cross-checked against the ASN.1 MIB text (netdisco + librenms) + oidref.

### SNMP (metric plane) — with three corrections to prior notes
System/sessions branch `fgSystemInfo` = `…101.4.1` — VERIFIED:
`fgSysCpuUsage` `.3`, `fgSysMemUsage` `.4`, `fgSysSesCount` `.8`,
`fgSysLowMemUsage` (kernel mem %) `.9`.
- **CORRECTION:** session setup rate `fgSysSesRate1` = **`…4.1.11`**, NOT `.9`
  (prior note had `.9`, which is actually `fgSysLowMemUsage`).
- **HA** (`fgHighAvailability` `…101.13`) — VERIFIED:
  `fgHaSystemMode` `.13.1.1` (`standalone(1)/activeActive(2)/activePassive(3)`),
  per-VDOM `fgVdEntHaState` `…101.3.2.1.1.4` (TC `FgHaState
  {primary(1),secondary(2),standalone(3)}` — older copies label these
  master/backup/standalone, **same integers**; the prior 1/2/3 mapping was right),
  `fgHaStatsSyncStatus` `…101.13.2.1.1.12` (`{unsynchronized(0),synchronized(1)}`
  — **note 0/1, not 1/2**).
- **VPN** (`fgVpn` `…101.12`) — VERIFIED: aggregate `fgVpnTunnelUpCount` `.12.1.1`;
  per-tunnel `fgVpnTunEntStatus` `…101.12.2.2.1.20` (`{down(1),up(2)}` — matches
  prior note). FortiGate is the **one vendor with a real per-tunnel state enum.**
- **Policy stats** (`fgFwPolStatsTable`) — VERIFIED: `fgFwPolPktCount {entry 2}`,
  `fgFwPolByteCount {entry 3}` (Counter32), keyed by policy-id + VDOM.
  **CORRECTION:** these are **total pass-through** counters, **NOT denies** — the
  prior note's "device_fw_policy_denies = fgFwPolPktCount/ByteCount" is wrong.
  Denies = syslog `action=deny`.
- **Threat counters via SNMP — VERIFIED THEY EXIST** (resolves the prior "logs
  only?" open question): IPS branch `fgIps` `…101.9` table `…9.2.1.1`
  (`fgIpsIntrusionsDetected` `.1`, `…Blocked` `.2`, per-severity, anomaly);
  AV branch `fgAntivirus` `…101.8` table `…8.2.1.1` (`fgAvVirusDetected` `.1`,
  `…Blocked` `.2`, per-protocol). **Aggregate per-VDOM rates** — good for z-score
  baselining; per-event detail (which signature/host/file) is syslog-only.
- **Conserve mode** — PARTIAL: **no live "in conserve mode" boolean** in the MIB;
  only threshold config OIDs `fgSIAdvMem*ConsThrsh` exist. Live signal = the
  conserve-mode enter/leave **syslog event** (or derive by comparing
  `fgSysMemUsage` vs the threshold OIDs).

### Syslog (event plane) — VERIFIED (FortiOS Log Message Reference)
- Default **`key=value` space-separated**; **CEF** optional (`set format cef`).
- Three top-level `type`: **`traffic`, `utm`, `event`**. UTM `subtype`: `virus`,
  `webfilter`, `ips`, `app-ctrl`, `dlp`, `waf`, `dns`, `anomaly` (DoS), `ssl/ssh`,
  `emailfilter`, `voip`. Event `subtype`: `system`, `vpn`, `ha`, `user`, `router`…
- RCA fields (VERIFIED present): `devname`, `vd`, `type`, `subtype`, `level`,
  `action`, `srcip`/`dstip`/`srcport`/`dstport`, `service`, `app`, `policyid`,
  `sentbyte`/`rcvdbyte`, `logid`. IPS: `attack`, `attackid`, `severity`. AV:
  `virus`, `filename`.
- CEF mapping rule (VERIFIED): `type:subtype`→`cat`; CEF `SignatureId` = **last 5
  digits of the 10-digit `logid`**; unmatched fields carry an `FTNTFGT` prefix.

### API / streaming
- FortiOS **REST `/api/v2/monitor/…`** (VERIFIED direction): `system/ha-statistics`,
  `vpn/ipsec`, `firewall/policy` (hit counts), `system/resource/usage` — richest
  live source but poll-based per-device. No native gNMI/Kafka export; "streaming"
  = syslog.
- **Plane choice:** metrics (CPU/mem/sessions/rate/tunnel-up/HA/IPS+AV counters) =
  SNMP; events (IPS/AV hits, VPN up/down, HA failover, conserve enter/leave) =
  syslog; REST = gap-filler (live policy hit counts, HA member health).

---

## 3. Cisco — ASA + Firepower/FTD

**Method caveat:** `cisco.com/c/td/docs` and `community.cisco.com` returned HTTP
403 to the fetcher. MIB objects were verified against **Cisco's official published
MIB source** (`raw.githubusercontent.com/cisco/cisco-mibs`, treated as PRIMARY);
syslog message IDs / FMC API rest on directly-fetched CiscoDevNet GitHub +
ciscolearning pages and Cisco-sourced search snippets. No cisco.com page read
byte-for-byte — flagged per row.

### SNMP (metric plane)
- **Sessions** — VERIFIED: `cufwConnGlobalNumActive` `1.3.6.1.4.1.9.9.491.1.1.1.6`
  (CISCO-UNIFIED-FIREWALL-MIB, Gauge32) — primary live-session gauge; setup rate
  `cufwConnGlobalConnSetupRate1` `…491.1.1.1.10` (**CORRECTION:** the assumed
  `cufwConnGlobalNumSetupRate1Min` does not exist). Also `cfwConnectionStatValue`
  `1.3.6.1.4.1.9.9.147.1.2.2.1.5` (CISCO-FIREWALL-MIB), indexed by
  `cfwConnectionStatType` (currentInUse/currentOpen/high…).
- **Failover/HA** — VERIFIED: `cfwHardwareStatusValue` `…147.1.2.1.1.3`
  (enum incl. **active(9)/standby(10)**), table indexed by `cfwHardwareType`
  **primaryUnit(6)/secondaryUnit(7)**; detail string `…147.1.2.1.1.4`.
- **IPsec** — VERIFIED with design caveat: `cikeTunStatus`
  `1.3.6.1.4.1.9.9.171.1.2.3.1.35` and `cipSecTunStatus` `…171.1.3.2.1.51`
  (enum active(1)/destroy(2)). **A live row ~always reads active(1); down = row
  disappears (NoSuchInstance).** Collector = row-presence diffing, not value
  transitions.
- **CPU/mem** — VERIFIED: `cpmCPUTotal1minRev` `1.3.6.1.4.1.9.9.109.1.1.1.1.7`
  (use the Rev/1min — `cpmCPUTotal5sec` is deprecated); `ciscoMemoryPoolUsed/Free`
  `1.3.6.1.4.1.9.9.48.1.1.1.5/.6`. **Caveat:** 32-bit mem gauges wrap on large-RAM
  boxes → prefer CISCO-ENHANCED-MEMPOOL-MIB `cempMemPoolHCUsed/HCFree`
  (**UNVERIFIED at OID level** — MIB not fetched).
- **FTD SNMP** — VERIFIED (snippet): v1/v2c/v3 **GET-only, no SET**; unified health
  (CPU/mem/Snort/HA/cluster). **Lina-only** (per-Snort stats not SNMP-reachable);
  **IPsec-via-SNMP contested on FTD** (often NoSuchInstance) — needs per-version
  on-box walk. **Security events are NOT in SNMP on FTD** (eStreamer/syslog only).

### Syslog (event plane) — format `%ASA-Level-MessageID` / `%FTD-…`
- **Deny/ACL** — VERIFIED: **106023** (`%ASA-4-106023`, deny by ACL, logged even
  without the `log` keyword, real pre-NAT IP); **106100** (per-flow ACL hit with
  `hit-cnt`, permit+deny, configurable level).
- **Connection build/teardown** — VERIFIED: **302013/302014** (TCP build/teardown;
  302014 carries connection_id, duration, bytes, **`reason_string`** +
  teardown_initiator — the RCA-critical field), **302015/302016** (UDP). Direction
  gotcha: `outbound` keyword flips src/dst.
- **Failover** — VERIFIED/PARTIAL: **101001/101002** (cable OK/bad),
  **411001/411002** (interface line-protocol up/down). 105xxx (105005 lost-comms,
  105043 failover-link-down…) meanings confirmed but per-ID severity not
  re-verified; the explicit ACTIVE/STANDBY role-change ID **not pinned (gap)**.
- **IPsec/VPN** — VERIFIED (IKEv2 is the canonical modern pair): **750006/750007**
  (IKEv2 SA UP/DOWN, with Local/Remote, Username, **Reason**); AnyConnect
  **722022/722023**. IKEv1 PARTIAL (713049/713120 confirmed; 713228 UNVERIFIED).
- **Resource/session exhaustion** — VERIFIED: **201003** (embryonic/half-open
  limit — SYN-flood signal), **201002** (max connections), **211001** (memory
  allocation error — pre-crash). 321xxx **UNVERIFIED** — drop unless on-box.
- **FTD security events over syslog** — VERIFIED (IDs, FTD 6.3+): **430001**
  intrusion, **430002** connection START, **430003** connection END. Connection
  fields (VERIFIED via sample): Protocol, Src/DstIP+Port, OriginalClientIP,
  Ingress/EgressZone, `AccessControlRuleName`, `AccessControlRuleAction`,
  UserName, Initiator/ResponderBytes (**END/430003 only**), ApplicationProtocol,
  URLCategory/Reputation. **Field set is version-dependent** (~6.2.3→6.3). 430001
  intrusion fields (GID/SID/Classification/Impact) **PARTIAL** (no verbatim sample).

### API / streaming
- **eStreamer** — VERIFIED (snippet): client-initiated, **TCP/8302 over TLS**,
  PKCS12 cert auth; intrusion/connection/file/malware/host/user events; managed
  devices stream intrusion-only. Modern client = **eNcore** (Python); legacy Perl
  SDK. The structured real-time security firehose.
- **FMC REST** — VERIFIED (direct fetch): auth
  `POST /api/fmc_platform/v1/auth/generatetoken` → `X-auth-access-token`
  (30 min, refresh ×3); config base `/api/fmc_config/v1/…` — **config/inventory
  only, NOT events**; rate-limited 120→300 GET/min.
- **ASA REST** — VERIFIED legacy: capped at 9.16, no longer enhanced, EoL
  announced. **Do not build on it.**
- **Plane choice:** real-time security events = eStreamer or syslog (FMC REST does
  NOT serve events); config/inventory = FMC REST → SoT reconciler; health = SNMP.

---

## 4. Versa — SD-WAN / SASE security

**Bottom line (VERIFIED direction):** box SNMP is shallow (host resources +
interfaces via *standard* MIBs); the **primary security/SD-WAN telemetry plane is
the API + syslog/IPFIX log plane.** Versa enterprise OID arc `1.3.6.1.4.1.42359`
(PEN 42359) exists but **no security-plane MIB object** (tunnel/session/HA) is
documented in any reachable primary source — the per-release `Versa-MIB.pdf` is
login-gated.

### SNMP
- VERIFIED: SNMP v1/v2c/v3 (USM MD5/SHA, AES/DES, VACM, traps/informs); MIBs are
  not inline-documented (per-release `Versa-MIB.pdf` in the FlexVNF download dir).
- VERIFIED: CPU/RAM/disk/interfaces via **standard HOST-RESOURCES-MIB**
  (`1.3.6.1.2.1.25`) — supported 22.1.3+. Enterprise arc `…42359.2.2` referenced.
- **Tunnel/session/HA via SNMP — UNVERIFIED, likely ABSENT.** Treat as
  API-sourced. (The `42359.x` security-object tree is paywalled — explicit gap.)

### Syslog / event plane — VERIFIED
- VOS exports **IPFIX + syslog**; Analytics LCE re-exports to 3rd-party collectors.
- Format = **KVP, comma-separated, leading ISO8601 timestamp + log identifier**
  (VERIFIED via literal log lines in Flow Logs / DoS Protection Logs docs).
- Log identifiers (VERIFIED): `accessLog`, `idpLog`, `urlfLog`, `avLog`,
  `dosThreatLog`, `ipfLog`, `denyLog`, `sfwAccessLog`, `authEventLog`,
  `flowMonLog`, `sdwanSlaPathViolLog`, `sdwanPathMosLog`, `alarmLog`, `eventLog`,
  `systemLoadLog`.
- `accessLog` (NGFW, VERIFIED): `applianceName`, `tenantName`, `flowId`,
  `sourceIPv4Address`/`destinationIPv4Address`, `sourceTransportPort`/
  `destinationTransportPort`, `action`, `rule`, `appIdStr`, `protocolIdentifier`,
  `fromUser`, `sentOctets`/`recvdOctets`, `urlCategory`, `appRisk`.
- `dosThreatLog` (VERIFIED): `threatType` (Flood/Scan), `dosAttackName`,
  `dosAction`, `severityLevel`, `dosAttacker`/`dosVictim`, `fromZone`/`toZone`.
- `idpLog`/`avLog` field lists — PARTIAL/UNVERIFIED (search-summary, not direct
  fetch); field names are pattern-consistent.

### API / streaming — the primary plane
- **Versa Analytics REST** (VERIFIED): base
  `https://{analytics}/versa/analytics/v1.0.0/data/provider/tenants/{tenant}/features/{feature}/?…`;
  OAuth bearer from Director `:9183/auth/token`. Exposes SD-WAN SLA & QoS, NGFW/
  stateful-fw/CGNAT, app monitoring, system health. Query shape example:
  `/features/SDWAN/?qt=rangeseries&…&q=linkstatus(site,accckt)&metrics=availability`.
  **Gap:** the full `features/` catalog is app-internal (Analytics → Tools →
  Documentation), so feature names beyond `SDWAN` are UNVERIFIED.
- **Versa Director REST** (VERIFIED): port 9182 = HTTPS Basic, 9183 = OAuth
  (token 900s, refresh 86400s); YANG `/api/config` + `/api/operational`; custom
  `/vnms/…`. **Caveat (VERIFIED, quoted):** "status information provided by live
  API calls is often not complete" → Versa recommends **streaming alarms to
  collectors** rather than polling. **Gap:** exact operational URIs for IPsec
  tunnel/session/SLA-monitor not confirmed.
- **SD-WAN/SLA** (VERIFIED via SD-WAN Dashboards): SLA Delay, SLA Loss Ratio;
  link/path state Down/Degraded/Up/Indeterminable + availability %; session
  counts; bandwidth Tx/Rx. **Jitter** not confirmed as a named dashboard metric.

---

## 5. Verification Table (consolidated, load-bearing claims)

| Vendor | Claim | Status | Source |
|---|---|---|---|
| PAN | `panSessionUtilization` …25461.2.1.2.3.1 (% gauge) | VERIFIED | docs.paloaltonetworks.com monitor-statistics-using-snmp; oidref 1.3.6.1.4.1.25461.2.1.2.3 |
| PAN | `panSessionMax/.3.2`, `Active/.3.3`, per-proto `.4-.6`, SslProxy `.7/.8` | VERIFIED | oidref 1.3.6.1.4.1.25461.2.1.2.3 |
| PAN | `panSysHAState/.1.11`, `HAPeerState/.1.12`, `HAMode/.1.13` | VERIFIED | librenms PAN-COMMON-MIB; mibbrowser.online; PAN identify-OID doc |
| PAN | GlobalProtect tunnel util/counts `…2.1.2.5.1.1-.3` | VERIFIED | oidref 1.3.6.1.4.1.25461.2.1.2.5.1.3 |
| PAN | Site-to-site IPsec per-tunnel state via SNMP | VERIFIED ABSENT | docs…/supported-mibs (negative) |
| PAN | Threat/IPS counters via SNMP | VERIFIED ABSENT | docs…/supported-mibs (negative) |
| PAN | CPU=hrProcessorLoad 1.3.6.1.2.1.25.3.3.1.2; mem=hrStorage (HOST-RESOURCES, not panSys) | VERIFIED | docs…/supported-mibs/host-resources-mib |
| PAN | Syslog CSV; classify on Type idx3 + subtype idx4; 17 log types | VERIFIED | docs…/use-syslog-for-monitoring/syslog-field-descriptions |
| PAN | TRAFFIC fields action/src/dst/sport/dport/proto/app/rule/from/to/srcuser/bytes/sessionid | VERIFIED | docs…/traffic-log-fields |
| PAN | THREAT fields threatid/thr_category/severity/direction; no byte fields | VERIFIED | docs…/threat-log-fields |
| PAN | XML API type=op (state plane), type=log async, REST config-only | VERIFIED | docs…/run-operational-mode-commands-api; rest-api-request-response-structure |
| PAN | Numeric OIDs not in prose; in bundled MIB zip | VERIFIED | docs…/resources/snmp-mib-files |
| Forti | Enterprise root …12356.101; fgSysCpuUsage .4.1.3, MemUsage .4, SesCount .8 | VERIFIED | oidref …101.4.1; FORTINET-FORTIGATE-MIB (netdisco/librenms) |
| Forti | setup rate fgSysSesRate1 = …4.1.11 (NOT .9) | VERIFIED (corrects prior) | oidref …101.4.1; Fortinet community tech-tip |
| Forti | fgVdEntHaState …101.3.2.1.1.4 {primary(1),secondary(2),standalone(3)} | VERIFIED | FORTINET-FORTIGATE-MIB verbatim |
| Forti | fgHaSystemMode …13.1.1 {standalone(1),activeActive(2),activePassive(3)} | VERIFIED | FORTINET-FORTIGATE-MIB verbatim |
| Forti | fgHaStatsSyncStatus …13.2.1.1.12 {unsynchronized(0),synchronized(1)} (0/1) | VERIFIED | FORTINET-FORTIGATE-MIB verbatim |
| Forti | fgVpnTunEntStatus …101.12.2.2.1.20 {down(1),up(2)}; fgVpnTunnelUpCount …12.1.1 | VERIFIED | FORTINET-FORTIGATE-MIB verbatim |
| Forti | fgFwPolPktCount/ByteCount are TOTAL counters, NOT denies | VERIFIED (corrects prior) | FORTINET-FORTIGATE-MIB |
| Forti | IPS counters fgIps …101.9.2.1.1; AV fgAv …101.8.2.1.1 (aggregate, per-VDOM) | VERIFIED | FORTINET-FORTIGATE-MIB |
| Forti | No live conserve-mode boolean OID (only threshold config OIDs) | VERIFIED/GAP | FORTINET-FORTIGATE-MIB |
| Forti | Syslog key=value default + CEF; type traffic/utm/event; IPS attack/attackid | VERIFIED | docs.fortinet.com FortiOS Log Message Reference; CEF mapping guide |
| Forti | REST /api/v2/monitor live state; no native streaming export | VERIFIED | docs.fortinet.com |
| Forti | fgTraps NOTIFICATION-TYPE OID definitions | UNVERIFIED (gap) | not isolated in fetched MIB excerpts |
| Cisco | cufwConnGlobalNumActive …9.9.491.1.1.1.6; setup rate …491.1.1.1.10 | VERIFIED | raw.githubusercontent.com/cisco/cisco-mibs CISCO-UNIFIED-FIREWALL-MIB |
| Cisco | cufwConnGlobalNumSetupRate1Min does NOT exist | VERIFIED (corrects assumption) | CISCO-UNIFIED-FIREWALL-MIB |
| Cisco | cfwHardwareStatusValue …147.1.2.1.1.3 active(9)/standby(10); primaryUnit(6)/secondaryUnit(7) | VERIFIED | raw.githubusercontent.com/cisco/cisco-mibs CISCO-FIREWALL-MIB.my |
| Cisco | cikeTunStatus …171.1.2.3.1.35 / cipSecTunStatus …171.1.3.2.1.51; down = row absent | VERIFIED | raw.githubusercontent.com/cisco/cisco-mibs CISCO-IPSEC-FLOW-MONITOR-MIB.my |
| Cisco | CPU cpmCPUTotal1minRev …109.1.1.1.1.7; mem ciscoMemoryPoolUsed/Free …48.1.1.1.5/.6 | VERIFIED | CISCO-PROCESS-MIB.my; CISCO-MEMORY-POOL-MIB.my |
| Cisco | cempMemPoolHCUsed/HCFree (large-RAM 64-bit) OIDs | UNVERIFIED (gap) | MIB not fetched |
| Cisco | FTD SNMP GET-only; security events not in SNMP; IPsec-via-SNMP contested | VERIFIED (snippet) | Cisco search snippets (cisco.com 403) |
| Cisco | ASA 106023 deny-by-ACL; 106100 per-flow ACL hit-cnt | VERIFIED | ASA Syslog Messages (snippet/DevNet) |
| Cisco | 302013/14 TCP, 302015/16 UDP; 302014 reason_string/bytes | VERIFIED | ASA Syslog Messages (snippet) |
| Cisco | 101001/02 cable, 411001/02 line-proto; ACTIVE/STANDBY role-change ID | PARTIAL/gap | ASA Syslog Messages (snippet) |
| Cisco | 750006/750007 IKEv2 SA up/down (+Reason); 722022/23 AnyConnect | VERIFIED | ASA Syslog Messages (snippet) |
| Cisco | 201003 embryonic limit, 201002 max conn, 211001 mem-alloc; 321xxx | VERIFIED (321xxx UNVERIFIED) | ASA Syslog Messages (snippet) |
| Cisco | FTD 430001 intrusion / 430002 conn-START / 430003 conn-END (6.3+); bytes END-only | VERIFIED (430001 fields PARTIAL) | FTD security-event syslog (sample) |
| Cisco | eStreamer TCP/8302 TLS, PKCS12, eNcore client | VERIFIED (snippet) | Cisco eStreamer/eNcore docs (snippet) |
| Cisco | FMC REST generatetoken; config-only (no events); 120→300 GET/min | VERIFIED | ciscolearning.github.io / CiscoDevNet (direct) |
| Cisco | ASA REST legacy, EoL, do not build | VERIFIED | Cisco ASA REST API notes (snippet) |
| Versa | SNMP v1/v2c/v3; CPU/mem/if via HOST-RESOURCES-MIB; PEN 42359, arc …42359.2.2 | VERIFIED | docs.versa-networks.com Configure_SNMP; support art. 23000028726 |
| Versa | Tunnel/session/HA via SNMP | UNVERIFIED (likely absent; MIB login-gated) | — |
| Versa | Syslog KVP comma-sep + ISO8601 + log identifier; accessLog/dosThreatLog fields | VERIFIED | docs.versa-networks.com Flow_Logs; DoS_Protection_Logs; Log Types overview |
| Versa | idpLog/avLog field lists | PARTIAL/UNVERIFIED | search summary only |
| Versa | Analytics REST base + OAuth from Director :9183; SD-WAN SLA/NGFW features | VERIFIED | docs.versa-networks.com Analytics_REST_API_Overview |
| Versa | Director REST 9182 Basic / 9183 OAuth; "live API status often not complete" → stream alarms | VERIFIED | docs.versa-networks.com Director_REST_API_Overview |
| Versa | SLA Delay + Loss Ratio + link state Up/Degraded/Down dashboards; jitter as named metric | VERIFIED (jitter UNVERIFIED) | docs.versa-networks.com SD-WAN_Dashboards |

---

## 6. Proposed Canonical-Family Mapping

### Metric plane (`device_fw_*` / `device_sdwan_*`)

| Canonical family | PAN-OS | FortiOS | Cisco ASA/FTD | Versa | Plane |
|---|---|---|---|---|---|
| `device_fw_sessions` | panSessionActive `…3.3` | fgSysSesCount `…4.1.8` | cufwConnGlobalNumActive `…491.1.1.1.6` | Analytics API (NGFW) | SNMP (Versa=API) |
| `device_fw_session_utilization` | panSessionUtilization `…3.1` | derive vs platform max | derive vs cap | — | SNMP/derived |
| `device_fw_session_rate` | — | fgSysSesRate1 `…4.1.11` | cufwConnGlobalConnSetupRate1 `…491.1.1.1.10` | — | SNMP |
| `device_fw_ha_state` | panSysHAState `…1.11` (+peer `.12`, mode `.13`) | fgVdEntHaState `…3.2.1.1.4` (+mode `…13.1.1`, sync `…13.2.1.1.12`) | cfwHardwareStatusValue `…147.1.2.1.1.3` (active9/standby10) | **GAP** (alarmLog/event?) | SNMP (Versa=event) |
| `device_fw_tunnel_state` (per-tunnel) | XML-API `show vpn ipsec-sa` | fgVpnTunEntStatus `…12.2.2.1.20` {down1/up2} | cipSec/cikeTunStatus **row-presence** | API/event | mixed |
| `device_fw_tunnels_up` (aggregate) | panGPGW…ActiveTunnels (GP only) | fgVpnTunnelUpCount `…12.1.1` | count active IPsec rows | Analytics API | SNMP/API |
| `device_fw_cpu_percent` | hrProcessorLoad `…25.3.3.1.2` | fgSysCpuUsage `…4.1.3` | cpmCPUTotal1minRev `…109.1.1.1.1.7` | HOST-RESOURCES `…25` | SNMP |
| `device_fw_mem_percent` | hrStorage `…25.2` | fgSysMemUsage `…4.1.4` | ciscoMemoryPoolUsed/Free (or cempHC) | HOST-RESOURCES `…25` | SNMP |
| `device_fw_ips_detected` / `_blocked` | — (event-only) | fgIps `…9.2.1.1.1/.2` | — (event-only) | Analytics API | SNMP (Forti) |
| `device_fw_av_detected` / `_blocked` | — (event-only) | fgAv `…8.2.1.1.1/.2` | — (event-only) | Analytics API | SNMP (Forti) |
| `device_fw_policy_denies` | **event-derived** | **event-derived** | **event-derived** | **event-derived** | event |
| `device_fw_conserve_mode` | — | **event-derived** (or threshold-derive) | — | — | event |
| `device_sdwan_path_latency` | — | — | — | Analytics SLA Delay | API |
| `device_sdwan_path_loss` | — | — | — | Analytics SLA Loss Ratio | API |
| `device_sdwan_path_jitter` | — | — | — | Analytics SLA (UNVERIFIED named) | API |
| `device_sdwan_tunnel_state` | — | — | — | Analytics linkstatus (Up/Degraded/Down) | API/event |

**Proposed NEW families** (beyond the shipped `fortios_*` + `device_session_count`):
`device_fw_session_utilization`, `device_fw_session_rate`, `device_fw_ha_state`,
`device_fw_tunnel_state` + `device_fw_tunnels_up`, `device_fw_ips_detected/_blocked`,
`device_fw_av_detected/_blocked`, `device_fw_policy_denies` (event-derived),
`device_fw_conserve_mode` (event-derived), and the Versa SD-WAN set
`device_sdwan_{path_latency,path_loss,path_jitter,tunnel_state}` (API-sourced).

### Event plane (`fw_event` normalized schema)

| `fw_event` field | PAN (CSV) | FortiOS (kv) | Cisco ASA / FTD | Versa (kv) |
|---|---|---|---|---|
| device | Serial→hostname | devname | hostname / FTD sensor | applianceName |
| tenant | (vsys) | vd | context | tenantName |
| category / subtype | Type idx3 / idx4 | type / subtype | msg-ID class / FTD evt-type | log identifier |
| severity | severity (THREAT) | level / IPS severity | %ASA level | severityLevel / signaturePriority |
| action | action | action | 106023 deny / RuleAction (FTD) | action / idpAction / dosAction |
| src / dst (+ports) | src/dst sport/dport | srcip/dstip srcport/dstport | conn endpoints | sourceIPv4Address/… ports |
| proto | proto | service/proto | protocol | protocolIdentifier |
| app | app | app | ApplicationProtocol (FTD) | appIdStr |
| rule | rule | policyid | access_group / RuleName (FTD) | rule |
| zone (from/to) | from / to | (vd) | IngressZone/EgressZone (FTD) | fromZone / toZone |
| user | srcuser | (user evt) | idfw_user / UserName | fromUser |
| threat / signature | threatid (+thr_category) | attack/attackid; virus | GID/SID (430001) | signatureMsg/signatureId; dosAttackName |
| bytes | bytes_sent/received | sentbyte/rcvdbyte | 302014 bytes; Init/RespBytes (430003) | sentOctets/recvdOctets |
| session_id | sessionid | (sessionid) | connection_id (302xxx) | flowId |
| teardown_reason | — | — | 302014 reason_string; 750007 Reason | — |

High-value events for the correlation bus (`control_plane` lane, mirroring the
metric+trap pattern): **VPN/IPsec down, HA failover, session-table/embryonic-limit
exhaustion, conserve-mode enter, IPS/DoS signature hit.**

---

## 7. Open Gaps / Needs Live Device

1. **FortiGate `fgTraps` NOTIFICATION-TYPE OIDs** — trap definitions (VPN up/down,
   HA switch, conserve, IPS) not isolated from fetched MIB excerpts. Relevant: we
   run an SNMP-trap pipeline; trap-driven HA/VPN alerts beat polling. Needs
   `snmptranslate -Tp` against the full MIB.
2. **Cisco — no cisco.com page read byte-for-byte (all 403).** Syslog format
   strings/severities + FTD support tables are snippet-derived. Hard-audit by
   fetching (via browser/proxy): ASA Syslog Messages guide, FTD
   security-event-syslog-messages, "Secure Firewall SNMP MIBs Reference."
3. **Cisco CISCO-ENHANCED-MEMPOOL-MIB OIDs** (`cempMemPoolHCUsed/HCFree`) — the
   correct large-RAM memory source — UNVERIFIED; fetch the MIB.
4. **Cisco FTD IPsec-via-SNMP** — frequently NoSuchInstance; needs per-version
   on-box `snmpwalk`.
5. **Cisco syslog IDs** — ACTIVE/STANDBY role-change ID not pinned; 321xxx and
   IKEv1 713228 UNVERIFIED. Anchors are 201002/201003/211001 + 750006/750007.
6. **Cisco FTD 430001 intrusion field list** — PARTIAL (no verbatim sample);
   pull one to lock GID/SID/classification.
7. **Versa `Versa-MIB.pdf` object list is login-gated** — the `…42359.x`
   security-object tree (tunnel/session/HA via SNMP) is UNVERIFIED; assume
   API/event-sourced. `device_fw_ha_state` source for Versa is unknown.
8. **Versa Director operational URIs** for IPsec tunnel/session/SLA-monitor not
   confirmed; Analytics `features/` catalog beyond `SDWAN` is app-internal.
9. **Versa idpLog/avLog fields + jitter metric** — search-summary only, not
   directly fetched.
10. **PAN numeric OIDs** corroborated via MIB files, not PAN prose — confirm
    against the per-version bundled MIB zip before shipping the collector. Op-cmd
    verbatim strings (`<show><vpn>…`) valid but not quoted (JS-rendered doc).
11. **Per-VDOM / per-context / per-tenant keying** — FortiGate IPS/AV/policy/HA
    tables are VDOM-indexed; resolve `fgVdEntName` to map counters→tenant
    correctly (strict-tenancy model). Same concern for ASA contexts and Versa
    `tenantId`.

All live-device validation should run on the clos lab (FortiGate `dmz-fw` is
already onboarded; PAN/Cisco/Versa need lab instances per the onboarding recipe).
