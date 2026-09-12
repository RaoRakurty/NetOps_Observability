# Security Section for Correlix — market/standards research (2026-08-25)

Commissioned by the owner (frontend/product wave item 9): how to build a
security section for NETWORK DEVICES that ties into the correlation engine.
Researched by a web-research agent against primary sources; fetch-blocked
sources (cisa.gov, cisco.com, ibm.com → HTTP 403) are marked. This document is
the design input; the v1 build decision is at the end.

## (a) Vendor → capability table

| Vendor | Ingests | Detections | UI emphasis |
|---|---|---|---|
| Cisco Secure Network Analytics (Stealthwatch) | NetFlow/IPFIX/sFlow from existing gear ("network as sensor") | ~100 behavioral heuristics → alarm categories (Recon, C&C, Exfiltration, DDoS, Data Hoarding, Policy Violation) | Host groups, per-host Concern Index, drill to flows [fetch blocked] |
| Darktrace NETWORK | Mirrored traffic incl. encrypted | Self-learning baselines, autonomous response | Threat Visualizer; **Cyber AI Analyst writes incident narratives** |
| ExtraHop RevealX | Packets + flow, out-of-band decryption | ML + curated signatures; lateral movement | Detection → forensics → response in one workflow; packet query from a detection |
| Vectra AI | Traffic + identity + cloud | 150+ AI models, ">90% of ATT&CK"; AI Triage/Stitching/Prioritization | **Prioritized ENTITY list** (hosts ranked by urgency); claims 99% alert-noise cut |
| Corelight Open NDR | Packets → Zeek + Suricata + YARA | Multi-layer + threat intel | **"Evidence-first"**: network data as high-fidelity evidence to SIEMs |
| Arista NDR (Awake) | Packet sensors | Adversarial modeling over inferred entities | EntityIQ knowledge graph; **kill-chain visualization across entities/protocols/time** |
| Plixer One (Scrutinizer) | NetFlow/IPFIX + DNS/L7 metadata | Flow analytics mapped to ATT&CK | Performance + security from the same flow data |
| Kentik | Flow + BGP feeds + SNMP | DDoS (low-FP), **BGP hijack/leak + RPKI validation**, threat-feed matches | Security inside the performance platform; RTBH/Flowspec mitigations |
| LiveAction ThreatEye | — | Appears discontinued/absorbed | — |
| FastNetMon | NetFlow v5/v9, IPFIX, sFlow, mirror | Per-host pps/bps/fps thresholds by hostgroup; detection in 1–2s | Headless + API; BGP blackhole via GoBGP/ExaBGP, Flowspec (Advanced), Kafka export |

**Takeaway:** packet NDRs (Darktrace/ExtraHop/Vectra/Corelight/Arista) need
taps Correlix doesn't have — their UI ideas transfer, their sensor model
doesn't. The flow/BGP-native vendors (Cisco SNA, Kentik, Plixer, FastNetMon)
are the true comparables: everything they detect comes from telemetry Correlix
ALREADY ingests.

## (b) SIEM out-of-box network-device content (surprisingly thin)

- **Splunk ESCU "Router and Infrastructure Security"** (cisco:ios syslog):
  new login attempts, software download to device, traffic mirroring, rogue
  DHCP, port-security violation, ARP poisoning, IPv6 threats.
- **Sigma** `rules/network/cisco/aaa`: 13 rules — clear logs, disable logging,
  modify config, local account changes, crypto actions, file deletion, net
  sniffing, discovery, moving data, DoS, dot1x disabled; plus cisco/bgp,
  cisco/ldp, huawei_bgp_auth_failed, juniper_bgp_missing_md5.
- **Sentinel**: Cisco ISE ~7 rules (admin password reset, log deletion,
  privileged command from new IP...); ASA only 2; SD-WAN 4.
- **Elastic**: Cisco IOS integration = parsing only, ZERO prebuilt rules;
  network rules are packet/firewall-side (sweeps, SYN scans, ICMP tunneling).
- **Google SecOps**: parsers exist, no documented curated network-device
  detections. **QRadar**: unverified (403).

→ The de-facto industry catalog is ~20 rules total. Shipping 10–15 well-tuned
network-device detections WITH causal context exceeds the SIEM baseline
(exceed-industry-baselines principle satisfied cheaply).

## (c) ATT&CK techniques observable from EXISTING Correlix telemetry

| Technique | Name | Observable via |
|---|---|---|
| T1059.008 | Network Device CLI | syslog command accounting, SSH session logs, config changes off-window |
| T1601.001/.002 | Modify System Image | reload/boot syslog, gNMI software version, checksum/inventory drift |
| T1542.005 | Pre-OS Boot: TFTP Boot | boot-config change + flow TFTP to unknown servers |
| T1602.001/.002 | Data from Config Repository | flow: SNMP from untrusted src, bulk config transfer; SNMP auth-fail syslog |
| T1020.001 | Traffic Duplication | `monitor session` syslog + new sustained ERSPAN/GRE flow |
| T1556.004 | Network Device Auth (magic password) | image checksum mismatch + login success without AAA accounting |
| T1600 | Weaken Encryption | crypto config diff |
| T1562.003 | Impair Defenses: logging disabled | `no logging` syslog + **silence detection** (ArcaneDoor tell) |
| T1078 / T1110 | Valid Accounts / Brute Force | local-account use where TACACS+ is norm; auth-failure bursts |
| T1498/T1499 | DoS | flow volumetrics + interface counters |
| T1090/T1572 | Proxy/Tunneling | unexpected GRE/IPIP/ESP from control plane, beaconing |
| (no clean ID) | BGP hijack/leak | BGP/BMP feeds (BGPalerter/Kentik practice) |

Campaign anchors: **ArcaneDoor** (Talos; tells = logging gaps, unexpected
reboots, unexplained config changes), **Jaguar Tooth** (CISA AA23-108; SNMP
abuse + image tampering), CISA's communications-infrastructure hardening
guidance (Salt-Typhoon era) — its monitoring asks read like this feature's spec.

**NIST CSF 2.0 mapping**: DE.CM-01, DE.AE-02/-03 (events correlated — literally
the correlation engine), DE.AE-08, ID.AM-01/-08, PR.PS-01, RS.AN/RS.MA.
OWASP: only the existing §15 LLM guardrails apply (copilot summarization).

## (d) Ranked detection classes (✅ = telemetry already ingested)

1. **Device auth anomalies** ✅ syslog — thresholds + rarity (first-seen admin
   source; failure-then-success). FP: NMS pollers — baseline known managers.
2. **Config change intelligence** ✅ syslog+gNMI — risk-classified config
   events; off-window or high-risk (logging off, crypto, mirror, boot) always
   alert. Low FP for high-risk classes.
3. **Device silence / logging gap** ✅ — per-device log-rate baseline; alert
   when a steady logger goes quiet WHILE still up per SNMP/gNMI (the
   correlation-engine advantage; ArcaneDoor tell).
4. **Volumetric DDoS** ✅ flow — FastNetMon model: per-hostgroup pps/bps/fps,
   1–5s buckets, amplification-port enrichers. Flash-crowd FP → require
   protocol mix + source dispersion.
5. **Scanning/recon** ✅ flow — cardinality thresholds; allowlist scanners.
6. **Management-plane abuse** ✅ flow+syslog — mgmt ports from outside declared
   mgmt subnets (make mgmt-subnet declaration an onboarding step).
7. **Software/image drift** ✅ gNMI+syslog+inventory — any undeclared version
   transition; downgrades critical. Very low FP.
8. **BGP anomalies** ⚠️ — needs an RIS Live ingester (new, lightweight);
   local BGP-auth-failure syslog is ✅ today.
9. **Exfiltration by volume** ✅ flow — needs 7-day baseline; ship dark.
10. **Beaconing/C2** ✅ flow — high FP untuned; informational tier only.
11. **Traffic mirroring/tunnel exfil** ✅ — config event AND new tunnel flow:
    a two-signal correlation, ideal for the engine. Very low FP.
12. **Rogue infra services** ⚠️ syslog where switches report (DHCP snooping,
    DAI, port-security) — pass-through as first-class events.

## (e) UI patterns worth copying

1. **Prioritized device-risk list** (Vectra/Cisco SNA): triage ENTITIES, not
   alerts; per-device score aggregated from open findings, decayed over time.
2. **AI-analyst incident narrative** (Darktrace): detections grouped into an
   investigated incident with a written story — reuse the RCA document
   pattern, including honest "possibly because of X" confidence language.
3. **Kill-chain causality timeline** (Arista NDR): maps 1:1 onto the Correlix
   causality graph with broken-red rendering.

**Differentiator:** NDRs sell correlation as a black box; Correlix's causality
is INSPECTABLE — every edge cites the raw evidence record. "Security incident
as a root-cause analysis with an evidence chain," from sensors the customer
already has. Flow vendors detect but don't explain; packet NDRs explain but
need new sensors. Correlix explains from existing sensors.

## (f) Recommended v1 scope (agent's recommendation, owner to ratify)

Build order:
1. **Security event normalization layer** — classify existing syslog/trap/gNMI
   into a security taxonomy tagged with ATT&CK IDs (parsing + rules only).
2. **Detections #1 #2 #3 #7 #12** — all low-FP, all from existing telemetry,
   match the CISA monitoring asks and the entire public SIEM catalog.
3. **DDoS #4** — FastNetMon-style thresholds; v1 response = alert + evidence
   (top talkers, protocol mix); automated RTBH/Flowspec deferred to v2.
4. **SecurityIncident in the correlation engine** + three UI surfaces (risk
   list, incident narrative, kill-chain timeline).

Defer: exfil/beaconing (ship dark until baselines), BGP hijack (fast-follow
with the RIS Live ingester — synergy with wave item 10), scanning/mgmt-plane
(v1.1), automated mitigation (v2).

### SecurityIncident entity model (sketch)

```
SecurityIncident
  id, tenant_id                      // §3a: stamped from principal, RLS-scoped
  status: open|investigating|contained|resolved|false_positive
  severity + confidence              // separate axes
  attck_techniques: []string
  kill_chain_stage: recon|initial_access|persistence|defense_evasion|
                    collection|exfiltration|impact
  primary_entity: device_ref
  related_entities: [device|prefix|external_ip|user_account]
  findings: []Finding                // Finding ≠ alert: findings accumulate
    Finding{detector_id, class, first/last_seen, score,
            evidence: []EvidenceRef} // BY-REFERENCE into OS/CH/gNMI stores
  causality_graph: edges{from,to, relation: enables|precedes|confirms|
                         possibly_causes, confidence}
  narrative: RCA-style doc (promoted incidents only)
  risk_contribution: per-device score delta with decay
```

Design choices: findings accumulate silently, only correlated combinations
promote to an incident (the Vectra noise-kill); evidence is by-reference so
every edge is auditable; same causality vocabulary as network RCA so the
existing broken-red path UI renders it; device risk = pure aggregation.

Sources: full URL list in the session transcript 2026-08-25 (Cisco SNA
datasheet, Darktrace, ExtraHop, Vectra, Corelight, Arista NDR, Plixer, Kentik,
FastNetMon GitHub, Splunk ESCU, SigmaHQ, Elastic detection-rules, Azure
Sentinel solutions, Talos ArcaneDoor, CISA AA23-108, MITRE technique pages,
NIST CSWP 29, BGPalerter).
