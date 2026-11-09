# Vendor pack sources

**Date:** 2026-11-09. **Status:** research input to `docs/design/TELEMETRY_PARSING_ENRICHMENT_2026-11-09.md` §6a. Items marked UNVERIFIED are leads, not facts. Vendor formats and message IDs change by release, so each pack re-checks them against the vendor source. Third-party samples are for format only; no rule or file from a third-party pack is copied without checking its licence (§7).

Repo baseline is from `/home/rao/Projects/NetOps_Observability/NetOps_Observability`; every web claim has a URL or is marked **UNVERIFIED**.

### 0. Baseline: what the repo has today (file:line)

| Layer | State | Evidence |
|---|---|---|
| Syslog envelope | syslog-ng `udp/tcp :514` + `:${SYSLOG_PORT}` → `syslog-parser()` with **no flags** | `deployment/docker/syslog-ng/core.conf:101-127` |
| RFC 5424 handling | **Not auto-detected.** syslog-ng `syslog_format_handler` runs the RFC 5424 parser only when `LP_SYSLOG_PROTOCOL` is set, else the legacy 3164 parser. A `<PRI>1 2026-…` frame fails the date parse and becomes a hostname-less MESSAGE (hostname → peer address) | syslog-ng `modules/syslogformat/syslog-format.c:1237-1240` (master, fetched today); `core.conf:125-127` sets no `flags(syslog-protocol)`. **Lead:** matches the design doc §3.3 cEdge "hostname falls back to sender address" symptom |
| Legacy parser extras | 3164 path parses Cisco sequence id and Cisco `*`/`.` timestamp markers | `syslog-format.c:907-910` |
| Vendor heuristic | Fortinet (`devname=`+`logid=`), PAN (`,TRAFFIC|THREAT…,`), Juniper (`[junos@2636`/`RT_FLOW`/7 appnames), Arista (7 appnames), Cisco `%[A-Z][A-Z0-9_]+-[0-7]-[A-Z0-9_]+` | `deployment/docker/vector/vector.yaml:571-582` |
| Body grammars | 3: `ios_style.v1` (`%FAC-SEV-MNEMONIC:` 3-part, colon adjacent), `srlinux.v1` (`\w+|pid|tid|seq|subsys||S:`), FortiGate kv | `vector.yaml:656-679`, `:609-647` |
| Severity reconcile | min(PRI, embedded) | `vector.yaml:692-695` |
| Enterprise MIBs indexed | Nokia TIMETRA-{BGP 1551, CHASSIS 667, FILTER 362, SYSTEM 286, LOG 195}; Juniper {BGP4-V2-MIB-JUNIPER 156, JUNIPER-MIB 121, JUNIPER-IF-MIB 70, JUNIPER-CFGMGMT-MIB 19}; Cisco {OLD-CISCO-INTERFACES 128, CISCO-BGP4 123, CISCO-PROCESS 122, CISCO-QOS-PIB 95, CISCO-OSPF 66, CISCO-ENTITY-FRU-CONTROL 58, CISCO-CONFIG-MAN 37, CISCO-ENVMON 37, CISCO-SYSLOG 20, CISCO-MEMORY-POOL 14}; Arista {BGP4V2 73, BRIDGE-EXT 11, IF 8, NEXTHOP-GROUP 7, REDUNDANCY 7, ENTITY-SENSOR 6, GENERAL 5, VRF 5} | `src/backend/collectors/mibs/index/oididx.json` (counted per module) |
| MIB gaps vs manifest | `ARISTA-MLAG-MIB` in `DEFAULT_MIBS` (`gen_index.py:44ff`) contributes **0 nodes** and is **absent from Arista's public MIB list** (42 modules). `TIMETRA-PORT-MIB`/`TIMETRA-VRTR-MIB` are in `FETCH_PINS` (`gen_index.py:407ff`) but `NETSNMP_ROOTS` (`gen_index.py:287-305`) covers only TIMETRA-BGP arcs, so **no port/VRTR notifications decode**. No BFD-STD-MIB, CISCO-BFD-MIB, TIMETRA-BFD-MIB, CISCO-ENTITY-SENSOR-MIB, CISCO-STACKWISE-MIB, CISCO-RF-MIB, CISCO-VPC-MIB | same files |
| Engine rules naming a vendor | syslog: cisco 13, arista 9, juniper 4, nokia 2 (+fortinet/paloalto catalog-only); trap: cisco 6, juniper 4, nokia 3, arista 3 | `telemetry-catalog/events.yaml:394-2341` (`vendors:` arrays) |
| Detection profiles | 20; `aruba.json` (14823 only), `hp.json` (11 only), `dell.json` (674 only), `extreme.json` (1916 only) have empty `profiles`; no SONiC profile (SONiC reports net-snmp 8072 → `net-snmp.json`) | `src/backend/internal/vendorprofile/profiles/*.json` |

Two parser facts for every pack: (a) the regex at `vector.yaml:658` requires `%FAC-<digit>-MNEMONIC:` with the colon adjacent — IOS-XR's 4-part `%ROUTING-BGP-5-ADJCHANGE :` fails both the heuristic (`:580`) and the grammar; (b) ASA `%ASA-6-302013:` matches `ios_style.v1`, so ASA already parses (event_type = 6-digit id).

---

### 1. Coverage table
Y verified · P partial · N none · U unverified. "Licence OK" = fetch+pin without redistribution (tracker 377 posture). "Capture" = free software image emitting real syslog/traps.

| Vendor / OS | Syslog grammar known | Parser today | MIB obtainable (pinned?) | Licence OK | Fault rows sourced | Capture option |
|---|---|---|---|---|---|---|
| Cisco IOS/IOS-XE | Y (3-part) | parsed | Y — `github.com/cisco/cisco-mibs`, commit-pinnable; **no LICENSE** (`license: null` via API) | P (fetch-only) | P | CML-Free (IOL/IOL-L2/ASAv, 5 nodes, free CCO) |
| Cisco NX-OS | Y | parsed | Y (same repo) | P | P (BFD text verified) | none free |
| Cisco IOS-XR | Y (4-part) | **unparsed, vendor=unknown** | Y (same repo) | P | P | XRd: CCO + active service account; 90-day eval |
| Cisco ASA | Y | parsed as ios_style | Y | P | P | CML-Free ASAv |
| Cisco SD-WAN | Y (design doc) | unparsed | Y `sdwan/{controller,device}/<rel>` (17.9…26.1) | P | P | lab |
| Juniper Junos | Y (5424 SD + 3164) | vendor only, **unparsed** | Y (zip/tar package; login U) | U | P | vJunos free, no time limit (login U) |
| Arista EOS | Y | parsed | Y (public page, **unversioned URLs**, "All rights reserved") | P | P | cEOS-lab, free registered account |
| Nokia SR OS | **Y (literal verified)** | **unparsed** | P (login-gated; LibreNMS commit pin today) | P | **Y (event tables verified)** | none free |
| Nokia SR Linux | Y | parsed (`srlinux.v1`) | Y (`/opt/srlinux/snmp/MIBs.zip` inside free image) | P | P | **ghcr.io/nokia/srlinux, no registration** |
| HPE Aruba AOS-CX | P (ELMRG PDFs exist, unread) | none | U (HPE portal login) | U | N | simulator OVA free, account; entitlement disputed |
| ArubaOS-Switch | P (guide a00076275 exists) | none | U | U | N | none |
| HPE Comware | Y (H3C docs) | none | U | U | N | none free |
| Dell OS10 | P (ref guide exists; literal U) | none | Y (Dell portal, sign-in) | U | N | none (120-day trial, purchase-bound) |
| Dell OS9/FTOS | P | none | U | U | N | none |
| SONiC | **Y (template verified)** | **misparsed (§3)** | n/a (AgentX impls; **no traps shipped**) | Apache-2.0 | N | sonic-vs, free, ~4 GB |
| Extreme EXOS | Y (`<Sev:Comp.Sub.Cond>`) | none | P (eSupport, serial/agreement) | U | P (public EMS catalog) | **Virtual_EXOS GitHub, free** |
| Extreme VOSS | P | none | U (RAPID-CITY on mirrors) | U | N | none |
| Huawei VRP | P | none | U (login) | U | N | eNSP U |
| Fortinet | Y (kv) | parsed | Y (GUI download; portal login) | U | P | FortiGate-VM permanent trial (FortiCare, 7.2.1+) |
| Palo Alto | Y (CSV) | catalog-only | **Y public docs page** | U | P | VM-Series 30-day trial |
| Check Point | P | none | Y on-box `$CPDIR/lib/snmp/chkpnt.mib` (sk90470) | U | N | U |
| F5 | P | none | Y on-box GUI | U | N | U |
| MikroTik | P | none | **Y public** `download2.mikrotik.com/Mikrotik.mib` (HTTP 200) | U | N | CHR free (1 Mbps/if) |
| Ruckus | P | none | U (portal) | U | N | none |
| Ubiquiti | P | none | **Y public** `dl.ubnt-ut.com/snmp/UBNT-MIB` (HTTP 200, 4001 B) | U | N | none |
| Sophos | P | none | U (GUI) | U | N | 30-day eval via Central |

---

### 2. Wave 1

#### 2.1 Cisco
**IOS/IOS-XE.** `seq no:timestamp: %FACILITY-SUBFACILITY-SEVERITY-MNEMONIC: Message-text` (vendor, 12.2S SEM guide https://www.cisco.com/en/US/docs/ios/12_2s/system/messages/sem122sa.pdf; current IOS-XE overview page not retrievable). RFC 3164; `service sequence-numbers`, `service timestamps`, `logging origin-id` alter the header. **Parser:** matches `ios_style.v1`. PRI == tag digit (UNVERIFIED by capture).

**NX-OS.** `<PRI><hostname>: <datetime>: %FAC-SEV-MNEMONIC: text`; literal (third-party, napalm-logs Apache-2.0): `<190>sw01.pdx01: 2017 Jul 28 14:42:46 UTC: %AUTHPRIV-6-SYSTEM_MSG: pam_unix(dcos_sshd:session): session opened for user luke by (uid=0) - dcos_sshd[12977]` (https://napalm-logs.readthedocs.io/en/latest/syslog/nxos.html). Vendor: *System Messages Reference 10.6(2)F* https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/106x/system-messages/n9k-syslogs-10-6-2-f.html — verified: `BFD-5-SESSION_STATE_DOWN: BFD session [chars] to neighbor [chars] on interface [chars] has gone down. Reason: [chars].`; routing companion `n9k-syslogs-routing-10-6-2-f.html`. **Parser:** `ios_style.v1` after syslog-ng strips header; the `host: ` prefix quirk needs a fixture.

**IOS-XR.** `<PRI><msgid>: <host> <linecard>:<datetime>: <proc>[<pid>]: %<CATEGORY>-<GROUP>-<SEV>-<CODE> : <MSG>`. Literals (third-party): `<149>2647599: vmx01 RP/0/RSP1/CPU0:Mar 28 15:08:30.941 UTC: bgp[1051]: %ROUTING-BGP-5-MAXPFX : No. of IPv4 Unicast prefixes received from 1.2.3.4 has reached 94106, max 125000`; `<187>94307: gw2.acy1 LC/0/2/CPU0:Jul  7 20:16:14.834 : ifmgr[214]: %PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/2/0/4, changed state to Down` (https://napalm-logs.readthedocs.io/en/latest/syslog/iosxr.html). Vendor format statement exists in NCS 560 6.6.x guide (English HTML 404; Japanese/Scribd copies only — literal UNVERIFIED). **Parser fails** → new grammar `iosxr.v1`.

**ASA.** `[<PRI>]: [Timestamp] [Device-ID] : %ASA-Level-Message_number: Message_text`; facility "always ASA"; no severity-0 messages; EMBLEM "prints colon (:) after <PRI>", UDP only; RFC 5424 timestamp option (UTC). Literals (vendor): `<166>:2018-06-27T12:17:46Z: %ASA-6-110002: Failed to locate egress interface…`; `2018-06-27T12:17:46Z asa : %ASA-6-110002: …` (https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/monitor-syslog.html). Catalogue https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/about.html. **Parser:** parses; EMBLEM `<PRI>:` needs a syslog-ng fixture.

**Fault mnemonics** (only NX-OS BFD text fetched-verified; rest **UNVERIFIED — confirm in per-platform System Message Guide / Error Message Decoder (CCO login)**): BGP `%BGP-5-ADJCHANGE` (IOS/NX-OS), `%ROUTING-BGP-5-ADJCHANGE` (XR); OSPF `%OSPF-5-ADJCHG` (IOS), `%OSPF-5-ADJCHANGE` (NX-OS), `%ROUTING-OSPF-5-ADJCHG` (XR); IS-IS `%CLNS-5-ADJCHANGE`, `%ROUTING-ISIS-5-ADJCHANGE`; BFD `%BFD-6-BFD_SESS_DOWN`/`%BFDFSM-6-BFD_SESS_DOWN` (IOS), `BFD-5-SESSION_STATE_DOWN` (NX-OS ✓), `%L2-BFD-6-SESSION_STATE_DOWN` (XR); link `%LINK-3-UPDOWN`/`%LINEPROTO-5-UPDOWN`, `%ETHPORT-5-IF_DOWN_LINK_FAILURE`/`IF_UP` (NX-OS, community), `%PKT_INFRA-LINK-3-UPDOWN` (XR ✓); env `%ENVMON-*`/`%PLATFORM_ENV-1-*`, NX-OS `%PLATFORM-2-PS_FAIL`/fan/temp, XR `%PLATFORM-ENVMON-*`; CPU/mem `%SYS-3-CPUHOG`, `%SYS-2-MALLOCFAIL`, NX-OS `%SYSMGR-2-*`/`%PLATFORM-2-MEMORY_ALERT`; config `%SYS-5-CONFIG_I` (rule exists `events.yaml:1045`), `%VSHD-5-VSHD_SYSLOG_CONFIG_I`, `%MGBL-CONFIG-6-DB_COMMIT`; HA `%STACKMGR-*`, `%VPC-2-*`, `%HA-REDCON-*`. **events.yaml covers** BGP/OSPF/IS-IS adjchange, notification/churn, link, STP, EVPN, FHRP, MAC flap, config; **not** BFD, chassis/env, CPU/mem, stack/vPC.

**Traps/MIBs.** Enterprise 9 (+41916). `github.com/cisco/cisco-mibs`: `license: null` (GitHub API ✓); README: "mirror of various internal MIB files… ftp.cisco.com… decommissioned… this [is] the new source"; `v2/` = 1000 files; `sdwan/device/{17.9,17.12,17.15,17.18,26.1}`, `sdwan/controller/`; HEAD `c9ab98c03ee051de74edda72f6d5c43ee65cad91` (2026-09-29) → commit-pinnable. **No grant anywhere** → fetch-only (D4). Indexed notifications: CISCO-BGP4-MIB `cbgpFsmStateChange`/`cbgpBackwardTransition`; CISCO-CONFIG-MAN-MIB `ciscoConfigManEvent`; CISCO-ENVMON-MIB fan/temp/supply; CISCO-ENTITY-FRU-CONTROL-MIB `cefcPowerStatusChange`/`cefcFanTrayStatusChange`/FRU inserted-removed; CISCO-PROCESS-MIB `cpmCPURisingThreshold`; CISCO-SYSLOG-MIB `clogMessageGenerated`. **Missing:** CISCO-BFD-MIB (`ciscoBfdSessUp/Down`), CISCO-STACKWISE-MIB, CISCO-RF-MIB (`ciscoRFSwactNotif`), CISCO-ENTITY-SENSOR-MIB, CISCO-VPC-MIB. Standard-only: linkDown/Up, coldStart, bgpBackwardTransition, ospfNbrStateChange. (OID values to be read from the pinned file in PR 7 style, not from this report.)

#### 2.2 Juniper Junos
**Syslog (vendor; juniper.net now 301s to networkingdocs.hpe.com).** Standard: `timestamp host process[pid]: TAG: text`. Structured-data: `<priority code>version timestamp hostname process processID TAG [junos@2636.platform variable-value-pairs] message-text`; "If the system logging utility cannot determine the value in a particular field, a hyphen ( - ) appears instead"; platform suffix table (`1.1.1.2.18` = M120 …). Literal: `<165>1 2007-02-15T09:17:15.719Z router1 mgd 3046 UI_DBASE_LOGOUT_EVENT [junos@2636.1.1.1.2.18 username="regress"] User 'regress' exiting configuration mode` (https://networkingdocs.hpe.com/documentation/en_US/junos13.1/topics/reference/general/syslog-interpreting-msg-generated-structured-data-format.html). `explicit-priority` ignored under `structured-data`; from 19.2R1 no other format statements coexist (Junos 13.2/19.2 docs via search). Fault literal (Juniper community, third-party): `Apr 7 07:32:34 Branch1 rpd[2310]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.1 (External AS 1111) changed state from Established to Idle (event HoldTime) (instance master)` (https://community.juniper.net/discussion/event-policy-question). Stable id = TAG; PRI reliable both formats. **Parser:** vendor=juniper, **no body grammar → unparsed**; SD frames are RFC 5424 → syslog-ng legacy parser mangles them (§0). **Fault TAGs (UNVERIFIED individually; System Log Explorer is authority, not fetched):** `RPD_BGP_NEIGHBOR_STATE_CHANGED`, `RPD_OSPF_NBRDOWN/NBRUP`, `RPD_ISIS_ADJDOWN/ADJUP`, `BFDD_TRAP_SHOP_STATE_DOWN/UP`, `SNMP_TRAP_LINK_DOWN/UP`, `CHASSISD_FAN_FAILURE`, `CHASSISD_PSU_*`/`CHASSISD_POWER_*`, `CHASSISD_TEMP_*`, `KERNEL_MEMORY_*`/`RPD_SCHED_SLIP`, `UI_COMMIT`/`UI_COMMIT_COMPLETED` (rule exists `events.yaml:1053`), `CHASSISD_VCHASSIS_*`, `JSRPD_*`. **Traps/MIBs.** Enterprise 2636. Package ("zip or tar", folders StandardMibs/JuniperMibs) under "Enterprise-Specific MIBs and Traps"/SNMP MIB Explorer (https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/junos-os-snmp-faqs.html); download page 404 after HPE redirect; apps.juniper.net blocked here — **login + licence text UNVERIFIED**. Indexed: JUNIPER-MIB `jnxPowerSupplyFailure`, `jnxFanFailure`, `jnxOverTemperature`, `jnxRedundancySwitchover`, `jnxFruRemoval`; JUNIPER-CFGMGMT-MIB `jnxCmCfgChange`; BGP4-V2-MIB-JUNIPER established/backward. Missing: JUNIPER-VIRTUALCHASSIS-MIB, BFD-STD-MIB + JUNIPER-BFD-MIB, JUNIPER-ALARM-MIB.

#### 2.3 Arista EOS
**Syslog.** `<PRI><datetime> <hostname> <process>: %<facility>-<severity>-<tag>: <MSG>`; literal (third-party): `<149>Apr 16 11:04:17 edge01 Rib: %BGP-3-NOTIFICATION: received from neighbor 194.53.172.97 (AS 2611) 6/1 (Cease/maximum number of prefixes reached) 0 bytes` (https://napalm-logs.readthedocs.io/en/latest/syslog/eos.html). Vendor page: severity 0–7, `logging format prefix`, `show logging` "Sequence numbers: disabled / Hostname format: Hostname only / Syslog facility: local4"; full catalogue is the release `SysMsgGuide.pdf` on Arista Support (**login**) (https://www.arista.com/en/um-eos/eos-system-event-logging). A third-party mirror PDF exists but was refused by policy (walled copy) — not a usable source. RFC 5424 output UNVERIFIED. **Parser:** `ios_style.v1` matches; vendor=arista only for 7 appnames (`vector.yaml:578`) — real agents `Rib`, `Bgp`, `Lldp`, `Stp`, `Mlag`, `ConfigAgent` fall through to **vendor=cisco**. Fault mnemonics (UNVERIFIED): `%BGP-5-ADJCHANGE`, `%BGP-3-NOTIFICATION` ✓, `%OSPF-4-OSPF_ADJACENCY_ESTABLISHED/TEARDOWN`, `%BFD-5-STATE_CHANGE`, `%LINEPROTO-5-UPDOWN`, `%ENVMON-*`/`%SYSTEM-*` PSU/fan/temp, `%SYS-5-CONFIG_I` via `ConfigAgent:` (rule `events.yaml:1096`), `%MLAG-4-*`, `%AGENT-*` memory. **Traps/MIBs.** Enterprise 30065; public page lists 42 proprietary MIBs + "All Arista MIBs" zip, **flat unversioned URLs**, no licence beyond footer "© 2026 Arista Networks… All rights reserved" (https://www.arista.com/en/support/product-documentation/arista-snmp-mibs) → sha256 pin only (URL not commit-pinnable); keep LibreNMS commit URL as fallback. **No MLAG MIB exists** → drop `ARISTA-MLAG-MIB` from `DEFAULT_MIBS`. Indexed: REDUNDANCY switchover, ENTITY-SENSOR alarms, BGP4V2, BRIDGE-EXT MAC move.

#### 2.4 Nokia SR OS / SR Linux
**SR OS syslog (vendor, verified).** RFC 3164; `PRI = facility*8+severity`; default facility local7; HEADER `MMM DD HH:MM:SS <source IP>`; MSG `<log-prefix>: <seq> <vrtr-name> <application>-<severity>-<Event Name>-<Event ID> [<subject>]: <message>\n`; prefix default `TMNX`; vrtr-name ∈ {Base, management, vpls-management, vprnN}; empty subject renders `[]:`. Severity map: critical→alert(1), major→critical(2), minor→error(3), warning→warning(4), cleared/indeterminate→info(6); no emergency/notice/debug. Literal: `<188>Jan  2 18:43:23 10.221.38.108 TMNX: 17 Base SYSTEM-WARNING-tmnxStateChange-2009 [subject]: …` (https://infocenter.nokia.com/public/7750SR222R1A/topic/com.nokia.System_Mgmt_Guide/syslog_implemen-ai9exj5x1i.html). Max 1023 B (pysros). Console/file: `nnnn YYYY/MM/DD HH:MM:SS.SS TZONE <severity>: <application> #<event-id> <vrtr-name> <subject>` + message, e.g. `252 2013/05/07 16:21:00.76 UTC WARNING: SNMP #2005 Base my-interface-abc` / `Interface my-interface-abc is operational` (https://documentation.nokia.com/sr/24-10/7x50-shared/log-events/log-events-overview.html). **PRI reliable; stable id = `<Event Name>-<Event ID>`.** **Parser: none.**

**SR OS fault events (vendor Log Events Guide 22.10, verified; 24.10 pages exist per nav):** BGP (https://documentation.nokia.com/sr/22-10/books/log-events/log-bgp.html): 2039 `bgpBackwardTransNotification` BGP4-MIB.bgpNotification.2 warning; 2038 `bgpEstablishedNotification` .1 minor; 2020 `tBgpNgBackwardTransition` TIMETRA-BGP-MIB.tBgpNotifications.8 warning; 2019 `tBgpNgEstablished` .7 minor; 2005 `sendNotification`, 2006 `receiveNotification`, 2007 `bgpInterfaceDown`, 2008 `bgpConnNoKA`, 2011 `bgpRemoteEndClosedConn` (no SNMP); 2034 `tBgpMaxNgPfxLmt` .20; 2035 threshold .21. PORT (`log-port.html`): 2009 `tmnxEqPortError` TIMETRA-PORT-MIB.tmnxPortNotification.14 minor "Physical port $tmnxPortNotifyError$"; 2005/2006 SFP inserted/removed .8/.9; SFP status family .36. BFD (`log-bfd.html`): 2001 `tmnxBfdOnLspSessDown` TIMETRA-BFD-MIB.tmnxBfdNotifications.1; 2002 up .2 (LSP-BFD; IP-BFD likely under VRTR — not fetched). CHASSIS (`log-chassis.html`): 2144 `tmnxEqPhysChassPowerSupInFail` .131 critical; 2146 OutFail .133; 2148 `tmnxEqPhysChassisFanFailure` .135 critical; 2005 `tmnxEnvTempTooHigh` .2 major; 2001 `tmnxEqCardFailure` .7 major; 2010/2011 PSU inserted/removed .4/.5. SYSTEM (`log-system.html`): 2006 `tmnxConfigModify` TIMETRA-SYSTEM-MIB.tmnxSysNotifications.8 warning; 2007 Create .9; 2008 Delete .10; 2009 `tmnxStateChange` .11; 2002/2003 save ok/failed; 2010 `tmnxModuleMallocFailed` .12 major; CLI change = USER 2011 `cli_config_io` minor "User from $srcAddr$: $prompt$ $message$" (`sample-log-event.html`). CPU events not in SYSTEM (UNVERIFIED location). Link up/down = standard linkDown/linkUp. **events.yaml covers** `trap.bgp.nokia_ng` + hints, IS-IS/LLDP syslog markers, `trap.config.change` (TIMETRA-SYSTEM indexed); **not** the `APP-SEV-NAME-ID` syslog grammar, port errors, chassis.

**SR OS MIBs.** Enterprise 6527. Official files in the image / Nokia support portal (login); no public Nokia download found. LibreNMS mirror (GPLv3 repo; Nokia copyright text, no grant) is today's commit-pinned transport; mirror revisions lag (TIMETRA-CHASSIS Rev 16.0/2017 per search). Add TIMETRA-PORT/BFD/VRTR notification arcs to `NETSNMP_ROOTS`.

**SR Linux.** Log layout (vendor): `nnnn YYYY/MM/DD HH:MM:SS.SS TZONE <severity>: <application> <router-name>` + subject/message; 8 standard severities; event name = table title, e.g. `bgpNeighborBackwardTransition` default warning, "In network-instance $network-instance$, the BGP session with $peer-address$ moved from higher state $last-state$…" (https://documentation.nokia.com/srlinux/26-7/books/log-events/log-intro.html). The pipe-delimited form `srlinux.v1` parses is the Linux daemons' syslog/stdout output — not documented there; keep `lab_validated` only if captured. SNMP (vendor 25.7): v2c/v3; MIBs "packaged with each release… Nokia support portal or in /opt/srlinux/snmp/MIBs.zip"; traps listed in `/etc/opt/srlinux/snmp/installedTraps` once a trap-group exists; customizable framework from 24.10.1 (`rfc3418_traps.yaml`, community) (https://documentation.nokia.com/srlinux/25-7/books/system-mgmt/snmp.html). Default trap set **UNVERIFIED — read installedTraps on the free container**. Flows: sFlow only (`system sflow` sample-rate/collector; 23.7: sample size/polling not configurable) (https://documentation.nokia.com/srlinux/23-7/books/troubleshooting-toolkit/sflow.html).

---

### 3. Wave 2

**HPE Aruba AOS-CX.** Enterprise: HP 11 lineage; AOS-CX wired arc **47196 UNVERIFIED** (not in `aruba.json`, which has only 14823). Event Log Message Reference Guides per release, public PDFs (https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/elmrg.pdf, 10.15) — domain blocked here, **unread**; numeric event IDs (community: 4667/4668; "same across CX platforms"). RFC 5424 default UNVERIFIED. MIBs: HPE Networking Support Portal (login; corporate e-mail). Capture: AOS-CX Switch Simulator OVA — free, account required, entitlement disputed, "AS IS". Elastic `hpe_aruba_cx` (ELv2, lead only). Flows: sFlow (U).

**ArubaOS-Switch/ProCurve.** Reference guide HPE `emr_na-a00076275en_us` (unread). Older manuals: 5-digit event number + module + text — literal UNVERIFIED. MIBs: HPE support (login U). No VM.

**HPE Comware (H3C).** Enterprise **25506 UNVERIFIED**, absent from profiles. Vendor (H3C, public): `<PRI>Timestamp Sysname %%vvModule/Level/Mnemonic: location; content`, e.g. `%%10SYSLOG/6/SYSLOG_RESTART`; alt CMCC/unicom/SGCC/RFC 5424 (https://www.h3c.com/en/d_202502/2361897_294551_0.htm, https://www.h3c.com/en/d_202309/1921112_294551_0.htm). Stable id = Module/Level/Mnemonic. MIBs login U. Flows NetStream/sFlow (U).

**Dell OS10 / OS9.** 674 in profile; Force10 **6027 UNVERIFIED**, absent. OS10 System Log Message Reference exists (dell.com blocked; unread). Wire format `Node.1-Unit.1:PRI [event], Dell EMC (OS10) %IFM_ASTATE_DN: …` UNVERIFIED; older DNOS has `logging version` 3164/5424. MIBs: "SmartFabric OS10 Software (sign in required)… MIBs" (Dell Info Hub). Capture: not free (entitlement-bound). Flows sFlow (U).

**Extreme EXOS/Switch Engine.** Enterprise 1916. Format (vendor): `timestamp <Severity:Component.Subcomponent.Condition> text`, e.g. `<Warn:SNTP.RslvSrvrFail>`, `<Info:System.userComment>`; `configure log target … format` adds/removes items only (https://documentation.extremenetworks.com/ExtremeXOS%20v33.1.1%20Command%20References/GUID-5AD413EE-EEB4-400B-81E2-824C87ECFE76.shtml). Stable id = Component.Sub.Condition; public *EMS Messages Catalog v33.7.x* (e.g. `vlan.msgs.portLinkStateUp`, Info). MIBs: eSupport, serial/agreement number needed. Capture: **github.com/extremenetworks/Virtual_EXOS qcow2, free** (licence text unread). Flows sFlow.

**Extreme VOSS/Fabric Engine.** Enterprise 2272 (Rapid City; mirror `RAPID-CITY::rcIpBgpTmpBackwardTransNotification`; vendor-UNVERIFIED). Community sample `CP2 [ts] 0x… 0x… GlobalRouter IP INFO …`; VOSS 8.6 guide: RFC 5424/3339 compliance (https://documentation.extremenetworks.com/VOSS/SW/86/VOSSUserGuide/GUID-8EAE6AFD-6356-461B-BA4B-9DCA7F789A09.shtml); "Log Message Format" in Troubleshooting VOSS 8.2 PDF (unread). MIBs eSupport. No VM. Flows IPFIX (U).

**SONiC.** No profile (net-snmp sysObjectID → `net-snmp.json`). **Syslog (source-verified):** `SONiCForwardFormat = "<%PRI%>%TIMESTAMP:::date-rfc3339% {{hostname}} %syslogseverity-text:::uppercase% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"` (+ variant with `{{os_version}}`) — `sonic-buildimage/files/image_config/rsyslog/rsyslog.conf.j2:62-70`. Wire: `<PRI>2026-11-09T…+00:00 host INFO bgp#bgpd[123]: msg` — RFC 3339 timestamp, **no version "1"**, uppercase severity word in PROGRAM position → syslog-ng legacy parser sets PROGRAM=`INFO|ERR|…` and shoves the tag into MESSAGE (same shape as the `confd 2939 - -` defect). No stable id (FRR/daemon free text). **Traps:** `sonic-snmpagent` = AgentX sub-agent (Apache-2.0) implementing RFC1213/2737/2863/3433/4292/4363, IEEE 802.1AB, Cisco BGP4/PFC/QoS/FRU, Dell (`src/sonic_ax_impl/mibs/{ietf,vendor/cisco,vendor/dell}`); trap support = **open unmerged PR #366** (2026-02-05) → **no traps upstream today**. Fallback: standard-MIB polling + syslog + sFlow (hsflowd, U). Capture: `sonic-vs.img.gz` (Azure Pipelines artifact `sonic-buildimage.vs`), ~1.1 GB, 4 vCPU/4 GB per CML guide (https://support.stordis.com/hc/en-us/articles/26116997413661).

---

### 4. Wave 3 (leads)

| Vendor | Ent. | Syslog lead | MIB source | Capture |
|---|---|---|---|---|
| Huawei VRP | 2011 | `TimeStamp HostName %%ddModuleName/Severity/Brief(l)[cnt]:Description` — AR V200R010 Log Reference "Log Message Format Description" exists (https://support.huawei.com/enterprise/en/doc/EDOC1100035586/97342dce/log-message-format-description; JS-only, literal UNVERIFIED); S9300 manual confirms `ModuleName/Severity/Brief` | login | eNSP (U) |
| Fortinet | 12356 | kv parsed; `logid=` stable id | GUI "Download FortiGate MIB File / Fortinet Core MIB File"; portal login (https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/608160/mib-files) | FortiGate-VM ≤7.2.0 15-day eval (1 CPU/2 GB); 7.2.1+ permanent trial, FortiCare acct, 3 if/policies/routes |
| Palo Alto | 25461 | CSV detected | **public** https://docs.paloaltonetworks.com/resources/snmp-mib-files (`.my` + `.md5`), PAN-COMMON-MIB/PAN-TRAPS | VM-Series 30-day trial |
| Check Point | 2620 | U | sk90470: `$CPDIR/lib/snmp/chkpnt.mib`, `chkpnt-trap.mib`, `/etc/snmp/GaiaTrapsMIB.mib`; sk183166: some OIDs defined incorrectly | U |
| F5 | 3375 | U | on-box F5 → Downloads → SNMP MIBs (DevCentral) | U |
| MikroTik | 14988 | U | **public** `https://download2.mikrotik.com/Mikrotik.mib` (200 via redirect; sha256-pin only) | CHR free: no expiry, 1 Mbps/if |
| Ruckus | 25053 | U | portal (login) | none |
| Ubiquiti | 41112 | EdgeOS rsyslog (U) | **public** `https://dl.ubnt-ut.com/snmp/UBNT-MIB` (200, 4001 B) | none |
| Sophos | 21067/9789 | U | GUI (U) | 30-day eval via Central |

---

### 5. Flows / goflow2 (source-verified, `netsampler/goflow2` main, BSD-3)
- Sampling resolution `producer/proto/producer_nf.go:635-659`: options records searched for IE **305** → **50** → **34**; first hit stored per `(version, obsDomainId)` (`:723-735`, `:774-786`); IPFIX per-record selectors can override (`:736-748`); otherwise `SamplingRate` = **0** (repo treats as 1:1, `flows.go:70` per design doc §4). v5: header `SamplingInterval & 0x3FFF` (`producer_nflegacy.go:60`). sFlow carries rate per sample.
- Expect mishandling: samplerId-scoped options (IE 48/49) not keyed by obsDomainId → 0; options template arriving after first data → 0 for an interval; Juniper ACX/PTX options data "not compliant with IPFIX RFC 7011" (Juniper docs; impact U); exporters with no options (Nokia SR OS cflowd: `rate` 1–1,000,000 default 1000, template retransmit 600 s, **no options template mentioned**) → 0 → silent 1:1. PR 5 `sampling_status` is right; add "vendor known to sample, reported 0" once vendor is inventory-known.
- Per vendor: Cisco FNF v9/IPFIX; Juniper inline jflow v9/IPFIX (rate exported? U); Arista sampled flow tracking IPFIX v10, mutually exclusive with sFlow (https://www.arista.com/um-eos/eos-sampled-flow-tracking); SR OS cflowd v9/IPFIX; SR Linux sFlow only; SONiC/AOS-CX/Dell/EXOS sFlow (U); Fortinet v9/IPFIX+sFlow, PAN v9, Check Point, F5 IPFIX, MikroTik v1/5/9/IPFIX, Huawei NetStream — all UNVERIFIED this session.

---

### 6. Capture options without hardware (owner option; tracker 249 unchanged)

| OS | Image | Terms | 4-core fit | Emits |
|---|---|---|---|---|
| Nokia SR Linux | `ghcr.io/nokia/srlinux` | "no registration, licensing, or contract requirements" (https://network.developer.nokia.com/dc-fabrics/try-sr-linux); BSD-3 repo | ~2 GB/node | syslog, traps (installedTraps), sFlow |
| Arista cEOS-lab | arista.com download | free **registered account**; EULA unread | ~1–2 GB/node | 3-part syslog, traps, IPFIX/sFlow |
| SONiC-VS | Azure Pipelines artifact | open source | 4 vCPU/4 GB | rsyslog (verified template); **no traps** |
| Juniper vJunos | vJunos Lab page | "no cost for non-production test… no time limit" (https://www.juniper.net/us/en/dm/vjunos-labs.html); login U | ≥4 vCPU/5+ GB (U) — tight | both syslog formats, traps |
| Cisco CML-Free | developer.cisco.com | free CCO; IOL/IOL-L2/ASAv; 5 nodes | CML VM ~8 GB (U) | IOS + ASA only |
| Cisco XRd | software.cisco.com | active service account; 90-day eval | heavy (U) | XR syslog |
| Virtual_EXOS | github.com/extremenetworks/Virtual_EXOS | free (licence U) | light | EMS syslog, traps |
| AOS-CX simulator | HPE portal | free account; entitlement disputed; AS IS | 2–4 GB (U) | CX syslog, traps |
| FortiGate-VM | Fortinet | permanent trial (FortiCare) | 1 CPU/2 GB | kv syslog, traps |
| MikroTik CHR | mikrotik.com | free level | tiny | RouterOS syslog, traps |
| PAN VM-Series | 30-day trial | form | 2 vCPU/5.5 GB (U) | CSV, PAN-TRAPS |
| Dell/VOSS/Huawei/Comware/Ruckus/Ubiquiti/F5/Check Point | — | no free lab image found | — | — |

Realistic concurrent set on the lab box: SR Linux ×2 + cEOS ×1 + SONiC-VS ×1 (≈8–9 GB) → promotes Nokia/Arista/SONiC to `lab_validated`; rotate vJunos/FortiGate-VM.

---

### 7. Open-source packs (licences via GitHub API)
- SC4S `splunk/splunk-connect-for-syslog` — **Apache-2.0** (copy with attribution OK; still cite vendor per fidelity rule).
- napalm-logs — **Apache-2.0**; logstash-patterns-core — **Apache-2.0**; goflow2 — **BSD-3**; sonic-snmpagent — **Apache-2.0**.
- Elastic integrations — **Elastic License 2.0** → format reference only, **never copy pipelines** into Apache-2.0 Correlix.
- LibreNMS — GPLv3 repo; `mibs/` are vendor-copyright files → fetch-only transport, never vendor; mirrors lag and have disagreed with vendor (Viptela precedent).
- rsyslog — LGPL-3.0 (docs licence U); FortiSIEM docs — proprietary (read-only).
- Nokia/Cisco/Arista/Juniper MIB text: vendor copyright, no grant found; Arista says "proprietary". IETF RFC modules remain the only vendorable set (`mibs/vendored/SOURCES.md`).

---

### 8. Recommended pack order + effort
1. **Envelope fix (PR 10, all vendors) — M:** syslog-ng must accept RFC 5424 on udp/tcp 514 (a `syslog-parser(flags(syslog-protocol))` branch gated by `^<\d+>1 `, or move framing to Vector's auto-detecting syslog source). Fixtures from vendor docs: Junos SD, SONiC, ASA EMBLEM `<PRI>:`, IOS-XR, SR OS `TMNX:`.
2. **Nokia SR OS pack — M:** grammar `sros.v1` (`APP-SEV-NAME-ID [subject]:`), rows from verified tables (BGP 2039/2038/2020/2019/2011/2005-2009/2034; PORT 2009; CHASSIS 2144/2146/2148/2005/2001; SYSTEM 2006-2010; USER 2011); extend `NETSNMP_ROOTS` with TIMETRA-PORT/BFD/VRTR arcs; severity via PRI map. SR Linux container → `lab_validated` traps.
3. **Cisco IOS-XR grammar + Cisco MIB additions — M–L:** `iosxr.v1`; CISCO-BFD/RF/STACKWISE/ENTITY-SENSOR/VPC from pinned `cisco-mibs` commit; NX-OS header fixture; BFD/env/HA rows.
4. **Juniper — M:** `junos_sd.v1` + `junos_std.v1`, BFD/chassis/VC rows, JUNIPER-VIRTUALCHASSIS + BFD-STD-MIB; blocked on MIB package terms.
5. **Arista — S–M:** widen appname list (`vector.yaml:578`), drop `ARISTA-MLAG-MIB`, MLAG/BFD/env rows; cEOS → `lab_validated`.
6. **SONiC — S–M:** profile (8072 + `sysDescr` "SONiC"), FRR BGP/BFD regexes, documented standard-MIB-only stance, sFlow.
7. **Extreme EXOS — M:** `ems.v1`, rows from public EMS catalog, Virtual_EXOS captures.
8. **AOS-CX, Comware, Dell OS10, VOSS — M each**, after reading the PDFs (blocked here) and owner decision on portal accounts.
9. **Third wave:** pin PAN/MikroTik/Ubiquiti public MIBs cheaply; Fortinet/Check Point/F5 MIBs are on-box only; defer.

---

### 9. Literal fixtures available now
- Junos SD: `<165>1 2007-02-15T09:17:15.719Z router1 mgd 3046 UI_DBASE_LOGOUT_EVENT [junos@2636.1.1.1.2.18 username="regress"] User 'regress' exiting configuration mode` (vendor).
- Junos std: `Apr 7 07:32:34 Branch1 rpd[2310]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.1 (External AS 1111) changed state from Established to Idle (event HoldTime) (instance master)` (community).
- SR OS: `<188>Jan  2 18:43:23 10.221.38.108 TMNX: 17 Base SYSTEM-WARNING-tmnxStateChange-2009 [subject]: …` (vendor); console `252 2013/05/07 16:21:00.76 UTC WARNING: SNMP #2005 Base my-interface-abc` (vendor).
- IOS-XR: two napalm-logs lines (§2.1) (third-party).
- NX-OS: napalm-logs `%AUTHPRIV-6-SYSTEM_MSG` line (third-party); `BFD-5-SESSION_STATE_DOWN: BFD session [chars]…` (vendor template).
- ASA: `<166>:2018-06-27T12:17:46Z: %ASA-6-110002: …` and `2018-06-27T12:17:46Z asa : %ASA-6-110002: …` (vendor).
- EOS: `<149>Apr 16 11:04:17 edge01 Rib: %BGP-3-NOTIFICATION: received from neighbor 194.53.172.97 (AS 2611) 6/1 (Cease/maximum number of prefixes reached) 0 bytes` (third-party).
- SONiC: template-derived `<PRI>YYYY-MM-DDTHH:MM:SS.ffffff+00:00 <host> INFO <tag>: <msg>` (source-verified; no captured line).
- EXOS: `<Warn:SNTP.RslvSrvrFail>` (vendor). Comware: `%%10SYSLOG/6/SYSLOG_RESTART` (vendor).

---

### 10. Owner decisions (recommendations)
1. **Universal MIB posture:** fetch-only, sha256-pinned, commit-pinned where possible, never vendored, for all non-IETF MIBs (no vendor grants redistribution). Vendor URL first, LibreNMS commit as transport fallback.
2. **Login-gated vendors** (Nokia official, Juniper terms, HPE/Aruba, Dell, Extreme, Huawei, Ruckus; Fortinet/F5/Check Point on-box): decide per vendor whether a Correlix portal account is acceptable for build-time fetch. Recommend yes for Nokia/Juniper/Extreme; defer Dell/HPE/Huawei; **fallback where refused = standard MIBs only** (IF/BGP4/OSPF/ISIS/ENTITY/LLDP/BFD-STD/HOST-RESOURCES) with trap rows labelled `standard_only`.
3. **Juniper package:** confirm login/terms before PR; pin sha256 + release name if anonymous.
4. **Arista:** accept sha256-only pins on unversioned arista.com URLs + LibreNMS commit fallback (status quo).
5. **SONiC:** document "no traps" until PR #366 merges; rely on polling + syslog + sFlow.
6. **Free lab images:** approve SR Linux (no registration), an arista.com account for cEOS-lab, SONiC-VS; optionally a Juniper account for vJunos. Software only; no hardware.
7. **Envelope rework location:** syslog-ng flag branch vs Vector-native framing (affects all vendors + storm parity leg).
8. **Elastic integrations:** read-only reference (ELv2).

### 11. Unverified / not reached
IOS-XE/XR official English format pages (secondary copies only); Arista SysMsgGuide (login/walled); Juniper MIB download terms; AOS-CX ELMRG, Dell OS10 syslog reference, Huawei format pages (blocked/JS); VOSS format; all third-wave syslog literals; per-vendor flow sampling export behaviour; vJunos/XRd/CML resource numbers; documentation of SR Linux's pipe-delimited syslog form; cEOS-lab EULA; enterprise numbers 47196/25506/6027/2272.
