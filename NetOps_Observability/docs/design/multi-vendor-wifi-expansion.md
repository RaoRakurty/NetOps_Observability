# Multi-vendor + WiFi expansion roadmap (extends tracker #73)

How to add vendors **and a new WiFi device class WITHOUT live lab devices**, the
principled way (the fidelity ladder, no fabricated OIDs). Companion to the
single-contract catalog (`telemetry-catalog/`) and
[the firewall onboarding methodology](../../.claude/.../netops-firewall-onboarding-methodology.md).

## 0. The core enabler — you do NOT need a device to author a profile
Fidelity ladder (catalog truth, not vendor marketing):
- **doc_claimed** — OID/YANG-path/log-format exists per a vendor MIB/YANG/log-ref.
  *Authored from docs. No device.* Not advertised as supported.
- **lab_validated** — a captured/synthetic/**snmpsim** fixture replays through
  `normalize.py`/`parse_events.py` to the right canonical output. *No live device
  required — the fixture can be synthetic or simulated.*
- **live_validated** — confirmed flowing end-to-end. *Only this needs the device.*

**Rule: author only from real, cited OIDs/paths/formats. Never invent an OID to
fill a gap — flag it for a fixture instead.**

## 1. The big simplifier — standard MIBs already cover most vendors
The `generic` SNMP profile (HOST-RESOURCES 1.3.6.1.2.1.25, IF-MIB
1.3.6.1.2.1.2/31, ENTITY 1.3.6.1.2.1.47, sysUpTime) gives interface/CPU/mem/
inventory for **any** SNMP device. Vendor profiles only *layer on* the enterprise
OIDs the standards don't reach. So a new wired SNMP vendor needs mainly:
1. a **credential profile** (Admin → SNMP Credentials),
2. **vendor classification** (sysObjectID enterprise prefix + syslog grammar),
3. a thin **vendor profile** for enterprise-only families (vendor CPU/mem if no
   HOST-RESOURCES, BGP/OSPF/QoS specifics).

IANA enterprise numbers (for sysObjectID-based vendor ID — verify before use):
Cisco 9 · Juniper 2636 · Arista 30065 · Nokia/Timetra 6527 · Fortinet 12356 ·
Palo Alto 25461 · **Extreme 1916** · **MikroTik 14988** · **Ubiquiti 41112** ·
Aruba/HPE 14823 · Meraki (via Cisco) · Versa 42359 (verify).

## 2. Wired vendor plan (build order, all doc_claimed first)
| Vendor | Standard-MIB coverage | Enterprise OIDs to GROUND | Syslog grammar |
|---|---|---|---|
| **Juniper** (profile EXISTS) | ✓ generic | jnxOperating (CPU/mem/temp), jnxBgpM2, OSPF/ISIS | RT_FLOW (firewall), rpd/mgd/chassisd; junos@2636 SD |
| **Palo Alto** NGFW | ✓ generic | PAN-COMMON-MIB (panSessionActive, HA, panSys) | **CSV** TRAFFIC/THREAT/SYSTEM/CONFIG (classifier stub exists) |
| **Versa** SD-WAN/NGFW | partial | **controller-API** (Director/Analytics) for path-SLA/steering | Versa NGFW syslog |
| **Extreme** (EXOS/VOSS) | ✓ generic | EXTREME-SOFTWARE-MONITOR (CPU/mem), VOSS rcKhealth | EMS/log format |
| **MikroTik** (RouterOS) | ✓ generic (partial HR) | MIKROTIK-MIB mtxrHl (1.3.6.1.4.1.14988.1.1.3.*: voltage/temp/cpu), wireless registration table | RouterOS topics |
| **Ubiquiti** (EdgeOS/UniFi) | ✓ generic (EdgeOS) | UBNT-MIB; UniFi = **controller API** (not box SNMP) | EdgeOS syslog / controller |

## 3. WiFi — a NEW device class (families + entities, not just a vendor)
> ⏸️ **PARKED (owner, 2026-06-14): hold implementation.** WiFi follows the full
> process — **thorough research → design sign-off → implement** — because it's a
> new device class (new families, entities, and a source model that spans SNMP /
> controller / cloud-API). Everything below is a **pre-research SKELETON to seed
> that research**, NOT a greenlit build. Do not implement WiFi rows until the
> design is signed off.

WiFi adds wireless telemetry the wired catalog lacks. **The source model is the
deciding factor**, mirroring SD-WAN:

| AP deployment | Telemetry source |
|---|---|
| Standalone (MikroTik wireless, Ubiquiti EdgeOS, autonomous APs) | **SNMP** — IEEE `802.11-MIB` (dot11) + vendor wireless MIB |
| Controller-managed (Cisco WLC, Aruba, ExtremeCloud IQ on-prem, UniFi controller) | controller **SNMP MIB** or **API** |
| Cloud-managed (Meraki, Mist, UniFi cloud, Aruba Central) | **cloud API** (like Versa) |

### New canonical metric families (names; OIDs/paths per-source, doc_claimed)
- `device_wifi_clients` (per radio/ssid), `device_wifi_channel_util`,
  `device_wifi_noise_floor`, `device_radio_txpower`, `device_radio_channel`,
  `device_client_rssi`, `device_client_snr`, `device_wifi_tx_retries`,
  `device_wifi_tx_drops`, `device_ap_uptime`.

### New identity entities (extend `identity.yaml`)
- `ap` (parent: site), `radio` (parent: ap, key band/index),
  `ssid`/`wlan` (key SSID name), `client` (key MAC; parent: ap+radio).
  → a client-roam event joins the AP's radio metrics on (ap, radio).

### New event families (extend `events.yaml`)
- `wifi_client_assoc` / `wifi_client_deauth` / `wifi_client_roam`
  (correlates_with device_wifi_clients, join (device, ap) or (ap, ssid)),
- `rogue_ap_detected`, `ap_up_down`, `rf_interference`.

## 4. Validate WITHOUT hardware — the snmpsim harness (enabler you selected)
`snmpsim-command-responder` serves `.snmprec` files (one line per OID) on a UDP
port; the real Go SNMP collector polls it like a device → end-to-end
**lab_validated** with no hardware.
- Plan: a `deployment/docker/snmpsim/` service + `.snmprec` per vendor (captured
  via `snmpwalk` from a real device elsewhere, OR hand-built from the MIB),
  + a `devices.yaml` sim entry (needs the collector to accept `host:port`).
- Gates a `make sim-validate` that proves every vendor profile parses to the
  canonical contract before it's ever pointed at real gear.

## 5. Build sequence (grounded, incremental — no fabrication)
1. **snmpsim harness** (no OID risk; unblocks validating everything below).
2. **Palo Alto** + **Versa** (firewall methodology already proven on FortiOS;
   PAN classifier stub exists) — highest product value (security plane).
3. **Extreme / MikroTik / Ubiquiti** wired (mostly generic + thin enterprise).
4. **WiFi device class** — ⏸️ PARKED (§3): research → design sign-off → implement.
   (skeleton above seeds the research; not greenlit.)
Each step: author doc_claimed from cited MIB/YANG/log-ref → snmpsim/synthetic
fixture → lab_validated → live_validated when gear is available.

## 6. What's needed to GROUND each (so OIDs aren't guessed)
Per vendor, one of: the vendor **MIB file**, an `snmpwalk` capture, a YANG model,
or a documented log sample. Provide any of these (or authorize a research pass)
and the catalog rows go from skeleton → cited doc_claimed → snmpsim-validated.
