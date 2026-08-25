# Vendor extensibility — the Vendor Profile (2026-08-25)

Question: how do we add a new vendor — e.g. a **SonicWall** firewall or an
**Extreme** switch — across CVE feeds, hardening, config/packet capture, and
dialect, without surgery?

## The problem: vendor knowledge is scattered today

Adding a vendor currently means editing several unrelated places:
- `collectors/vendor.go` — detection (SNMP enterprise OID + sysDescr match).
- `internal/netconcepts/vrf.go` — dialect terms.
- `scripts/vuln-feed-prepare.py` — NVD CPE vendor-name mapping.
- `config/snmp_profiles.json` — OID mappings.
- (planned) hardening rules, config-capture commands, packet-capture commands.

That is 4–7 touch-points for one vendor. The fix is to consolidate them behind
one extension point.

## The design: a declarative Vendor Profile (one file per vendor)

A **Vendor Profile** is a single declarative descriptor (data + a few small
parse/command snippets) that carries everything the platform needs about a
vendor. The engines READ profiles; they never hard-code vendors. Adding a
vendor = author one profile + register it. §4 plug-and-play: no engine change,
replaceable, isolated.

```
VendorProfile {
  id            "sonicwall"                 // canonical, normalized
  aliases       ["sonicos","dell sonicwall"] // sysDescr / CPE / import aliases
  device_class  ["firewall"]                // firewall | switch | router | wireless
                                            // → selects which rule families apply
  detect {
    snmp_enterprise_oids  [8741]            // → collectors/vendor.go map
    sysdescr_match        ["sonicos","sonicwall"]
    cpe_vendor            ["sonicwall"]     // NVD supplement mapping
  }
  dialect {                                 // generalizes netconcepts beyond VRF
    vrf_term      "n/a"                     // firewalls: "security zone" concept instead
    zone_term     "zone"
    // concept → this vendor's word; the engine reasons in concepts, renders in dialect
  }
  cve {
    psirt_connector  "sonicwall-psirt"      // connector type (csaf|openvuln|rss|portal|nvd-only)
    psirt_config     { url, format, auth_ref }
    eol_source       "operator-table"        // or a vendor EoX-style API
  }
  capture {
    config_show      ["show current-config"] // running-config equivalent over SSH
    pcap_method      "on-device"             // on-device | span-only | unsupported
    pcap_commands    [ ... bounded EPC/packet-monitor ... ]
  }
  snmp_profile   "sonicwall.json"           // OID map (existing SNMP profile manager)
  syslog_hints   { format_markers: [...] }  // parse hints for the syslog lane
  capabilities   { gnmi:false, netconf:false, on_device_capture:true }
  hardening      "sonicwall"                // → the vendor's bindings for the shared rule catalog
}
```

## The load-bearing principle: concept-level logic, vendor dialect bindings

Most rule LOGIC is vendor-NEUTRAL (a concept: "telnet enabled", "mgmt plane
reachable from an untrusted seam", "SSHv1 in use"). The Vendor Profile provides
only the DIALECT BINDINGS — how to DETECT and EXPRESS each concept in this
vendor's syntax. This is the netconcepts pattern (item 4) generalized from
just-VRF to the whole vendor surface.

So the hardening engine iterates the shared concept catalog (§5e) and asks the
profile: "for SonicWall, how do I detect concept X, and what is the remediation
in SonicOS syntax?" The engine has zero vendor branches. Example binding:

```
concept: mgmt-telnet-enabled
  sonicwall: { detect: <SonicOS config pattern>, remediate: "<SonicOS CLI to disable>" }
  extreme:   { detect: <EXOS config pattern>,     remediate: "disable telnet" }
```

A concept a vendor doesn't have (e.g. a firewall has no "VTY access-class" but
has "management interface access rules") is marked `n/a` for that vendor and the
engine skips it — device-class already narrows the applicable families.

## Graceful partial coverage (honesty, not all-or-nothing)

A vendor need not arrive complete. A profile with only detection + SNMP + NVD
CVE mapping still provides value; hardening rules and on-device capture can come
later. The profile DECLARES what it supports, and the UI shows honest per-vendor
coverage — never a false "fully supported":

  SonicWall — CVE ✓ (PSIRT)  ·  hardening ✓ (firewall set)  ·  config-capture ✓
              ·  on-device pcap ✗ (SPAN-only)  ·  gNMI ✗

An unassessed dimension shows as unassessed (consistent with the vuln
"unassessed devices" honesty list), never as clear.

## The two examples

- **SonicWall (SonicOS firewall):** device_class firewall → the FIREWALL
  hardening family (mgmt-interface exposure, default access rules, admin access
  hardening, insecure mgmt protocols) rather than the switch/VTY family. CVE via
  SonicWall PSIRT advisories; config capture over the SonicOS CLI/API; SNMP
  enterprise OID for detection. Firewall zone/policy concepts extend the dialect
  table.
- **Extreme (EXOS switch):** device_class switch → the switch hardening family;
  EXOS `show configuration` capture; Extreme GTAC/PSIRT advisories; EXOS config
  parse patterns. (`collectors/vendor.go` already partially recognizes
  "extreme" — the profile formalizes and completes it.)

## Effort per vendor (bounded, mostly declarative)

| Dimension | Effort |
|---|---|
| Detection (OID + sysDescr + CPE name) | small — a few lines, often partly present |
| CVE binding | small if a PSIRT feed exists (connector config); else NVD-vendor-name mapping |
| Dialect terms | a handful |
| **Hardening bindings** | the bulk — detect/remediate for the ~20–30 concept catalog in the vendor's syntax (bounded DATA, many concepts similar across vendors) |
| Config-capture command | one mapping |
| SNMP profile | OID map (the SNMP Profile Manager UI already exists) |
| Packet-capture command | one mapping (or declare SPAN-only/unsupported) |

Standard protocols come free: NetFlow/sFlow/IPFIX and RFC syslog are
vendor-agnostic, so the flow and (largely) syslog lanes work for a new vendor
with no per-vendor code.

## Migration & where it lives

- Consolidate the scattered vendor knowledge behind the profile registry over
  time — `collectors/vendor.go`'s detection map, `netconcepts`' dialect, the
  CVE vendor mapping, and the SNMP profiles all become profile fields. Existing
  vendors get profiles that reproduce today's behavior (no regression).
- A profile is reference data (global, read-only — not tenant data, §3a). New
  profiles ship with the binary OR are operator-loadable (the offline/air-gap
  path), so a customer can add a vendor without waiting for a release.

## Net

Adding SonicWall or Extreme becomes: **write one Vendor Profile** (declarative,
mostly data), register it, and the vendor lights up across CVE matching,
hardening, config/packet capture, dialect, and detection — with the engines
untouched and honest partial-coverage until the profile is complete.
