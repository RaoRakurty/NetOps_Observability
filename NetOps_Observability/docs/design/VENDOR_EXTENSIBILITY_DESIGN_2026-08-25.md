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

## Schema addendum — `config_capture.platform_dialects` (2026-09-02)

The config-capture binding is **vendor-level**: one command per vendor family,
because `internal/configstore` resolves a device to a family and never to a
platform (one Junos command serves every Junos box, and the volatile header a
device stamps is a property of the OS family, not the chassis). That holds for
every vendor that ships one CLI.

Nokia ships two. SR OS answers `admin display-config` in the classic TiMOS CLI;
SR Linux answers `info from running flat` in a model-driven CLI that shares no
statement with it. They cannot be two vendor documents — the document name *is*
the vendor id — and they cannot share one command without sending one of the two
a command it does not have. So `config_capture` gained an optional
`platform_dialects` array: a **sibling capture family** under one vendor, with
its own id, its own `platform_contains`/`platform_rank`, its own
`running_config_cmd` and its own `volatile_rules`.

```jsonc
"config_capture": {
  "platform_contains": ["nokia", "sr os", "sros", "timos", "alcatel"],
  "platform_rank": 50,
  "running_config_cmd": "admin display-config",
  "volatile_rules": [ /* SR OS' # Generated / # Finished / # TiMOS- headers */ ],
  "platform_dialects": [{
    "id": "srlinux",
    "platform_contains": ["sr linux", "srlinux"],
    "platform_rank": 45,          // MUST beat its own vendor: the label contains "nokia"
    "running_config_cmd": "info from running flat",
    "volatile_rules": [],         // measured: the flat form stamps no header at all
    "notes": "how the command was established"
  }]
}
```

Four properties are load-bearing and enforced at load:

- **One rank space.** A dialect's `platform_rank` competes with every vendor's in
  the same ranked, first-match-wins pass, and uniqueness is checked across both.
  This is not cosmetic: "Nokia SR Linux" contains "nokia", so without rank 45 the
  nokia family claims it and an SR Linux box is sent SR OS' command.
- **A dialect must be reachable.** `platform_contains` and a positive rank are
  required — a capture command nothing can resolve to is a silently dead table.
- **The id is the key downstream.** `ConfigCaptureVendorForPlatform` returns the
  *dialect* id, and the capture command, the volatile-rule list and the redaction
  rule set all key on it. `ConfigCaptureFamilies()` (vendors + dialects) is what
  a consumer's closed-table test iterates, so a new dialect cannot ship a
  device-facing command without a golden.
- **No inheritance.** A dialect does not inherit its vendor's volatile rules. SR
  Linux declares none, and that is a measured claim (two consecutive captures of
  lab spine1 were byte-identical over 728 lines), not an omission.

The `capture` block on the *profile* is unchanged and still the platform's own
command; the two may legitimately differ, and for `nokia/srlinux` they now agree.

The same day, two `hardening.binding` values were added for the same reason —
`arista` (EOS borrows IOS' *show* grammar, not its *configuration* grammar) and
`srlinux` (which had been scored against SR OS' grammar and answering "not
enabled" to everything). A hardening binding is a third axis, independent of both
`cli.dialect` and the capture family.

## Net

Adding SonicWall or Extreme becomes: **write one Vendor Profile** (declarative,
mostly data), register it, and the vendor lights up across CVE matching,
hardening, config/packet capture, dialect, and detection — with the engines
untouched and honest partial-coverage until the profile is complete.
