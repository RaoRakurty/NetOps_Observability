# Cisco TAC research — IOS-XE, IOS-XR, NX-OS

Research inputs for the TAC escalation pack (design of record:
`docs/design/TAC_ESCALATION_2026-09-05.md`). Three files, one per dialect:

| File | Dialect id | Issues |
|---|---|---|
| `cisco-iosxe.yaml` | `cisco-iosxe` | 40 |
| `cisco-iosxr.yaml` | `cisco-iosxr` | 38 |
| `cisco-nxos.yaml`  | `cisco-nxos`  | 40 |

`ai/tac/README.md` did not exist when these were written, so the schema is the one
given in the research brief (`vendor` / `sources` / `tac_baseline` / `issues`).
`tac_baseline.commands` is a plain list of command strings, exactly as the brief
specifies.

## The three vendor TAC data-collection guides

These are the "what TAC asks for on every case" documents; each file's
`tac_baseline` is built from its own one.

- **IOS / IOS-XE** — Quick Start Guide: Data Collection for Various Routing &
  Platform (IOS & IOS-XE Routers) Related Issues
  https://www.cisco.com/c/en/us/support/docs/ip/ip-routing/216088-quick-start-guide-data-collection-for.html
- **IOS-XR** — Troubleshoot Quick Reference Command List for TAC Assistance
  https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xr-software/215365-quick-reference-guide-to-collect-tac-req.html
- **NX-OS** — Quick Reference Guide to collect TAC requested outputs from Nexus switches
  https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/214107-quick-reference-guide-to-collect-tac-req.html

Supporting baselines also cited: the Nexus 9000 troubleshooting guide's *Before
Contacting Technical Support* chapter, the Nexus 7000 CLI Management Best Practices
*Collecting Data for the Cisco TAC* chapter, the ASR 9000 *Tech-Support Commands*
reference, and the Cisco IOS XE Software Forensic Data Collection Procedures.

## Proposed additions to the issue-class taxonomy

The design's closed taxonomy (§2) has 20 classes. Everything below is carried in the
YAML with `proposed_class: true` on each issue that uses it. 28 proposals:

**Routing**
- `eigrp-adjacency` — EIGRP neighbour not forming / flapping (IOS-XE, NX-OS)
- `eigrp-route-missing` — prefix absent from the EIGRP topology or RIB (IOS-XE)
- `eigrp-sia` — route stuck-in-active; distinct failure mode, pages on its own (IOS-XE)
- `multicast-pim` — PIM neighbour missing, mroute/RPF failure (all three)
- `multicast-igmp` — IGMP / IGMP-snooping group not programmed (IOS-XE, NX-OS)
- `bfd-session` — BFD session down taking its client protocol with it (IOS-XR)
- `rib-fib-inconsistency` — routing table and forwarding table disagree (NX-OS)

**MPLS**
- `mpls-l3vpn` — VPNv4/VRF route missing, route-target import/export (IOS-XE, IOS-XR)
- `mpls-forwarding` — label binding present but not programmed; LSP black-hole (IOS-XR)
- `mpls-te` — TE tunnel down: path computation, RSVP signalling, admission control (IOS-XR)

**Layer 2**
- `stp-topology` — TCN churn, L2 loop / broadcast storm, guard-inconsistent port
- `vlan-trunk` — trunk not forming, allowed/native VLAN mismatch, VLAN suspended
- `port-channel-lacp` — port-channel not bundling, member suspended
- `mac-learning` — MAC move / MAC flapping / learn-disable, unknown-unicast flooding
- `fhrp` — HSRP **and** VRRP (dual-active, state churn, virtual-IP conflict). One class
  for both; NX-OS's real syslog facilities are `HSRP_ENGINE-*` and `VRRP-ENG-*`.

**Forwarding / policy**
- `forwarding-drops` — NP/ASIC/punt-path drops that are not interface errors (IOS-XR)
- `acl-drops` — traffic dropped by an ACL, or ACL/TCAM programming exhaustion
- `control-plane-policing` — CoPP (IOS-XE, NX-OS) and LPTS (IOS-XR) policer drops

**Platform / lifecycle**
- `crash-reload` — process crash, core file, unexpected reload
- `platform-boot` — node not in RUN state, SW_INACTIVE, card boot failure (IOS-XR)
- `fpd-firmware` — FPD/field-programmable firmware below the image baseline (IOS-XR)
- `redundancy-switchover` — RP/RSP redundancy state wrong or unplanned switchover (IOS-XR)
- `software-install` — install / SMU activation / commit failure (IOS-XR)
- `licensing` — smart licensing trust, communication, or entitlement failure

**Services**
- `ntp-sync` — clock not synchronising
- `snmp-agent` — polling failures, timeouts, SNMP-driven CPU
- `aaa-auth` — AAA / TACACS+ authentication or authorization failure
- `dhcp-relay` — DHCP relay / ip helper-address failure

## Conventions and honesty notes

- **Read-only only.** No `debug`, `clear`, `reload`, `test`, `monitor`/capture,
  `attach module`, `bcm-shell`, `ethanalyzer`, `install`, `tac-pac`, `copy` or
  configuration commands appear in any `commands` list, even where the source doc
  lists them. `dir`, `ping` and `traceroute` are used where a doc uses them.
- **Abbreviations expanded.** Where a Cisco page prints an abbreviated form
  (`sh int`, `sh contr np counters np0`), the YAML carries the canonical full form
  with placeholders (`show interfaces <if>`, `show controllers np counters np<npu>
  location <loc>`). No command text was otherwise altered.
- **Placeholders**: `<if> <peer> <prefix> <vrf> <vlan> <po> <loc> <npu> <slot>
  <name> <jid> <instance> <group> <vni> <mac> <pid>`; each is declared in that
  command's `params`.
- **`log_signatures` are doc-sourced only.** Where no syslog mnemonic could be found
  on a fetched Cisco page for that OS, the list is empty rather than guessed. Two
  consequences worth knowing:
  - **IOS-XR routing adjacency mnemonics are not publicly documented.**
    `%ROUTING-BGP-5-ADJCHANGE`, `%ROUTING-ISIS-4-ADJCHANGE`, `%ROUTING-OSPF-5-ADJCHG`
    and `%L2-BFD-*` could not be found on any public cisco.com page. They are *not*
    shipped. The XR mnemonics that **are** verified include
    `%PKT_INFRA-LINK-3-UPDOWN`, `%PKT_INFRA-ERRDIS-6-ERROR_DISABLE`,
    `%OS-SHMWIN-2-ERROR_ENCOUNTERED`, `%HA-HA_WD_LIB-4-RLIMIT`,
    `%ROUTING-BGP-4-VIRTUAL_MEMORY_LIMIT_THRESHOLD_REACHED`,
    `%ROUTING-IPV4_IGMP-4-OOR_LIMIT_REACHED`, `%MGBL-CONFIG-6-DB_COMMIT`.
    Filling the routing gap needs the (login-gated) IOS-XR System Error Message
    reference or captured lab syslog — not inference.
  - **NX-OS FHRP facilities are not what people assume.** The Nexus 9000 System
    Messages Reference has no `%HSRP-5-STATECHANGE` and no `%VRRP-*`. The real
    strings are `%HSRP_ENGINE-5-GRPSTATECHANGE`, `%HSRP_ENGINE-6-STATECHANGE`,
    `%VRRP-ENG-5-VR_STATE_CHANGE`. Log-matching rules must key on those.
- **NX-OS release mix.** Command spellings were confirmed against the Nexus 9000
  Show Command Reference 7.0(3)I7(x); behaviour and causes come from the 9.3(x)
  troubleshooting guide and the 10.6(x) configuration guides. A few commands exist
  only in the newer guides and are cited to them.
- **Known doc gap:** the Nexus 9000 9.3(x) troubleshooting guide chapter its own TOC
  labels "Troubleshooting VLANs" actually contains VXLAN Broadcom-shell data-path
  material. VLAN coverage is sourced from the Layer 2 Switching configuration guide
  instead.

## Commands considered and excluded as unverified

These are widely used in practice but could not be confirmed verbatim on a fetched
public page for that OS, so they are **not** in the YAML:

- IOS-XR: `show vrf <vrf> detail`, `show bgp vpnv4 unicast ...`,
  `show ospf neighbor detail` (the `detail` keyword is confirmed for OSPFv3 and for
  `show isis adjacency`, not for OSPFv2), `show bgp neighbors <peer> received-routes`,
  `show snmp mib access` (on the TAC page but not in the SNMP command reference).
- NX-OS: `show bgp ipv4 unicast neighbors <peer> received-routes`,
  `show ip ospf database`, `show hsrp state`, `show vrrp detail`, bare
  `show ip mroute`, `show port-channel compatibility-parameters`,
  `show hardware internal buffer info pkt-stats` for the H-chapter (used, but cited
  to the TAHUSD technote rather than the command reference).
- IOS-XE: `show interface transceivers` (plural, as an inventory command) —
  replaced with the documented `show interfaces transceiver supported-list` and
  `show idprom interface <if> | include Connector type`.
- Anything under a `debug`-named subcommand (e.g. IOS-XR
  `show optics-driver debug optics port ...`) is excluded on the token alone.
