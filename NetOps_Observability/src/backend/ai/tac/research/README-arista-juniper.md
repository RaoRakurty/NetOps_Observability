# TAC research — Arista EOS and Juniper Junos

Research inputs for the TAC escalation pack (design of record:
`docs/design/TAC_ESCALATION_2026-09-05.md`). Two files, 40 issues each, every
command quoted from a public vendor page that was actually fetched.

- `arista-eos.yaml` — 40 issues, 268 command entries (181 distinct commands)
- `juniper-junos.yaml` — 40 issues, 259 command entries (121 distinct commands)

**Schema note:** `ai/tac/README.md` did not exist when this research was written,
so both files use the schema given in the research brief (`vendor`, `sources`,
`tac_baseline`, `issues[]` with `id`/`class`/`title`/`symptoms`/`log_signatures`/
`likely_causes`/`commands[{cmd,intent,params}]`/`tac_first_look`/`sources`). Two
optional keys were added where honesty required them: `proposed_class: true` on a
class not in the design taxonomy, and `sourcing_note` on an issue whose command
text came from vendor page content that a JavaScript portal would not render
directly.

## Vendor TAC data-collection guides

**Arista**
- Arista Support & Community Guide (case-opening requirements, file upload paths):
  https://www.arista.com/assets/data/pdf/Arista_Support_Community_Guide.pdf
  — asks for a detailed problem description, the output of `show tech-support`
  "(ideally compressed)", network diagrams, and contact details; for an RMA it adds
  `show version` (the serial number in it determines the SLA). Upload: Support
  Portal (10 GB), email (25 MB, must quote the case Ref ID), or FTP to
  `ftp.arista.com` (`cd support`, `cd <case number>`, `put <filename>`).
- EOS User Manual index: https://www.arista.com/en/um-eos

**Juniper**
- Data Collection for Customer Support:
  https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/task/data-collection-for-jtac.html
  — `request support information | save /var/tmp/rsi-CURRENT-DATE.log`, then
  `file archive compress source /var/log/* destination /var/tmp/logs-CURRENT-DATE.tgz`,
  then `file list /var/tmp/logs-CURRENT-DATE.tgz detail`; upload both to the case.
- `request support information` reference:
  https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/request-support-information.html
- JTAC User Guide (PDF):
  https://www.juniper.net/content/dam/www/assets/resource-guides/us/en/jtac-user-guide.pdf

## Proposed classes (not in the §2 taxonomy)

The design taxonomy is `ospf-adjacency`, `ospf-database`, `ospf-flapping-link`,
`isis-adjacency`, `isis-lsp`, `bgp-session`, `bgp-route-missing`, `bgp-instability`,
`interface-errors`, `link-flap`, `optics`, `hardware-fault`, `high-cpu`,
`high-memory`, `mlag-vpc-peer`, `evpn-vxlan`, `qos-drops`, `mpls-ldp`,
`config-change`, `generic`. These two files need the following additions, each
marked `proposed_class: true` at every use:

| Proposed class | Why it is not covered by an existing class | Used by |
|---|---|---|
| `lacp-bundle` | LAG member not bundling is neither an interface error nor a link flap; the evidence is actor/partner LACP state | both |
| `stp-topology` | Topology-change churn, unexpected root, and guard-triggered blocking | Arista |
| `vlan-trunk` | Allowed-VLAN / native-VLAN mismatch on an up trunk | Arista |
| `mac-learning` | MAC flapping or a MAC that will not learn (port security, static pin) | Arista |
| `fhrp-anycast-gw` | VRRP dual-master and VARP anycast-gateway failure | Arista |
| `virtual-chassis` | VC member not joining / VCP down — the Junos analogue of `mlag-vpc-peer` | Junos |
| `mpls-rsvp` | The taxonomy has `mpls-ldp` only; RSVP-TE LSP down/flapping is a distinct battery | Junos |
| `l3vpn` | VRF route missing vs. blackhole with routes present | Junos |
| `interface-down` | A port that never comes up is a different first look from one that flaps | Junos |
| `environment` | PSU / fan / temperature is triaged separately from a component `hardware-fault` | both |
| `process-crash` | Agent crash (EOS) / daemon core (Junos) — a core file changes the case type | both |
| `software-upgrade` | Boot, image and extension-load failures | Arista |
| `storage-full` | /var full is its own failure and blocks RSI collection | Junos |
| `control-plane-policing` | ACL/CoPP (EOS) and DDoS-protection policers (Junos) | both |
| `ntp-sync`, `snmp`, `aaa-auth`, `dhcp-relay`, `multicast` | Management-plane and service classes with their own command batteries | both (dhcp-relay Junos only) |

If the taxonomy should stay small, `environment` can fold into `hardware-fault`
and `vlan-trunk`/`mac-learning` into `stp-topology` — but `lacp-bundle`,
`virtual-chassis`, `mpls-rsvp`, `l3vpn` and `process-crash` each carry a genuinely
different command plan and should stay.

## Excluded commands, and why

Every entry is read-only. Deliberately excluded, with the reason:

- **Arista** — `clear ip bgp <peer>` (documented recovery for a peer idled by
  `maximum-accepted-routes`); `clear ip access-lists counters`,
  `clear ipv6 access-lists counters`, `clear aaa counters radius|tacacs`,
  `clear radius proxy counters`, `event-monitor clear`; all `debug` forms;
  `reload`/`restart`; config-mode statements the docs mention as fixes
  (`dual-primary detection ... action errdisable`, `dual-primary recovery delay`,
  `spanning-tree bpduguard rate-limit`, `switchport trunk allowed vlan`,
  `switchport trunk native vlan`, `mac address-table aging-time`,
  `default switchport port-security mac address moveable`, `ip virtual-router
  address`, `hardware tcam profile vxlan-routing`, `event-monitor <table>`);
  `bash`/shell steps such as reading `/var/log/agents` or copying `/var/core`;
  the CCF/DMF-only `upload support <filename>`.
- **Junos** — `clear bgp neighbor` (needed to recover a peer held by
  `idle-timeout forever`) and `clear bgp damping`; `restart routing`;
  `restart interface-control` and `request virtual-chassis recycle` (both named on
  the VC troubleshooting page); `request diagnostics tdr start|abort` (TDR is an
  active test that disrupts the link); all `traceoptions` recommendations;
  `monitor interface traffic` and `monitor traffic`; `ping`, `ping mpls`,
  `traceroute`, `ping overlay`/`traceroute overlay` (they inject traffic — the MPLS
  and L3VPN troubleshooting pages lean on them heavily, so they are the obvious
  candidates if an "active probe" tier is ever added); `file archive compress ...`
  from the JTAC baseline, because it writes an archive rather than reading state —
  it is called out in `tac_baseline.notes` so the collector can be granted that one
  write deliberately.

## Known coverage gaps (deliberately left empty rather than guessed)

- **Arista**: DHCP relay (the IPv4 chapter's DHCP-relay sections exist but no
  `show` command could be read from a fetchable page) and feature **licensing**
  (no core-EOS `show license`-class command found publicly). No issue was written
  for either; adding one needs an on-box or logged-in-portal confirmation.
- **Arista**: the exact `show tech-support | gzip` piping form is *not* stated on
  any public page — the support guide only says "ideally compressed". The `logGrab`
  helper script could not be confirmed on a fetchable official page either.
- **Arista**: platform/chip-family TCAM utilisation commands exist (referenced from
  the TCAM TOI index) but their exact syntax is gated; omitted rather than guessed.
- **Junos**: spanning tree (`show spanning-tree bridge`/`interface`),
  `show ethernet-switching table`, `show vlans`, MC-LAG (`show interfaces mc-ae`,
  `show iccp`), `show firewall` filter counters and `show system license` could not
  be confirmed on a fetchable CLI-reference page in this pass (the session's web
  search budget ran out and those slugs 404 under the patterns that worked for ~40
  other commands). L2 fabric coverage for Junos therefore leans on the EVPN command
  set. These are the first gaps to close in a follow-up pass.
- Several `supportportal.juniper.net` KB articles and most `eos.arista.com`
  community articles render only inside a JavaScript portal. Where their content is
  used, the issue carries a `sourcing_note` and the URL is still cited; treat those
  command spellings as verify-on-box rather than as quoted-from-a-rendered-page.
