# TAC research — Nokia SR Linux, Nokia SR OS, Huawei VRP, Fortinet FortiOS, Palo Alto PAN-OS

Research inputs for the TAC escalation pack (design of record:
`docs/design/TAC_ESCALATION_2026-09-05.md`). Five files; every command is quoted
from a public vendor page that was actually fetched — nothing is invented.

| file | issues | command entries (distinct) | baseline |
|---|---|---|---|
| `nokia-srlinux.yaml` | 40 | 253 (138) | 14 |
| `nokia-sros.yaml` | 40 | 252 (170) | 14 |
| `huawei-vrp.yaml` | 52 | 318 (177) | 31 |
| `fortinet-fortios.yaml` | 55 | 363 (171) | 24 |
| `paloalto-panos.yaml` | 40 | 242 (110) | 16 |

Huawei and FortiOS exceed the 30–40 band on purpose: the mandated coverage list
for each enumerates more than 40 distinct, separately-cited scenarios, and
trimming would have meant dropping grounded material. Every extra issue carries
its own sources.

**Schema note:** `ai/tac/README.md` did not exist when this research was written,
so all five files use the schema from the research brief — `vendor`, `sources`,
`tac_baseline{commands[{cmd,intent,params,writes_file?}], notes, sources}`, and
`issues[]` with `id`/`class`/`title`/`symptoms`/`log_signatures`/`likely_causes`/
`commands[{cmd,intent,params,writes_file?}]`/`tac_first_look`/`sources`.
`proposed_class: true` marks a class outside the §2 taxonomy. `params` is
validated to equal exactly the set of `{}` placeholders in `cmd`.

---

## Vendor TAC data-collection guides

**Nokia SR Linux** — the bundle command is **`tech-support`**, a bare global CLI
command usable from any mode. It is *not* under `tools system`, contrary to the
research brief's assumption. It pauses ~5 s while applications dump their reports
and **writes a zip on the device** under `/tmp` (`admintech-report-<ts>.zip`, newer
builds `tech-support-<ts>-<host>.zip`). `tech-support exclude-binaries` omits IDB
and proprietary content for a smaller archive. Both `writes_file: true`.
- https://documentation.nokia.com/srlinux/26-3/books/system-mgmt/cli-interface.html
- https://documentation.nokia.com/srlinux/26-7/books/system-mgmt/general-operational-commands.html
- https://documentation.nokia.com/srlinux/26-7/books/system-mgmt/pre-defined-show-reports.html — the authoritative catalogue of every `show` report
- https://documentation.nokia.com/srlinux/26-7/books/log-events/ — every `log_signatures` entry is a real event id from here
- https://learn.srlinux.dev/cli/show-commands/

**Nokia SR OS** — **`admin tech-support [file-url]`** (`writes_file: true`).
Nokia's own reference says it "creates a system core dump" and "should only be
used with authorized direction of Nokia support": treat it as an owner-approved
change-window action, not a routine collector. With `file-url` omitted it
auto-names `ts-XXXXX.<date>.<time>UTC.dat` into the configured `ts-location`,
which SR OS does **not** auto-create; with no ts-location the file-url is
mandatory. `admin display-config` is the read-only config dump.
- https://documentation.nokia.com/sr/23-7-2/cli-books/classic-cli-command-reference/classic-t-commands.html (`admin tech-support`, `ts-location`)
- https://documentation.nokia.com/sr/23-7-2/cli-books/classic-cli-command-reference/classic-d-commands.html (`admin display-config`)
- https://documentation.nokia.com/sr/22-10-2/titles/clear-monitor-show-tools-commands.html — the CMST book; its a–x chapters are the syntax authority
- https://documentation.nokia.com/sr/22-10-2/books/log-events/log-bgp.html (+ ospf/isis/ldp/mpls/rsvp/port/chassis/lag/svcmgr/vrtr/system/security/snmp/ntp/bfd/stp)

**Huawei VRP** — **`display diagnostic-information [file-name]`**. With a
file-name it writes a `.txt` to the default storage device (`writes_file: true`);
without one it dumps to the terminal. Huawei's own caveat: running it on several
terminals at once markedly raises CPU usage and degrades device performance; it
also emits personal data (e.g. MAC addresses), which must be deleted after use.
Newer releases add a one-click logs/KPI/PADS collection mode.
- https://support.huawei.com/enterprise/en/doc/EDOC1100280260/974004b2/collecting-fault-information-using-query-commands
- https://support.huawei.com/enterprise/en/doc/EDOC1100280260/794e659e/collecting-diagnostic-information-logs-kpis-and-pads-files-in-one-click-mode-versions-earlier-than-v800r025c00
- https://support.huawei.com/enterprise/en/doc/EDOC1100280260/5df02e82/commonly-used-commands-for-maintenance
- https://support.huawei.com/enterprise/en/doc/EDOC1100280260/c4073c75/collecting-fault-information
- NE40E Troubleshooting Guide (rich per-case alarms/logs sections): https://support.huawei.com/enterprise/en/doc/EDOC1000177634
- NetEngine 8000 F8 Troubleshooting Guide: https://support.huawei.com/enterprise/en/doc/EDOC1100280260

  *Access note:* `support.huawei.com` returns HTTP 403 to direct fetches (Akamai)
  and a JS shell to headless renderers. The pages were read through a text-proxy
  transport; the canonical `support.huawei.com` URLs above are what is cited.

  CE-switch VXLAN/EVPN/M-LAG and stack/CSS are fully citable from the CloudEngine
  16800/9800/8800/6800 Troubleshooting Guide (V300):
  https://support.huawei.com/enterprise/en/doc/EDOC1100313446 — real case studies
  with commands and example output for VXLAN tunnel failure, EVPN route learning,
  MAC flapping, all three M-LAG failure modes, and stack/CSS setup failure.
  Run `display diagnostic-information` from the **user view**, never over the
  console port, and never while CPU is already high — collect specific commands
  instead. `dir` is the one non-`display` baseline entry: Huawei's own procedure
  uses it to confirm the diagnostic file was written.

**Fortinet FortiOS** — **`execute tac report`** runs the whole diagnostic
battery. Fortinet documents it as console output ("an extensive snapshot of your
system … the output from this command is very large"); **no fetched page states
that it writes a file on the FortiGate**, so it is recorded `writes_file: false`
and flagged as *output-only, file-writing not claimed*. `diagnose debug report`
appears nowhere in the 7.6.0 Administration Guide page set (1324 URLs) — recorded
as **unverified** rather than guessed. Everything is per-VDOM unless scoped
global.
- https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/321075/troubleshooting-methodologies — Fortinet's own "gather information for technical support" checklist
- https://docs.fortinet.com/document/fortigate/7.4.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet — the single richest source
- https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/194558/conserve-mode
- https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/44240/ipsec-related-diagnose-commands
- https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/818746/sd-wan-related-diagnose-commands

**Palo Alto PAN-OS** — **the CLI form of tech-support generation could not be
verified.** Every public page found documents it only through the web UI
(Device > Support > *Generate Tech Support File* → *Download Tech Support File*).
`scp export tech-support` / `tftp export tech-support` / `request tech-support
dump` appear in **no** fetched page, so **no tech-support command is asserted in
the file**. The only verified CLI export forms are `scp export configuration
from <named-config> to <user@host:path>` and `scp export logdb to
<user@host:path>` — both `writes_file: true`, and both *push data to an external
host*, which is a different trust model from a read (see Open questions).
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-web-interface-help/device/device-support
- https://docs.paloaltonetworks.com/panorama/administration/troubleshooting/troubleshoot-panorama-system-issues/generate-diagnostic-files-for-panorama
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/cli-cheat-sheets/cli-cheat-sheet-device-management
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/cli-cheat-sheets/cli-cheat-sheet-networking
- https://docs.paloaltonetworks.com/sd-wan/administration/troubleshooting

---

## Proposed classes (not in the §2 taxonomy)

The design taxonomy is `ospf-adjacency`, `ospf-database`, `ospf-flapping-link`,
`isis-adjacency`, `isis-lsp`, `bgp-session`, `bgp-route-missing`,
`bgp-instability`, `interface-errors`, `link-flap`, `optics`, `hardware-fault`,
`high-cpu`, `high-memory`, `mlag-vpc-peer`, `evpn-vxlan`, `qos-drops`,
`mpls-ldp`, `config-change`, `generic`. Everything below carries
`proposed_class: true`.

**Routing / infrastructure OSes**

| class | files | note |
|---|---|---|
| `lag-lacp` | srlinux, sros, vrp | Huawei Eth-Trunk maps here |
| `ntp-sync` | srlinux, sros, vrp | |
| `snmp` | sros, vrp | |
| `aaa-auth` | srlinux, sros, vrp | TACACS+/RADIUS/HWTACACS login |
| `bfd` | sros, vrp | |
| `logging` | srlinux, vrp | syslog / logbuffer / trapbuffer pipeline |
| `arp-nd` | srlinux, vrp | |
| `mpls-rsvp-te` | sros | |
| `l2vpn-vpls`, `l3vpn-vprn`, `sap-service`, `oam-sdp` | sros | SR OS service model |
| `mpls-l3vpn` | vrp | |
| `segment-routing` | vrp | |
| `stp-topology` | vrp | MSTP topology change / loop |
| `stack-css` | vrp | CSS / iStack setup failure (M-LAG uses `mlag-vpc-peer`) |
| `control-plane-policing` | vrp | Huawei CPCAR / cpu-defend |
| `acl` | srlinux | |
| `dhcp-relay` | srlinux | |
| `ip-vrf-routing` | srlinux | |
| `netconf-gnmi` | srlinux | management-plane / gRPC server |
| `process-health` | srlinux | application/process state |

**Firewalls** — FortiOS and PAN-OS agree on names wherever the concept matches:

`session-table`, `firewall-policy`, `nat`, `ipsec-vpn`, `ssl-vpn` (PAN-OS uses it
for GlobalProtect), `ha-cluster`, `content-update`, `logging-pipeline`,
`ssl-inspection` (PAN-OS decryption), `user-auth-fsso` (PAN-OS User-ID),
`routing-table`, `dns-resolution`, `licensing`, `certificate`,
`management-access`, `dhcp`, `traffic-shaping`.

FortiOS only: `conserve-mode`, `utm-inspection`, `sdwan-link`, `ztna`,
`hardware-offload` (NPU-offloaded sessions invisible to software diagnostics),
`mtu-path`.
PAN-OS only: `resource-exhaustion`, `panorama-connectivity`.

**Naming decision:** PAN-OS uses `resource-exhaustion`, *not* `conserve-mode` —
PAN-OS has no conserve mode; the analogue is packet-buffer protection plus
disk/log-quota pressure, and the FortiOS term would mislead.

### Cross-file synonyms to normalise before `classes.yaml` is frozen

The sibling Cisco/Arista/Juniper research coined different names for the same
concepts. One name should win per row:

| concept | names in use |
|---|---|
| link aggregation | `lag-lacp` (Nokia, Huawei) · `lacp-bundle` (EOS, Junos) · `port-channel-lacp` (IOS-XE, NX-OS) |
| SNMP | `snmp` (SR OS, VRP, EOS, Junos) · `snmp-agent` (Cisco) |
| BFD | `bfd` (SR OS, VRP) · `bfd-session` (IOS-XR) |
| ACL drops | `acl` (SR Linux) · `acl-drops` (IOS-XR, NX-OS) |
| MPLS TE | `mpls-rsvp-te` (SR OS) · `mpls-rsvp` (Junos) · `mpls-te` (IOS-XR) |
| L3VPN | `l3vpn-vprn` (SR OS) · `l3vpn` (Junos) · `mpls-l3vpn` (Cisco, VRP) |
| logging | `logging` (SR Linux, VRP) · `logging-pipeline` (firewalls) |
| process failure | `process-health` (SR Linux) · `process-crash` (EOS, Junos) |
| software | `software-upgrade` (EOS) · `software-install` (IOS-XR) |
| environment/hardware | `environment` (EOS, Junos) vs the taxonomy's `hardware-fault` |

---

## Open questions for the build

1. **`ValidateReadOnly` will reject legitimate reads on token alone.** Eight
   FortiOS commands are documented *status prints* that carry the `debug` token:
   `diagnose debug crashlog read`, `diagnose debug config-error-log read`,
   `diagnose debug rating`, `diagnose debug fsso-polling {detail,summary,user}`,
   `diagnose debug authd fsso {list,server-status}`. They need an explicit
   allowlist. Similarly SR Linux's `... protocols bgp graceful-restart` and
   Huawei's `display configuration commit list` / `display board-reset` are reads
   whose text contains `restart` / `commit` / `reset`.
2. **FortiOS stateful read-scoping.** `diagnose sys session filter <opt> <val>`
   and `execute log filter …` set a daemon-side read scope (they change no
   config and clear nothing), but `diagnose sys session list` is unusable on a
   production firewall without them. Product decision needed on whether the
   command table may emit scope-setters. `... filter clear` is excluded.
3. **FortiOS `diagnose sniffer packet <if> '<bpf>' 4 <count> l`** appears in 4
   issues. It is a live capture with an operator-supplied BPF — route it through
   the existing closed BPF grammar from the Packet Capture module, not the plain
   read-only table.
4. **FortiOS `diagnose test application <daemon> <n>`** (17 entries). Only "show"
   levels were kept; restart levels (99, and daemon-specific ones) were excluded.
   This needs a per-daemon, per-level allowlist, not a prefix match.
5. **PAN-OS `test authentication … password`** takes a cleartext credential on
   the command line. Recommend excluding it from automated collection or gating
   it behind explicit operator entry. (FortiOS's `diagnose test authserver …`
   was excluded for exactly this reason.)
6. **PAN-OS `scp export …` in the baseline** pushes files to an arbitrary
   external host rather than returning output over Correlix's own SSH channel.
   Probably wrong for the collector; the tech-support bundle likely has to come
   from the XML API (`type=export&category=tech-support`) instead — unverified in
   public docs and worth confirming with a licensed account.
7. **SR OS `admin tech-support` is not routine.** Nokia calls it a core dump
   requiring TAC authorisation. It should sit behind the design's optional
   size/time toggle with an explicit consent prompt, not in the default baseline.
8. **Huawei `pads diagnose …` was excluded but is high-value.** `pads diagnose
   route record rm ipv4-unicast`, `… isis spf-link`, `pads diagnose route flap
   source-trace bgp` are read-only in effect but are not `display` forms, so they
   failed the read-only rule. Huawei's own mandatory-check table lists them as the
   *first* thing to run for protocol-flapping cases. Worth a decision on widening
   the allowlist. Same question for the internal `display` forms excluded under
   Huawei's "Limited Command Permission" notice (`display dfs black-box …`,
   `display kpi …`, `display middleware litedb …`).
9. **Huawei QoS coverage is thin and that is honest, not an omission.** All five
   NE QoS case studies render as flowchart images with zero command text; the CE
   QoS pages are pure TOCs. The one `qos-drops` issue rests on
   `display traffic policy statistics interface {if} inbound` plus interface drop
   counters. No HQoS or queue-scheduling commands were invented.
10. **Nothing was sourced from `community.fortinet.com` or
   `knowledgebase.paloaltonetworks.com`.** The session's WebSearch budget was
   exhausted before those could be reached and neither site is crawlable without
   search. Both are official and would add real per-issue detail; worth a second
   pass with search available.
