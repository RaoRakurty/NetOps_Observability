# Troubleshooting — protocol diagnostics (collect → analyze)

Owner spec, 2026-08-27. A concrete mode of the rebuilt Troubleshooting page
(item 7). Complements — does not replace — the passive correlation engine:
this is **operator-initiated, point-in-time collection** that produces a
**shareable artifact** (paste into a TAC case). The engine does continuous RCA;
this is "capture the evidence myself, right now, and tell me what it says."

## Shape
- Tabs: **BGP · OSPF · IS-IS**.
- Each tab lists that protocol's **5 most common issues**. Picking one (or
  "collect all") arms a **Collect** button that runs a curated bundle of
  read-only `show` commands against the target device(s).
- A second **Analyze** button parses the collected output and returns a
  plain verdict + the likely cause + the remediation — rules-as-code over the
  raw text (the same pattern as the hardening/threat catalogs).
- The raw bundle + the verdict are **exportable** (redacted) for TAC / a peer.

## Vendor-dialect aware (reuses `internal/netconcepts`, item 4)
The issue is expressed as a **concept**; the command bundle renders in the
device's dialect. "OSPF neighbor" → Cisco `show ip ospf neighbor`, Juniper
`show ospf neighbor`, Nokia `show router ospf neighbor`. VRF/routing-instance is
resolved the same way. So one issue definition covers every vendor.

## The 15 issue → command-bundle matrix (Cisco IOS-XE shown; rendered per dialect)
Every bundle appends the **common L1/L2/routing supporting set** because most
protocol faults are really a layer below: `show interface <if>` (errors, CRC,
flaps, up/down), `show ip interface brief`, `show arp` / `show mac address-table`,
`show ip route`, MTU.

### OSPF
1. **Neighbor stuck (EXSTART/EXCHANGE/INIT, not FULL)** → `show ip ospf neighbor`, `show ip ospf interface <if>` (MTU, area, network-type), `show interface <if>` → *classic tell: EXSTART = MTU mismatch.*
2. **Adjacency won't form** → `show ip ospf interface <if>` (hello/dead timers, area-id, auth, network-type, subnet mask), `show run interface <if>`.
3. **Routes missing / not installed** → `show ip ospf database`, `show ip route ospf`, `show ip ospf` (area type stub/NSSA, distance).
4. **Flapping neighbor** → `show ip ospf neighbor` (state-change count), `show logging | i OSPF`, `show interface <if>` (flaps/errors).
5. **Suboptimal path / wrong metric** → `show ip ospf interface <if>` (cost), `show ip ospf database`, reference-bandwidth.

### BGP
1. **Session down (Idle/Active/Connect, not Established)** → `show ip bgp summary`, `show ip bgp neighbors <peer>`, `show ip route <peer-ip>`, TCP/179 reachability, ACL.
2. **Prefix not advertised / not received** → `show ip bgp neighbors <peer> advertised-routes` / `received-routes`, `show ip bgp <prefix>`, route-map / prefix-list / policy.
3. **Route not installed / best-path** → `show ip bgp <prefix>` (best-path reasons: local-pref, AS-path, MED, weight, next-hop reachability), `show ip route <prefix>`.
4. **Flapping session / dampening** → `show ip bgp neighbors <peer>` (flap count, last reset reason), `show logging | i BGP`, `show ip bgp dampening flap-statistics`.
5. **Wrong path / policy** → `show ip bgp <prefix>`, route-map, communities, AS-path access-list.

### IS-IS
1. **Adjacency down** → `show isis neighbors`, `show isis interface <if>` (level L1/L2, MTU, area, auth), `show clns interface <if>`.
2. **Adjacency stuck (INIT)** → `show clns neighbors detail`, hello-padding/MTU, network-type (p2p vs broadcast) mismatch.
3. **Routes missing** → `show isis database`, `show ip route isis`, L1↔L2 leaking, overload bit.
4. **Flapping** → `show isis neighbors`, `show logging | i ISIS`, `show interface <if>`, timers.
5. **Overload / suboptimal** → `show isis database detail` (overload-bit set?), metric-style (narrow vs wide).

## Collect mechanism
- Read-only `show` commands only, over the existing **device SSH gateway**
  (`FEATURE_DEVICE_SSH`, `device_ssh.go`) or **gNMI** where the device has it
  (state paths mirror the CLI). Never a config command.
- Runs the whole bundle in parallel across the picked devices; streams results
  into one panel; every command timestamped.

## Analyze mechanism (rules-as-code, mirrors hardening/threatlane)
- A catalog of **failure signatures** per issue: regex/structured matchers over
  the collected output → `{verdict, evidence-line, remediation, confidence}`.
  E.g. OSPF neighbor in `EXSTART` **and** `show interface` MTU differs across
  the link → "MTU mismatch — set matching `ip mtu` both ends." BGP peer `Idle`
  **and** no route to peer → "peering address unreachable — check the underlay /
  ACL," never a bare "session down."
- Fail-closed & honest: if the output doesn't match a known signature, say
  "no known signature matched — here's the raw output for TAC," never invent.

## Zero-trust / §3/§8
- Running commands on a device is authenticated + **audited** (who ran what,
  where, when). Per-tenant scoped (§3a) — an operator only collects from their
  own devices.
- Output can carry sensitive data → **redact before logging**, and the TAC
  export is an explicit, audited action with a redaction pass.

## Relationship to the correlation engine (the owner's redundancy question)
Not redundant — **complementary, and they cross-reference:**
- The **engine** is passive/continuous: it already knows "OSPF adjacency on
  core-01/Gi0/3 dropped, seam-owned." Its verdict is shown at the top.
- **This** is pull-on-demand: the operator captures the *actual device state
  right now* into a shareable bundle, and Analyze gives a second, evidence-
  linked read. Two honest signals beat one, and the raw capture is exactly what
  a vendor TAC asks for. Where the engine already has a verdict, Analyze shows
  it alongside "and here's what the live `show` output confirms."

## Where it lives on the page
A **Protocol Diagnostics** panel within the rebuilt Troubleshooting page
(item 7), sitting beside the symptom-first investigation flow: the investigation
answers "what's wrong and who owns it," this answers "capture and prove it, and
hand it to TAC."

## Build note
Reuses: SSH gateway (present, dormant), gNMI (present), netconcepts dialect
(present), the rules-as-code catalog pattern (present in hardening/threatlane).
New: the issue→bundle catalog, the collector orchestrator, the analyze
signatures, the export/redaction, and the UI. Feature-flagged; tests + isolation
test per §11/§3a.
