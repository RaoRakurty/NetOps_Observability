# Active Verification — Troubleshooting Modules

Status: modules 1–3 SHIPPED (2026-07-19) · 7 planned
Code: `src/backend/verify_modules.go` (+ `verify_engine.go` integration),
evidence lane: `src/correlation/verification_producer.py`
Owner ruling: mine the *knowledge* of NetClaw (Apache-2.0, John Capobianco,
`github.com/automateyournetwork/netclaw`, pinned commit
`49332542f43390955e758b69855a111b5ba0ff4c`) as content for prebuilt
deterministic modules — never run or integrate the agent itself. **Nothing in
this subsystem calls an LLM at runtime.** Attribution: see `NOTICE`.

## What a module is

The core Active Verification battery (RCA spec item 8) asks a small fixed set
of questions of every implicated device. A **module** is a set of extra
read-only checks with a **trigger condition**: a case runs the core battery
plus only the modules whose condition its context matches. Everything else is
identical to the core battery — the closed command allowlist, the one-SSH-
connection-per-device runner, per-check timeouts, the run budget, tenant-scoped
run records, and the corroborate/refute evidence contract.

Module firing context (`verifyCaseContext`) comes from the case's
`corr_current` row: seam `owner` badge, `top_hypothesis` template id,
`verdict_tier`, and `window_start` (for window-relative recency verdicts).

## Module catalog

### Shipped

| # | Module | Check id | Trigger condition | Looks for | Corroborates | Refutes |
|---|--------|----------|-------------------|-----------|--------------|---------|
| 1 | `iface_deep` — interface deep-dive | `ssh_iface_deep` | any case with a localized device (i.e. every run) | CRC / input / output error counters, output drops, duplex mismatch (half-duplex), interface resets / carrier transitions / link-status changes, flap or link transition inside the incident window | `link_state_change`, `if_errors`, `if_crc` | `if_errors`, `if_crc` |
| 2 | `bgp_edge` — BGP/edge seam | `ssh_bgp_edge` | seam is edge/ISP/middle-mile: case `owner` ∈ {isp, carrier} OR `top_hypothesis` contains `bgp` / `wan-edge` / `middle-mile` / `peering` / `interconnect` / `dia` | neighbors in Idle/Active/Connect/OpenSent/OpenConfirm, session uptime below incident age (recent reset), established sessions with 0 prefixes (prefix-count collapse), device-reported down-peer counts | `bgp_adjacency_change`, `bgp_state_anomaly`, `routing_adjacency_change` | `bgp_adjacency_change`, `bgp_state_anomaly` |
| 3 | `recent_change` — config-change detector | `ssh_config_change` | case at the **suspected** verdict tier (still hunting a cause) | a configuration change inside or shortly before the incident window (window start − 1 h slack; 24 h lookback when the window is unknown). A hit is a top-tier "possibly because of" signal | `config_change` | `config_change` |

### Planned (from the earlier module design; not yet built)

| Module | Sketch trigger | Sketch content |
|--------|----------------|----------------|
| IGP adjacency | hypothesis names ospf/isis/igp | OSPF/IS-IS neighbor tables, stuck EXSTART/EXCHANGE (MTU), timer/area mismatch indicators |
| Path/latency | path/probe-latency hypotheses | device-side reachability of the far seam end, path MTU indicators |
| QoS/congestion | congestion/utilization hypotheses | policy-map / queue drops per class, shaper/CIR counters |
| DNS/SaaS reach | dns/saas/egress hypotheses | resolver state, DNS server reachability from device |
| Device platform health | device_restart/alarm cases | CPU/memory/environment (fans, PSU), crash/reload reason |
| Tunnel/VPN | ipsec/tunnel hypotheses | IKE SA / tunnel interface state, SA lifetimes vs window |
| NTP/clock sanity | clock_skew evidence present | NTP association state, stratum, offset |

## Per-vendor command table (closed allowlist)

All commands are read-only `show`/`display` verbs, matched **verbatim** by the
runner's defense-in-depth gate; the guard test (`TestVerifyCommandTableReadOnly`)
covers the module table alongside the core one.

| Check | Cisco (IOS/IOS-XE/XR/NX-OS family) | Arista EOS | Juniper Junos | Huawei VRP | Nokia SR OS |
|-------|------------------------------------|------------|---------------|------------|-------------|
| `ssh_iface_deep` | `show interfaces` | `show interfaces` | `show interfaces extensive` | `display interface` | `show port detail` |
| `ssh_bgp_edge` | `show bgp all summary` | `show ip bgp summary vrf all` | `show bgp summary` | `display bgp peer` | `show router bgp summary` |
| `ssh_config_change` | `show running-config` ¹ | `show running-config diffs` ² | `show system commit` | `display configuration commit list` ³ | `show system rollback` |

¹ Only the `Last configuration change at …` / `… last updated at …` header
lines are parsed (IOS/IOS-XE and IOS-XR formats); the config text itself is
never stored — the bounded buffer is parsed in memory and discarded, and the
`observed` field carries only the matched timestamp line. NX-OS prints no such
header → honest *inconclusive* (skipped).
² EOS reads change evidence as the running↔startup diff: any diff hunk ⇒ an
unsaved change is present (decisive); empty output ⇒ configs match (pass).
³ VRP8 commit history; older VRP5 devices error → *inconclusive* (skipped).

Vendor keys are the discovery families (`collectors.vendorFromDescr`): the
single `cisco` family spans IOS-XE/NX-OS/IOS-XR, so each parser accepts all
three output dialects and reports *skipped* where a platform lacks the surface.

## Mined from NetClaw vs authored fresh

| Content | Provenance |
|---------|-----------|
| L1 fault semantics (CRC ⇒ cable/optic/duplex, input errors ⇒ physical corruption, output drops ⇒ congestion, resets/transitions ⇒ flapping, flap-frequency reasoning), uptime-recency thresholds, "counters are cumulative" caveat | NetClaw `pyats-troubleshoot`, `pyats-health-check` |
| BGP diagnosis (summary-table state reading, recent-reset via Up/Down column, checklist framing) | NetClaw `pyats-troubleshoot`, `pyats-routing` |
| Cisco command choices | NetClaw pyats skills |
| Juniper command choices (`show interfaces extensive`, `show bgp summary`, commit history) | NetClaw `pyats-junos-interfaces`, `pyats-junos-routing`, `junos-network` |
| Arista EOS, Huawei VRP, Nokia SR OS command profiles + their parser dialects | **Authored fresh** (NetClaw has no CLI coverage for these; Arista appears only via the CloudVision API) |
| Config-change-history commands (all vendors) | **Authored fresh** (no NetClaw skill covers read-only change-history commands) |
| Module/trigger framework, evidence semantics, window-relative math | Original to this project |

## Evidence semantics (honest by construction)

* **fail** — a decisive signal was found ⇒ the check **corroborates** its
  declared kinds (e.g. a config change inside the window corroborates
  `config_change`).
* **pass** — the surface was checked and is healthy ⇒ the check **refutes**
  its declared kinds (scoring's contradiction path).
* **skipped** — command unsupported, no credential, budget exhausted, or
  unparseable output ⇒ *inconclusive*: claims nothing, emits no signal.
  Parsers never guess.

Cumulative counters (CRC etc.) cannot prove *current* incrementing from one
snapshot; observed text says "(cumulative)" and window-relative indicators
(flap age, short session uptime, change timestamps) carry the recency claim.
Device timestamps are compared as UTC; the +1 h window slack absorbs small
zone/clock drift.

## Tenant isolation & bounds

Unchanged from the core battery: runs exist only inside tenant-keyed run
records (`verifyRunStore`), case lookups go through the tenant-scoped
`corr_current` read (cross-tenant id ⇒ 404), targets resolve only devices the
case's tenant can see, and evidence lands keyed by tenant on
`netops.verification`. Modules add commands to the same one-connection SSH
group, under the same per-check timeout, group bound and run budget; output
stays capped at 256 KiB per command.

## How to add a module

1. Add a check spec in `verifyModuleSpecs()` (id, `Module` name, corroborates/
   refutes drawn from kinds the correlation engine actually uses).
2. Add one command per vendor family to `verifyModuleCommandTable` —
   read-only `show`/`display` only; the guard test enforces the invariants.
3. Extend `verifyModulesFor` with the trigger condition (keep it a pure
   function of `verifyCaseContext`).
4. Write the deterministic parser (dispatch in `parseVerifyModuleOutput`),
   conservative: unparseable ⇒ skipped.
5. Mirror any new evidence kinds in `verification_producer.py`
   `REFUTABLE_KINDS` (closed vocabulary) + its test.
6. Unit tests with realistic canned outputs for every covered vendor
   (`verify_modules_test.go`), including pass, fail and skipped cases.
7. Update this catalog.
