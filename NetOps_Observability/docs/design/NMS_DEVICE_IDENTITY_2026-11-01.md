# Per-tenant telemetry streams and device identity — plan of record (2026-11-01)

Tracker 371 and 370. Status: **DESIGN — principle decided by the owner 2026-11-01: the truest
multitenancy, built the hard way (§2). Lab channel set-up to confirm (§8).**
NMS-first contract: `NMS_FIRST_PLAN_2026-10-24.md`. Engine stages per
`src/correlation/CLAUDE.md`.

## 1. What is wrong today, measured on the lab (vManage 20.6.1)

**Tenant is decided by matching the sender against one global identity map.**
The vector router looks the sender address up in `device_tenant.csv`, one file
for all tenants, built from every tenant's devices (`buildEnrichmentRows`,
`telemetry_enrichment.go`). An address claimed by two tenants is dropped
(#20 Phase 1, 2026-06-03), and the read side claims untagged rows by device
name/address (`visibleDeviceKeys`/`visibleDeviceAddrs`, `tenancy.go`). Every
tenant sends to the same syslog / trap / flow listener, and ingest tokens are
per lane, not per tenant. Consequences:

1. Overlapping address space between tenants — normal in the real world — cannot
   be attributed: the packet carries nothing that names the tenant.
2. A dropped identity lands untagged (platform-owned): both tenants silently lose
   that telemetry.
3. The read-side claim lets a tenant read untagged rows whose sender name/address
   collides with one of its own devices (tracker 370: RETAIL reads the Provider's
   13,348 syslog lines on the lab).
4. Controller-only devices are excluded from the map altogether
   (`d.Source == devmon.SourceController`), so an NMS-only tenant's traps, flows
   and syslog are never its own (tracker 371).

**Inside one tenant, telemetry does not bind to the controller's device.** A
controller-managed edge is known by its overlay system-IP (`cEDGE-40` →
10.255.255.40). It sends syslog, traps and IPFIX from the address its
configuration names — on the lab a loopback in service VPN 200:

| Device | Configured source (`/dataservice/device/config`) | Collector |
|---|---|---|
| cEDGE-40 (IOS-XE SD-WAN) | `logging source-interface loopback200 vrf 200`; `snmp-server host 192.168.172.1 vrf 200` | 192.168.172.1 |
| vEdge-20 (Viptela OS) | `logging … source-interface loopback200`; `trap target vpn 200 192.168.172.1 162 … source-interface loopback200` | 192.168.172.1 |
| all edges (cflowd policy `/template/policy/definition/cflowd/{id}`) | `collectors[{vpn 200, 192.168.172.1:2055, sourceInterface loopback200}]` | 192.168.172.1:2055 |

`/dataservice/device/interface?deviceId=<system-ip>` resolves `loopback200` per
device (cEDGE-40 → 192.168.222.107). Internal VPNs 65528/65530 reuse the same
addresses on different devices and are never identity. Viptela vEdges stamp the
system-IP into the IPFIX Observation Domain ID (vEdge-20 → 184549140 =
10.255.255.20); IOS-XE sends 512. Further gaps: the entity resolver exports the
controller device's system-IP as its management address; trap attribution only
matches SNMP collector targets; **syslog-ng forwards without the sender address**
(every syslog doc's `source_ip` is syslog-ng's own container, 172.18.0.12); SNMP
rows carry no chassis serial.

## 2. The principle (owner, 2026-11-01)

> In true multitenancy the tenant is decided by the stream the data arrives on.
> Same device, same hostname, same IP, same chassis serial in two tenants does
> not matter — the data arrives in two tenants' streams.

So:

- **Tenant = channel.** Every telemetry channel belongs to exactly one owner and
  is stamped with that owner where it enters ingest — never derived from what the
  data claims about itself.
- **Identity is resolved only inside a tenant.** `(tenant, sender) → that
  tenant's device`. Nothing is ever compared across tenants; overlap between
  tenants is irrelevant by construction.
- **The same physical device in two tenants is two devices with two streams.**
  Each tenant's copy is independent and complete; each tenant's view shows the
  device once and its telemetry once. Storage holds one copy per tenant on
  purpose.
- **A tenant reads only rows stamped with its own tenant.** The untagged
  read-side claim goes away (closes tracker 370 by removal, not by an
  ambiguity rule).
- **The shared listener is the Provider's channel.** What arrives on the default
  ports belongs to the platform realm — the rule #112 already applies to untagged
  data.

## 3. Channels — how a tenant's stream is delivered

| Option | What makes it the tenant's | Fits |
|---|---|---|
| **C1 per-tenant listener** (ports or VIP/hostname) | the destination the device sends to; the listener stamps the tenant | any device; the controller template sets destination + port (vManage: logging server, trap target and cflowd collector each take a port) |
| **C2 customer-site collector** | mutually-authenticated TLS with a per-tenant credential; the collector receives locally and forwards | overlap, NAT, firewalls, zero trust — authenticated channel, not UDP source (industry pattern: Kentik kproxy, LogicMonitor / ScienceLogic collectors) |
| **C3 per-tenant tunnel / VRF termination** | the address the traffic arrives on | MSP fabrics, SD-WAN service-VPN collectors |
| **C4 controller push** | the integration's credential (already per tenant) | vManage alarm webhook (tracker 358a), streaming exports |
| **C0 shared listener** (default ports) | — | the Provider's own stream, and nothing else: no address-based attribution to a tenant, no onboarding bridge (owner: "truest multitenancy") |

Zero-trust note: a UDP source address is routing, not authentication. C1/C3
stamp the tenant from the destination, so a stranger who learns a tenant's port
can inject into that tenant's stream (not read it); per-listener source-prefix
allowlists bound that, and C2 removes it.

## 4. Inside a tenant: binding telemetry to the right device

Per tenant, a device-identity resolver maps a sender to one of **that tenant's**
devices, so a trap from 192.168.222.107 lands on RETAIL's `cEDGE-40` — the same
entity as the controller's alarms and BFD evidence.

| Tier | Alias source |
|---|---|
| A | configured logging / trap / cflowd source-interface resolved via the device's interface list, per protocol (controller data) |
| B | in-band: IPFIX ODID == system-IP (Viptela); syslog HOSTNAME == device name; authenticated trap (community / v3 HMAC) |
| C | non-internal interface addresses: management, service VPNs, system-IP (exclude VPN ≥ 65528, link-local, VIPs) |
| D | NAT public IP — composite only |
| E | tenant-declared alias (UI) |
| F | the tenant's own SNMP-discovered twin (same-tenant merge on serial / system-IP / tier-A address) |

Within a tenant, an alias matching two devices resolves the tenant but not the
entity (abstain), and is surfaced to the tenant's admin. Across tenants nothing
is compared.

Consumers, all generated from the per-tenant resolver: the router's
`(channel, sender) → device` lookup (replaces the global `device_tenant.csv`
for tenant attribution), `entity_resolver.json` (tenant-scoped aliases: engine
stage [1] binds trap/syslog/flow to the controller device id), the NMS inventory
join (`BuildInventoryIndex`), and the trap receiver (controller devices become
resolvable, M4 gate kept).

**RCA outcome:** an NMS-only tenant's WAN/tunnel incident carries the edge's own
linkDown traps, syslog and flow collapse, grounded at rank 1 to the controller
alarm entity (stage [4]); device-direct witnesses are independent of
`via_controller`, so CONFIRMED is reachable under the existing verdict gate
(stage [7]).

## 5. The lab under this model

The lab keeps the same eight edges in two owners on purpose:

- **Provider** — SNMP discovery + the edges' current destinations
  (192.168.172.1, default ports) = the Provider's channel (C0).
- **RETAIL-WALMART** — vManage + a **second destination on each edge** to
  RETAIL's channel (C1: e.g. syslog 1514, traps 1162, cflowd 2056 on
  192.168.172.1), set once in the vManage templates / cflowd policy.

Each tenant then sees the eight edges once and their telemetry once.

## 6. Multi-vendor

Channels are vendor-neutral (every device that can send syslog/traps/flows can
send them to a port/VIP). Per-tenant alias sources per connector: vmanage
(lab-verified, §1) · catalyst_center (`managementIpAddress`, interface list,
config — uncaptured) · meraki (`lanIp`; NetFlow source = highest VLAN LAN IP in
the VPN) · versa (LEF arrives via an Analytics relay — payload identity) · ndfc /
prime / catalyst_9800 (`ipAddress`) · Juniper, Nokia, Arista, SONiC, generic (SNMP
ipAddrTable, tenant declarations, config-source parsing; Junos ODID configurable).

## 7. Phases (one PR each; ★ = high-risk: full gate + pgintegration + §3a test)

- **P0** fixtures: the §1 controller captures for a vEdge and a cEdge.
- **P0.5** syslog keeps its sender address (syslog-ng carries `${SOURCEIP}`;
  Vector maps it; VRL harness; install-boot).
- **P1★** channel model: `telemetry_channels` (owner, protocol, port/VIP,
  allowed source prefixes) in PG with FORCE-RLS; admin API + §3a isolation test;
  the router stamps `tenant_id` from the channel; default channel = Provider.
- **P2★** C1 listeners: Vector/syslog-ng/goflow2/trap receiver listen on the
  channel ports, carry the channel id, router stamps the owner; Kafka keyed by
  tenant; install-boot leg; promtool rule for an unknown or silent channel.
- **P3★** tenant reads only its own: remove the untagged read-side claim
  (`oslog.TenantFilter`, `flows.go`, secapi, parsercov, AI tools) and the global
  address→tenant attribution (`device_tenant.csv` as a tenant source) entirely.
  Cross-org tests per store, including two tenants with identical device names,
  addresses and serials whose streams never mix. Existing untagged data stays
  the Provider's.
- **P4** per-tenant identity resolver + vManage alias collection (tier A/B/C
  parsing, VPN-655xx exclusion, SNMP serial read fixed) feeding the router's
  device binding, entity_resolver, inventory join, trap receiver.
- **P5** in-band flow identity: `observation_domain_id` on `netops.flows`,
  composite lookup within the tenant.
- **P6** engine stage [1] canonicalization behind a byte-identical-when-OFF flag,
  `ENGINE_SEMVER` bump, replay.
- **P7** UI: channels (per tenant: endpoints to configure on devices, last seen,
  rates), device Identities tab, unattributed senders on the Provider channel.
- **P8** C4 vManage webhook (358a) · **P9** C2 site collector · **P10+** other
  connectors' alias sources (T8–T11).

## 8. Decided / open

- **Decided (owner, 2026-11-01):** the truest multitenancy, even where a use case
  is unusual. A tenant receives telemetry only through its own channel; the shared
  listener is the Provider's; nothing on it is attributed to a tenant by address,
  name or serial — not even during transition.
- **Open:** RETAIL's second destination on the lab edges (vManage templates +
  cflowd policy) — the owner sets it, or Claude does with explicit approval.
