# Telemetry names and trap attribution alerts

The `telemetry-names` group in `src/config/rules-scale-slo.yaml` (warning tier, never
pages) watches what tracker 387 PR 13 could not name. Nothing is lost while either fires:
the flow or the trap is stored and searchable. What is lost is meaning, and for traps the
device binding RCA needs.

Metrics:

- `netops_iface_names_rows{source}`, `netops_iface_names_exporters_uncovered`,
  `netops_iface_names_truncated_total`, `netops_iface_names_failures_total{stage}` on the
  api. The api writes `netops.iface_names` every minute from the SNMP ifIndex bridge
  (`iface_names_export.go`); the flows views join it on each flow row's own tenant,
  exporter and ifIndex.
- `netops_trap_attribution_events{basis,outcome}` on vector-router: which rung of the trap
  receiver's ladder named the trap's device (`mgmt_ip`, `interface_ip`, `sysname`,
  `agent_addr`) or `none`, and the tenant attribution outcome.
- `netops_flow_enrichment_events{...,iface_index}`: whether a flow carried real interface
  indexes or the IPFIX "no interface" sentinels (0, 4294967295). A sentinel is never named.
- `netops_nms_iface_bridge_rows{source,outcome}`, `netops_nms_iface_bridge_failures_total{stage}`,
  `netops_nms_iface_bridge_last_publish_timestamp_seconds` on the api (tracker 387 PR 13a):
  the interface bridge is the SNMP walk's rows merged with each controller's interface
  list (`if_bridge.go`, `internal/ifbridge`). `bridged` is what stands in the address and
  ifIndex maps per source; `agreed`/`conflict_won`/`conflict_lost` compare the two sources
  for one device (newer reading wins); for the NMS source, `device_unresolved`,
  `device_ambiguous`, `internal_vpn`, `unidentifying_address`, `truncated` and `stale` say why
  a controller's record reached no row.
- `netops_inventory_facts{fact,source,state}`: how model, site and role were settled for each
  device in the last registry export (`inventory_facts.go`): `manual`, `inventory` or `nms`
  set it, nothing stated it (`none`/`blank`), or two sources disagreed (`conflict`, left
  blank).

## FlowExporterWithoutInterfaceNames

An exporter has sent flows for 2 hours and no interface of it has a name, so the flows
views show its ports as bare ifIndex numbers.

1. Find it: `SELECT DISTINCT tenant_id, sampler_address FROM netops.flows WHERE ts > now() - INTERVAL 1 HOUR AND (tenant_id, sampler_address) NOT IN (SELECT tenant_id, exporter_addr FROM netops.iface_names) SETTINGS tenant_scope='__all__'`.
2. Is the address a device's inventory (management) address? Names are keyed on it. An
   exporter sourcing flows from another interface is not named today.
3. Does the device answer the IF-MIB walk? Check `entity_resolver.json` (or the api log
   line `entity-resolver-enrichment: exported N device(s), N iface-ip(s), N ifindex(es)`)
   for its ifindex rows. A device that answers no walk (on the lab: cedge-81, vedge-100)
   has none from SNMP; its controller's interface list fills them when the controller's
   device resolves to it. See NMSInterfaceBridgeEmpty below for why it may not.
4. `netops_iface_names_failures_total{stage="read"}` rising means the bridge itself is
   unread; `stage="write"` means ClickHouse refused the rows.

## TrapSourceUnattributedRatioHigh

More than half the traps of the last 30 minutes reached no device (`basis="none"`).

The receiver tries, in order: the source address as a device's management address; the
source address as an interface address that exactly one device reports (internal
loopbacks of VPN 65528 and above, and any address two devices share, are never used);
the trap's sysName; the v1 agent-addr. Every rung must still prove the device's
credential (the community for v1/v2c, a verified HMAC for v3). The tenant is always the
device's own, never derived from the address.

1. Group the unattributed traps by `host` on the Logs page (signal: SNMP traps,
   `attribution_basis:none`). One address carrying most of them is the usual shape.
2. If that address is an interface of a known device, where do its interface addresses
   come from? The SNMP walk (ipAddrTable) and the controller's interface list. A
   controller's rows land only on a device the integration's OWN owner owns, and the
   receiver attributes only to a device Correlix polls (it must prove that device's
   community). An integration owned by a tenant cannot name a platform-owned SNMP device:
   align the owners (assign the devices to the integration's tenant, or own the
   integration at the platform).
3. If the device is known by that address, check the community: a mismatch drops the
   identity on purpose (`guardTrapCommunity`).

## NMSInterfaceBridgeEmpty

The controller answered its per-device interface lists for 30 minutes (the
`interface_realtime` stream polled `ok`), and not one row of them reached the interface
bridge. Devices known only through the controller keep bare ifIndex numbers on flows and
traps, and a trap sent from one of their interface addresses names no device.

1. Read `netops_nms_iface_bridge_rows{source="nms"}` by outcome.
2. `device_unresolved`: the controller's devices match no inventory device of the
   integration's owner. Resolution is owner-strict (system-ip label, address, host-name,
   serial; never an address alone): an integration owned by tenant X names only tenant X's
   devices. The usual cause is an integration owned by a tenant while the SNMP-discovered
   devices are platform-owned, or the reverse. Align the owners; nothing should be bridged
   across them.
3. `device_ambiguous`: a controller key matched more than one device (two devices with one
   host-name). Fix the duplicate in inventory.
4. `internal_vpn` / `unidentifying_address` are expected (VPN 65528 and up, loopback,
   link-local) and never bridge.
5. `netops_nms_iface_bridge_failures_total{stage="publish"}` rising means the key-value
   store refused the rows; `stage="read"` that a bridge half could not be read.

## AS numbers: the iptoasn dataset

Cisco SD-WAN cflowd (and many exporters) sends no BGP AS elements, so `src_as`/`dst_as`
read 0. The flows API fills them from the iptoasn.com ip2asn dataset (PDDL-1.0) through the
`netops.ip_asn` dictionary, and labels each AS row `as_basis`: `exporter` (the exporter's
own), `dataset`, or absent (the row is left out; coverage counts it). Private and unrouted
space never gets an AS.

The dataset is fetched by the operator, never shipped:

    sudo python3 scripts/asn-prepare.py --fetch                       # records the sha256 it used
    sudo python3 scripts/asn-prepare.py --input ip2asn-combined.tsv.gz --sha256 <reviewed digest>

`sudo` because `data/clickhouse/user_files` belongs to the ClickHouse container user. The
dictionary reloads within two hours. `netops_flow_dataset_status{dataset="asn"}` says where it
stands: `loaded`, `loaded_empty`, `failed` (no file yet, or a bad one), `not_loaded` (never
asked for), `absent` (the dictionary does not exist), `unknown` (unread). The same metric
watches `geoip_country` (`scripts/geoip-prepare.py`), which read `failed` on the lab for its
whole life with nobody told. Until a dataset loads, the panels read exactly as before.
