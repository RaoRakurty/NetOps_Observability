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

## FlowExporterWithoutInterfaceNames

An exporter has sent flows for 2 hours and no interface of it has a name, so the flows
views show its ports as bare ifIndex numbers.

1. Find it: `SELECT DISTINCT tenant_id, sampler_address FROM netops.flows WHERE ts > now() - INTERVAL 1 HOUR AND (tenant_id, sampler_address) NOT IN (SELECT tenant_id, exporter_addr FROM netops.iface_names) SETTINGS tenant_scope='__all__'`.
2. Is the address a device's inventory (management) address? Names are keyed on it. An
   exporter sourcing flows from another interface is not named today.
3. Does the device answer the IF-MIB walk? Check `entity_resolver.json` (or the api log
   line `entity-resolver-enrichment: exported N device(s), N iface-ip(s), N ifindex(es)`)
   for its ifindex rows. A device that answers no walk (on the lab: cedge-81, vedge-100)
   has none. Tracker 387 PR 13a adds the controller (vManage) interface list as a second
   source.
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
2. If that address is an interface of a known device, does the device answer the SNMP
   walk? Its interface addresses come from it (ipAddrTable). Until it does, or until
   tracker 387 PR 13a brings the controller's interface addresses, it cannot attribute.
3. If the device is known by that address, check the community: a mismatch drops the
   identity on purpose (`guardTrapCommunity`).

## TrapTitleFallbackRatioRising

More than a quarter of the traps of the last 30 minutes have no readable title, and
that share is more than twice what it was over the six hours before
(`netops_trap_semantics_events{title="fallback"}`). They are stored and searchable; the
Logs page shows them by MIB name, and their peer, metrics and guidance may be missing.

A title comes from the trap packs (`src/backend/collectors/mibs/packs/*.json`,
`title_templates` and `titles`): a notification with no `titles` row, or one whose
templates all need a field the trap did not carry, falls back to the old summary.

1. Group the untitled traps on the Logs page (signal: SNMP traps,
   `title_basis:fallback`) by `trap_name` and `family`. One notification carrying most
   of them is the usual shape.
2. A notification no pack words: add a `titles` row naming a template (or a new
   template) in the vendor's pack. No code change; `go test ./collectors/` checks the
   OID, the name and the template syntax.
3. A notification that IS worded: compare a stored trap with the template's fields. A
   peer that stopped decoding shows as `bgp.peer_basis:unparsed` (the same counter's
   `peer` label): check the MIB index's INDEX clause for that table, or a vendor form a
   pack `tables` row should declare.

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
