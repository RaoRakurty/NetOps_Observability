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
