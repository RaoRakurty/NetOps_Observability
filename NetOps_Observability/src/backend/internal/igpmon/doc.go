// Package igpmon serves READ-ONLY OSPF and IS-IS monitoring over telemetry the
// platform ALREADY collects. It collects nothing itself and it invents nothing.
//
// # What exists today (the inventory this package is built on)
//
// Events (both protocols, ALWAYS available):
//
//	netops.corr_signals / corr_signals_archive, kinds `ospf_adjacency_change`
//	and `isis_adjacency_change`, produced by the syslog rules
//	syslog.ospf.adjacency_change (%OSPF-5-ADJCHG) / syslog.isis.adjacency_change
//	(isisAdjacencyChange, CLNS) and their trap twins trap.ospf.adjacency_change
//	(OSPF-TRAP-MIB ospfNbrStateChange) / trap.isis.adjacency_change (ISIS-MIB
//	isisAdjacencyChange). entity_type=device, entity_id=the device, and
//	attrs.{peer,state,tag} carry the neighbour and the up/down verdict.
//
// Live series (IS-IS only on the validated lab):
//
//	device_isis_adj_state — gNMI, Nokia SR Linux native isis adjacency state,
//	on-change, labels {device, ifName, isis_level, isis_neighbor, vrf},
//	ISIS-MIB numerics 1 down / 2 init / 3 up / 4 failed.
//
//	device_ospf_nbr_state (OSPF-MIB ospfNbrState, index label `neighbor`) and
//	device_ospf_if_state (ospfIfState) are DEFINED in the SNMP standard profile
//	but are SNMP-owned and only materialize on a device that answers
//	ospfNbrTable. The OpenConfig ospfv2 gNMI row in the telemetry catalog is
//	`doc_claimed`, never captured. So on a deployment with no OSPF-speaking
//	SNMP device there is NO live OSPF series at all.
//
// Not collected anywhere, by either transport:
//
//	LSDB / LSP database counts, OSPF area membership, IS-IS area addresses,
//	SPF-run counters, per-adjacency hold/dead timers.
//
// # The honesty contract
//
// Every response carries coverage{events, live_series, lsdb}. A source that is
// not collected is reported ABSENT (`null` plus a note naming why), never as a
// zero and never as "healthy": a fabricated 0 down-adjacencies from a protocol
// nobody is watching is exactly the lie an operator would act on.
//
// # Isolation (CLAUDE.md §3a)
//
//   - the ClickHouse read runs at the caller's chTenantScope, which is what the
//     tenant_iso FORCE row policies on corr_signals/corr_signals_archive
//     enforce on, and a scope of "" / "__none__" reads NOTHING (fail closed);
//   - every VictoriaMetrics read carries the caller's device boundary as
//     `extra_filters[]` (metricsScopeFilters), injected server-side by VM into
//     every series selector — a scoped principal whose filters are missing gets
//     NO live series rather than a fleet-wide read;
//   - ?device= is resolved through the principal-scoped inventory: a device of
//     another tenant, or one that does not exist, is a 404 — identical answers,
//     so existence is never revealed;
//   - the tenant is NEVER read from a query string or a body.
package igpmon
