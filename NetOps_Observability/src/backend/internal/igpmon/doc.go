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
// The advanced depth — LSP/LSA database size, area membership, SPF-run counters
// and adjacency/interface timers — is defined for BOTH protocols but collected
// by different transports, and on any given deployment quite possibly by
// neither. It was not collected at all until frontend-wave #11; the series now
// exist on both lanes:
//
//	IS-IS, gNMI, Nokia SR Linux NATIVE (subscriptions srl-isis-db /
//	srl-isis-timers in deployment/docker/gnmic/gnmic.yaml). The four paths were
//	VERIFIED against lab spine1 (SRL 24.10) on 2026-09-02, and the canonical
//	output was proven through gnmic's own processor engine:
//	  device_isis_lsp_count{device,vrf,isis_level}          level statistics/total-lsps
//	  device_isis_spf_runs_total{device,vrf,isis_level}     level statistics/spf-runs
//	  device_isis_area{device,vrf,area} = 1                 instance oper-area-id (info series)
//	  device_isis_adj_hold_seconds{device,vrf,ifName,isis_level,isis_neighbor}
//	                                                        adjacency remaining-holdtime
//
//	OSPF, SNMP, OSPF-MIB (the generic standard profile). DOC_CLAIMED: the OIDs
//	are index-resolved against the vendored MIB, but this deployment has no
//	OSPF-speaking SNMP device, so not one of them has ever returned a row:
//	  device_ospf_lsdb_count{device,area}       ospfAreaLsaCount  1.3.6.1.2.1.14.2.1.7
//	  device_ospf_area{device,area}             ospfAreaStatus    1.3.6.1.2.1.14.2.1.10
//	  device_ospf_spf_runs_total{device,area}   ospfSpfRuns       1.3.6.1.2.1.14.2.1.4
//	  device_ospf_if_hello_seconds{device,index} ospfIfHelloInterval  1.3.6.1.2.1.14.7.1.9
//	  device_ospf_if_dead_seconds{device,index}  ospfIfRtrDeadInterval 1.3.6.1.2.1.14.7.1.10
//
// Two asymmetries are real and are NOT smoothed over:
//
//   - IS-IS hold time is per ADJACENCY and is a COUNTDOWN (seconds until the
//     adjacency expires if no hello arrives), reset by every received hello —
//     not a configured interval. OSPF timers are per INTERFACE and ARE
//     configured intervals, because OSPF-MIB's ospfNbrTable has no hello or
//     dead column at all: a per-neighbour OSPF timer is not collectable over
//     SNMP, full stop.
//   - OSPF counts and SPF runs are scoped by AREA, IS-IS by LEVEL. Each block
//     ships the scope label it used rather than pretending to one vocabulary.
//
// # The honesty contract
//
// Every response carries coverage{events, live_series, lsdb, areas, spf_runs,
// timers}. The four depth flags are SEPARATE because the four probes are
// separate reads that fail independently; one flag for all of them would tell
// an operator that something is missing without telling them what.
//
// A source that is not collected is reported ABSENT (`null` plus a note naming
// the series AND the transport that would carry it), never as a zero and never
// as "healthy": a fabricated 0 down-adjacencies from a protocol nobody is
// watching is exactly the lie an operator would act on, and a fabricated LSDB
// of size 0 reads as "the database is empty", which is worse. A FAILED read and
// an ABSENT series are also kept apart — both end in coverage:false, but only
// one of them is a statement about what this deployment collects.
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
