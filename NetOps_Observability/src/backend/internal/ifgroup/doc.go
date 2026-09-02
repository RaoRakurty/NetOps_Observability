// Package ifgroup serves ONE read: a device's interfaces grouped by the routing
// instance they belong to, in the vendor's own dialect (frontend-wave item 4).
//
// ── WHAT IS ACTUALLY COLLECTED (verified 2026-09-02, not assumed) ───────────
//
// The canonical interface families are declared in telemetry-catalog/
// normalization.yaml with the label set
//
//	device_if_oper_status  labels: [device, vendor, ifName, transport]
//	device_if_admin_status labels: [device, vendor, ifName, transport]
//
// There is NO `vrf` label on any interface family, on either transport:
//
//   - SNMP (the OWNER of every device_if_* family — normalization.yaml
//     `owner.transport: snmp`) emits {device, vendor, index, ifName, ifAlias}
//     from IF-MIB. IF-MIB has no VRF column; a VRF-aware SNMP read needs
//     per-VRF contexts (v3) or MPLS-VPN-MIB, and this platform polls neither.
//
//   - gNMI DOES carry the concept, but only under /network-instances: the
//     gnmic `canon-tags` processor renames network-instance_name → vrf, and
//     the only subscriptions under that tree are BGP and IS-IS. The interface
//     subscriptions (`oc-interfaces`, `srl-interfaces`) sit at /interfaces and
//     /interface, which carry no network-instance key — gnmic.yaml states the
//     resulting label set outright: "{device, vendor, ifName, transport} for
//     interfaces/resources, + {peer, vrf} for BGP".
//
// So on today's deployment an interface's VRF membership is NOT COLLECTED, and
// this module says exactly that. It never invents a "default" group: "every
// interface is in the default VRF" is a claim about the device, and we have no
// evidence for it. An operator who reads "default" would design around it.
//
// ── WHY THE MODULE STILL QUERIES FOR IT ─────────────────────────────────────
//
// coverage.vrf_labels is PROBED at request time (does any returned interface
// series actually carry a non-empty `vrf` label?), never hardcoded false. The
// day a deployment widens its gNMI subscriptions to
// /network-instances/network-instance[name=*]/interfaces/interface — or points
// at a collector that binds interfaces to instances — the grouping lights up by
// itself, with no code change and, critically, with no window in which the UI
// shows a fabricated grouping. Same discipline as igpmon's LSDB probe.
//
// The routing instances the device is KNOWN to have are still reported, read
// from the one lane that does carry them (the BGP control-plane series' `vrf`
// label). They are listed as instances that exist, explicitly WITHOUT interface
// membership — an honest partial answer beats a confident wrong one.
//
// ── DIALECT ─────────────────────────────────────────────────────────────────
//
// The word in every heading is the DEVICE's word: Cisco "VRF", Juniper
// "routing-instance", Nokia "VPRN", Huawei "VPN instance" — resolved through
// the injected VRFTerm (internal/netconcepts over the vendor-profile registry),
// which also reports whether any profile actually claims the vendor, so an
// unrecognized vendor renders the industry-majority default without the
// response claiming the device was identified.
//
// ── ISOLATION (CLAUDE.md §3a) ───────────────────────────────────────────────
//
// The module holds no ambient authority: it reaches the inventory and the
// metric store only through Deps. The device is resolved through the
// principal-scoped inventory FIRST (a foreign id and an absent id answer the
// SAME 404, so the subtree is not an existence oracle), and EVERY metrics read
// carries the caller's device boundary as VictoriaMetrics `extra_filters[]` —
// the /api/metrics/query rule verbatim. A scoped principal with no boundary is
// refused the read rather than served the fleet.
package ifgroup
