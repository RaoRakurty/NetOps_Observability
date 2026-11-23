// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// confirmAdvice.ts — the "What would confirm it" line, named for the protocol
// the case is actually about (owner, 2026-11-23, ticket P-5B357F: an OSPF
// adjacency flap was told to "add peer-side BGP/routing state"). One rule: the
// independent witness we ask for is the SAME protocol seen from the other end
// (or from the path), never a protocol the evidence never mentioned.
//
// Presentation only: the engine's verdict, tiers and evidence gaps are
// untouched; this picks the words for the gap the NOC is asked to close.

export type ConfirmProtocol =
  | "ospf" | "isis" | "bgp" | "ldp" | "rsvp" | "bfd" | "eigrp"
  | "omp" | "control" | "stp" | "fhrp" | "lacp" | "link" | "routing" | "none";

// Ordered: the first match wins, so a specific protocol beats the generic
// "adjacency"/"routing" words that ride along with it.
const RULES: Array<[ConfirmProtocol, RegExp]> = [
  ["ospf", /\bospf|ospfv3|ospf_/i],
  ["isis", /is-?is\b|isis/i],
  ["bgp", /\bbgp|bgp_/i],
  ["ldp", /\bldp\b|ldp_|mpls/i],
  ["rsvp", /rsvp|\bte[-_ ]tunnel/i],
  ["bfd", /\bbfd|bfd_/i],
  ["eigrp", /eigrp/i],
  ["omp", /\bomp\b|omp_/i],
  ["control", /control[-_ ]connection|controller_control|vsmart|vbond|dtls/i],
  ["stp", /\bstp\b|stp_|spanning[-_ ]tree|topology[-_ ]change/i],
  ["fhrp", /fhrp|hsrp|vrrp|glbp/i],
  ["lacp", /lacp|port[-_ ]channel|bundle[-_ ]member|\blag\b/i],
  ["link", /link[-_ ]state|link_down|link_up|if_oper|interface[-_ ](down|flap)|lldp|transceiver|optic/i],
  ["routing", /adjacency|route_|_route|routing|peer/i],
];

/** The protocol a case is about, read from its names (most specific first). */
export function confirmProtocol(...names: Array<string | undefined | null>): ConfirmProtocol {
  for (const n of names) {
    const s = (n ?? "").trim();
    if (!s) continue;
    for (const [p, rx] of RULES) if (rx.test(s)) return p;
  }
  return "none";
}

// What an independent witness of each protocol looks like. Each sentence names
// the far end of the same protocol first, then the path-level witnesses that are
// independent of the device that reported it.
const PATH_TAIL = "traffic-flow loss across that link, or an active check through it from an independent vantage";
const ADVICE: Record<Exclude<ConfirmProtocol, "none">, string> = {
  ospf: `Add the OSPF neighbor state from the peer router (its side of the adjacency), interface errors or a flap on the adjacency link, ${PATH_TAIL}.`,
  isis: `Add the IS-IS adjacency state from the peer router (its side of the adjacency), interface errors or a flap on the adjacency link, ${PATH_TAIL}.`,
  bgp: "Add the BGP session state from the peer (its side of the session), the same prefixes withdrawn as seen from another router or route collector, traffic-flow loss toward those prefixes, or an active check from an independent vantage.",
  ldp: `Add the LDP session state from the peer router, an MPLS LSP ping or traceroute over the affected path, interface errors on the link, ${PATH_TAIL.replace("that link", "the LSP")}.`,
  rsvp: "Add the RSVP-TE tunnel state from the head end and tail end, an MPLS LSP ping over the tunnel, traffic-flow loss on the tunnel, or an active check through it from an independent vantage.",
  bfd: `Add the BFD session state from the peer, interface errors or drops on the path BFD monitors, ${PATH_TAIL}.`,
  eigrp: `Add the EIGRP neighbor state from the peer router, interface errors or a flap on the neighbor link, ${PATH_TAIL}.`,
  omp: "Add the OMP peering state as the controller (vSmart) sees it, the same routes withdrawn at another edge, traffic-flow loss on the overlay, or an active check across the overlay from an independent vantage.",
  control: "Add the controller's view of the same control connection (vSmart/vBond session state), the same loss reported by another edge, traffic-flow loss on the overlay, or an active check from an independent vantage.",
  stp: "Add topology-change notices from the neighbouring switches, the root bridge's view of the change, MAC-table flushes or a port state change on the peer, or traffic-flow loss in the affected VLAN.",
  fhrp: "Add the peer gateway's HSRP/VRRP state for the same group, interface state on the gateway-facing links, traffic-flow loss through the gateway, or an active check to the virtual gateway address from an independent vantage.",
  lacp: `Add the LACP/bundle state from the partner device, interface errors on the member links, ${PATH_TAIL.replace("that link", "the bundle")}.`,
  link: `Add the far-end port's link state or errors (or the LLDP neighbor dropping), interface counters on both ends, ${PATH_TAIL}.`,
  routing: `Add the routing state from the peer router (its side of the adjacency), interface errors or a flap on the link toward it, ${PATH_TAIL}.`,
};

const DEVICE_ONLY = "Add an independent view of the same device: interface errors or drops on its links, traffic-flow loss through it, downstream service impact, or an active check through it from an independent vantage.";
const GENERIC = "Add a second, independent source for the same fault: interface errors or drops, traffic-flow loss, downstream service impact, or an active check from an independent vantage.";

/** The "What would confirm it" sentence for a case about `protocol`. */
export function confirmAdvice(protocol: ConfirmProtocol, hasDevice: boolean): string {
  if (protocol !== "none") return ADVICE[protocol];
  return hasDevice ? DEVICE_ONLY : GENERIC;
}
