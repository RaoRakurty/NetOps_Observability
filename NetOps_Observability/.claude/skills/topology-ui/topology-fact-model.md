# Topology Fact Model

## Rule

Raw discovery data becomes facts first.

Facts are resolved into topology views.

React components never read raw discovery rows directly.

## Fact examples

- LLDP neighbor fact
- CDP neighbor fact
- BGP-LS adjacency fact
- IS-IS adjacency fact
- OSPF adjacency fact
- SNMP interface fact
- flow dependency fact
- cloud relationship fact
- NetBox intended link fact
- manual override fact

## Confidence examples

- bidirectional LLDP: 0.98
- source-of-truth link: 0.95
- BGP-LS adjacency: 0.90
- one-way LLDP: 0.85
- one-way CDP: 0.82
- flow-only dependency: 0.65
- hostname fuzzy match: 0.55
- unresolved remote chassis: 0.35

## Required fields

Every fact should have:
- fact_id
- source
- subject
- predicate
- object
- observed_at
- expires_at
- confidence
- raw_ref
