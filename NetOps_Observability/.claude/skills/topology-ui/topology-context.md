# Topology Context

## North star

Correlix topology is an operating canvas for NOC troubleshooting, path analysis, RCA, and future digital twin workflows.

## Source types

Supported topology sources:
- LLDP
- CDP
- SNMP
- BGP-LS
- IS-IS LSDB
- OSPF LSDB
- NetFlow/IPFIX
- syslog
- metrics
- cloud APIs
- Kubernetes APIs
- NetBox/Nautobot
- manual links

## Map workflows

Phase 1 workflows:
- Explore
- Investigate
- Path Trace

Future workflows:
- Change Review
- Capacity
- Dependency
- Executive / Geo

## Overlay types

- health
- utilization
- interface_errors
- routing_changes
- config_drift
- syslog
- flow
- rca_evidence
- golden_path_delta
- historical_diff

## Evidence principle

Every edge must answer:
- why does this link exist?
- which source proved it?
- how confident are we?
- when was it last seen?
- what changed?
