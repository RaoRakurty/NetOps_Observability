---
id: app-to-db-degradation
title: App-to-DB Tier Degradation
fault_domains: application, east-west, dc, flow, service
signals: app_to_db_latency, flow_retransmission, east_west_anomaly, service_health
keywords: app, database, db, tier, east-west, slow query, connection pool, latency, three-tier, backend
owner: App / Platform (with Network triage)
---

# App-to-DB Tier Degradation

## Symptoms
- Application slow while the WAN/edge is clean.
- East-west (app→DB) latency or retransmissions rising.
- Connection-pool exhaustion or timeouts to the database tier.

## Common fault domains
- DB tier itself (CPU, locks, slow queries, storage).
- East-west network segment between app and DB (loss/congestion).
- Connection-pool / app-tier misconfiguration.

## Correlix evidence to check
- App→DB flow volume, retransmissions, and latency (east-west).
- Interface health on the app↔DB segment.
- Service View health for the app and its DB dependency.
- Whether the WAN/edge path is clean (rules out north-south).

## Supporting evidence
- East-west retransmissions rising while north-south is clean → segment or DB.
- DB-tier resource anomaly coincides with app slowness → DB tier.

## Contradicting evidence
- WAN/edge also degraded → not isolated to the app-DB tier.
- No east-west anomaly and clean DB metrics → suspect app code/dependency, not infra.

## Missing evidence
- DB internal metrics (locks/queries) may not be in Correlix — correlate infra + escalate to DBA.
- Per-query latency not observable from flows alone.

## Recommended owner
App / Platform team (Network triages the east-west segment first).

## Next actions
1. Confirm the WAN/edge is clean (isolate to east-west).
2. Check app→DB flow retransmissions and latency.
3. Check the app↔DB segment interface health.
4. If the segment is clean, escalate to the DB/app owner with evidence.
5. Track recovery via service health.

## Escalation note
App <name> degraded since <start UTC>; WAN clean. East-west app→DB <retransmits/latency>. Segment <clean/degraded>. Routed to <network-segment | DB tier>.

## ITSM note template
App-to-DB degradation for <app> since <start UTC>. North-south clean. East-west <metric>. Owner: <segment / DB tier>. Evidence: <flows/findings>.
