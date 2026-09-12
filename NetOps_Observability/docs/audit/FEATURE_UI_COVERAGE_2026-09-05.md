# Feature → UI coverage audit — 2026-09-05

> Owner, 2026-09-05: *"I feel like we are building features but UI is missing —
> in that case we are missing all the work we have done. Please ensure."*

The owner's instinct is correct, and this is the measurement. **34 public API
route families** are registered by the backend and referenced by **no frontend
source file**. A further **33 API client helpers** exist in `services/api.ts`
wired to real routes but are **never called by any page** — a second, quieter
class of the same failure, invisible to a route-level scan.

Nine of the 34 route families are correctly headless (webhooks, nginx
`auth_request`, signed download links, service-to-service). Two are false
positives from a templated client path. **The remaining 23 are debt: shipped
backend capability that no user can reach.**

Method, and how to keep it true, are at the bottom. The guard is
`tests/test_feature_ui_coverage.py` + `docs/audit/headless-routes.yaml`.

---

## Summary

| Measure | Count |
|---|---|
| Public API route families (`/api/<a>/<b>`, excluding `/api/internal/*`) | 241 |
| Registered backend route patterns (main.go ∪ openapi.go, public) | 361 |
| Frontend `/api/…` literals, distinct (non-test sources) | 288 |
| Families **referenced** by the frontend | 207 |
| Families with **no** frontend reference | 34 |
| — of those, **headless-by-design** | 9 |
| — of those, **reached via a templated path** (false positive) | 2 |
| — of those, **MISSING UI** (debt, incl. `/api/troubleshoot/tac/knowledge`) | **23** |
| `services/api.ts` helpers never called by any page | 33 |
| Frontend literals pointing at a route the backend does not serve | **0** |

Verdict tally across the 104 product features inventoried below (counted from
the table itself, not estimated):

| Verdict | Features |
|---|---|
| `exposed` — page + nav entry | 60 |
| `partial` — data reachable only inside another page, read-only, or no controls | 18 |
| **`MISSING UI`** — backend capability with no user surface | **16** |
| `headless-by-design` | 10 |

The 16 MISSING-UI *features* span the 23 MISSING-UI *route families* plus the
MFA-enrolment, policy-document and service-catalog gaps that a route-level scan
alone would not have caught.

Two reverse checks are clean: **no page calls a route that does not exist**, and
**no page component under `pages/` is orphaned** — all 96 resolve through
`nav.tsx` (the four that looked unreferenced are lazy-imported by path:
`ExposureStories`, `ThreatDetectionView`, `SavedViews`, `Placeholders`).

---

## The coverage table

Nav paths are `Section → Leaf` from `src/frontend/src/nav.tsx`. Docs pages are
under `docs-portal/docs/`.

### Discovery, inventory and topology

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Device inventory + CRUD | `/api/devices*`, `discovery.go` | Infrastructure → Devices; `DeviceDetailPage.tsx` | `infrastructure/devices.md` | exposed | — |
| SNMP subnet discovery | `ENABLE_SNMP_DISCOVERY`, `/api/discovery/{config,refresh}` | Infrastructure → Discovery & NMS | `onboard-devices/snmp-discovery.md` | exposed | — |
| SNMP profiles + credentials | `/api/snmp/{profiles,credentials,options}` | Administration → SNMP Profiles | `onboard-devices/snmp-profiles.md` | exposed | `deleteSnmpProfile` helper unused — no delete control |
| Vendor detection | `ENABLE_VENDOR_DETECTION`, `collectors/vendor.go` | device attributes only | `onboard-devices/supported-devices.md` | partial | no coverage/failure view |
| LLDP / CDP / BGP-LS topology | `ENABLE_{LLDP,CDP,BGPLS}_DISCOVERY`, `/api/topology/*` | Investigate → Topology; `DeviceNeighbors.tsx` | `infrastructure/topology-canvas.md` | exposed | — |
| Tunnel discovery | `ENABLE_TUNNEL_DISCOVERY`, `/api/tunnels` | Investigate → Tunnels | `infrastructure/paths-and-tunnels.md` | exposed | — |
| Sites / locations / geomap | `/api/sites`, `/api/geomap`, `/api/devices/{id}/{site,location}` | Infrastructure → Sites (Map · Manage · Locations) | `infrastructure/geomap.md` | exposed | `deviceLocation`/`deviceSite` helpers unused |
| Regions | `/api/regions`, `region_router.go` | Platform → Regions | `administration/regions.md` | exposed | — |
| Source-of-truth import (NetBox) | `/api/sot/import`, `/api/automation/netbox` | Infrastructure → Source of Truth (platformOnly) | `automation/import-and-sync.md` | exposed | — |
| Seams (ownership handoffs) | `/api/seams`, `ENABLE_SEAM_BOOTSTRAP` | read inside Security Overview / RCA | `getting-started/concepts.md` | partial | **`/api/seams/groups` MISSING** — no grouped roll-up, no group PATCH editor |
| Ports / optics / DDM workbench | `/api/infrastructure/{interfaces,port-summary,…}`, `FEATURE_PORT_DOM` | Infrastructure → Interfaces & Optics | `infrastructure/interfaces-and-optics.md` | partial | `portSignatures`, `portModuleTypes`, `portFilterOptions`, `portInterfaceDetail` all unused by the page |
| Device SSH terminal | `FEATURE_DEVICE_SSH`, `/api/devices/{id}/ssh{,-ticket}` | `DeviceTerminal.tsx` | `investigate/collect-from-a-device.md` | exposed | — |

### Telemetry ingestion and the pipeline

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| SNMP metric collection | `ENABLE_SNMP_COLLECTION`, `ENABLE_SNMP_METRICS`, `/api/collectors` | Administration → Sensors (platformOnly, read-only); Explore → Metrics | `send-data/metrics.md` | partial | poll targets/intervals are env-only; no enable/disable control |
| gNMI streaming | `ENABLE_GNMI_COLLECTION` | Sensors; Data Sources | `onboard-devices/streaming-gnmi.md` | partial | status only, no subscription editor |
| NETCONF | `ENABLE_NETCONF_COLLECTION` | Sensors | — | partial | status only |
| Syslog ingest | `syslog-ng` → `vector`, `/api/logs/*` | Explore → Logs | `send-data/syslog.md` | exposed | — |
| SNMP traps | `FEATURE_SNMP_TRAPS`, `/api/events` | Explore → Events | `send-data/traps.md` | exposed | — |
| Flow ingest (NetFlow/sFlow/IPFIX) | `goflow2`, `/api/flows/*` | Explore → Flows | `send-data/flows.md` | partial | **`/api/flows/apps` and `/api/flows/services` MISSING** — no app view, no per-service view of the flow plane |
| Telemetry coverage / unrecognized shapes | `/api/telemetry/unrecognized`, `/api/admin/parser/stats` | Administration → Telemetry Coverage | `administration/telemetry-coverage.md` | exposed | — |
| Pipeline processors | `FEATURE_PROCESSORS`, `/api/pipeline/processors` | Administration → Processors | `administration/processors.md` | exposed | — |
| Sealed fields / sensitive-data access | `FEATURE_SEALED_FIELDS`, `internal/sealedfields` | Administration → Sensitive Data Access | `administration/sensitive-data-access.md` | partial | `sealRotate`, `processorUnseal` helpers unused — no key-rotation or unseal control |
| Sealed quarantine | `/api/quarantine`, `/api/quarantine/reattribute` | none | — | **MISSING UI** | no list of what the pipeline quarantined; re-attribution is CLI/break-glass |
| Pipeline debugger | `/api/debug/*`, `cmd/correlix-debug` | Platform → Pipeline Debugger | `send-data/debug-the-pipeline.md`, `administration/debug-the-pipeline-cli.md` | exposed | — |

### Active measurement (probes, paths, synthetics)

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Synthetic checks (HTTP/DNS/TLS/TCP) | `FEATURE_SYNTHETICS`, `collectors/synthetics.go`; targets from env (`synTargets()`) | results only as `synthetic_*` correlation signals; Sensors shows a target count | — | **MISSING UI** | **verified: there is no DEM/synthetics page.** No monitor editor, no per-check result history, no availability board |
| Traceroute / path discovery | `FEATURE_TRACEROUTE`, `collectors/traceroute.go`, `/api/probe/paths`, `/api/paths/health` | Investigate → Flow Trace (`NetworkPath.tsx`), `PathHealthList.tsx` | `infrastructure/paths-and-tunnels.md` | partial | results exposed; `TRACEROUTE_TARGETS` is env-only — no target editor |
| STAMP sender / reflector | `FEATURE_ACTIVE_PROBE`, `FEATURE_STAMP_REFLECTOR`, `STAMP_TARGETS` | probe signals only | — | **MISSING UI** | no page; targets env-only |
| WAN echo | `FEATURE_WAN_ECHO`, `WAN_ECHO_TARGETS`, `/api/wan/interfaces` | Investigate → WAN Paths (`WanCircuits.tsx`) | `infrastructure/wan-interface-metrics.md` | partial | page calls only `/api/wan/interfaces` — see the WAN row below |
| WAN circuits / endpoints / policy | `/api/wan/{circuits,endpoints,policy}`, `wan_circuits.go` | none — `WanCircuits.tsx` is *named* for `/api/wan/circuits` and does not call it | — | **MISSING UI** | derived circuit mesh, endpoint registry, and the GET/PUT measurement-policy intent surface |
| Active verification | `FEATURE_ACTIVE_VERIFICATION`, `/api/settings/verification` | none | — | **MISSING UI** | opt-in toggle + read-only SSH credential; every sibling `/api/settings/*` has a panel |
| Path baselines | `FEATURE_PATH_BASELINES`, `pathgraph/` | folded into path health | — | headless-by-design | engine input, no separate surface |

### Correlation, RCA and incidents

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Correlation engine (8 causal layers, ~90 symptom kinds) | `src/correlation/{signals,layers,catalog}.py`, `/api/correlations*` | Investigate → RCA | `investigate/rca-explained.md` | exposed | — |
| Findings / anomalies | `/api/findings` | Investigate → Findings | `incidents/anomalies-and-correlations.md` | exposed | — |
| Alerts, episodes, maintenance windows | `/api/alerts*`, `/api/rules` | Operations → Active Alerts · Monitor Rules · Maintenance Windows | `monitoring/manage-alerts.md`, `monitoring/maintenance-windows.md` | exposed | — |
| Incidents + incident policies | `/api/incidents`, `/api/incident-policies` | Operations → Incidents; Administration → Ticketing & Automation | `incidents/working-incidents.md` | exposed | `getIncident` helper unused |
| RCA reports / postmortems | `/api/correlations/rca-reports`, `rca_report_http.go` | Analytics → RCA Reports | `investigate/read-an-rca-case.md` | exposed | `unpromoteRca` helper unused — can promote, cannot un-promote |
| Recovery scorecard / time intelligence | `/api/reliability/{rollups,trends,chronic-offenders}` | Analytics → Recovery Scorecard | `incident-response/rca-time-intelligence.md` | partial | **`/api/reliability/time-metrics` MISSING** — the persisted MTTD/MTTR trend series is never charted |
| RCA path spine (external contract) | `/api/rca/{id}/path`, `path_graph_api.go` | equivalent data via `/api/correlations/{id}/rca-path-view` | — | headless-by-design | frozen API contract; a second UI call would duplicate |
| TAC escalation pack | `/api/incidents/{id}/tac/*`, `internal/tac` | Investigate → Troubleshooting, RCA workspace | `investigate/send-to-tac.md` | exposed | **`/api/troubleshoot/tac/knowledge` MISSING** — the vendor-coverage panel |
| Action queue / triage | `/api/alerts/episodes`, correlation feed | Operations → Action Queue | `noc-guide/from-signal-to-ticket.md` | exposed | — |

### Protocol and BGP

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| BGP watchlist | `FEATURE_BGP_ALERTS`, `/api/bgp/watchlist` | Analytics → BGP Operations | `bgp/watchlist.md` | exposed | — |
| BGP alerting config | `/api/bgp/alerts/config` | none | `bgp/alerting.md` | partial | `bgpAlertConfig` / `setBgpAlertConfig` helpers unused — thresholds not editable in-product |
| RPKI · ASPA · bogons · geofeed · live feed | `FEATURE_BGP_LIVE_FEED`, `FEATURE_BGP_BOGON_FEED`, `/api/bgp/*` | Analytics → BGP Operations (`pages/bgp/*`) | `bgp/{rpki,as-paths,bogons,geofeed}.md` | exposed | — |
| BMP receiver | `FEATURE_BMP`, `/api/bgp/bmp/*` | BGP Operations | `bgp/bmp.md` | exposed | — |
| OSPF / IS-IS monitoring | `internal/igpmon`, `/api/protocols/{ospf,isis}/*` | `pages/igp/IgpAdjacencies.tsx` via `/api/protocols/${proto}/…` | `investigate/igp-health.md` | exposed | (allowlisted as `dynamic` — templated path) |
| Protocol diagnostics | `FEATURE_PROTOCOL_DIAG_COLLECT`, `/api/troubleshoot/protocol-diagnostics/*` | Investigate → Troubleshooting | `investigate/protocol-diagnostics.md` | exposed | — |

### Applications, services and cloud

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| App identification (App-ID) | `appid/`, `/api/appid/{resolve,catalog,status}` | only `resolve/batch`, inside AppObs | `passive-flow-app-attribution.md` (docs/) | partial | **`/api/appid/catalog` and `/api/appid/status` MISSING** — no override editor, no engine-coverage view |
| App-ID fusion worker | `FUSION_WORKER_ENABLED`, `/api/appid/fusion/status` | none | — | headless-by-design | worker ops metrics for probes/CLI |
| Application registry | `/api/applications`, `appid.go` | none | — | **MISSING UI** | name/criticality/archive CRUD |
| Service catalog | `/api/services` (+ `/selectors`, `/bindings`, audited `/selectors/{v}/backfill`) | none — the Services page uses the *cloud business-services* registry instead | — | **MISSING UI** | two registries exist, one has no surface |
| Cloud app observability | `ENABLE_CLOUD_APP_OBS`, `/api/cloud/*` | Operations → Services (5 tabs) | `application-experience-correlation.md` (docs/) | exposed | — |
| Cloud network overview | `/api/cloud/network/overview` | none (handler names an unbuilt "Cloud Network Overview surface") | — | **MISSING UI** | provider/seam roll-up with open-issue localization |
| Business services / SLOs / monitors | `/api/cloud/{business-services,slos,monitors}` | Operations → Services | — | exposed | — |
| Cloud connectors (AWS/Azure/GCP) | `cloudconn/`, `/api/cloud/connectors` | Administration → Data Sources | `cloud-connectors-architecture.md` (docs/) | exposed | `cloudConnector`, `cloudIdentityMap`, `cloudClearResourceMapping` helpers unused |
| Cloud ingest service plane | `/api/cloud/ingest/{connectors,source-status}` | none | — | headless-by-design | service-to-service, deliberately cross-tenant |
| Cloud logs | `/api/logs/search` (cloud plane) | Explore → Logs → Cloud | `explore/logs.md` | exposed | — |

### Wireless

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Wireless inventory | `FEATURE_WIRELESS`, `/api/wireless/{controllers,aps,wlans}` | Infrastructure → Wireless | `infrastructure/wireless.md` | partial | **`/api/wireless/bssids` MISSING** — BSSIDs beneath the APs are not rendered |
| Wireless remediation actions | `FEATURE_WIRELESS_ACTIONS`, `/api/wireless/actions*` | none | — | **MISSING UI** | a full propose → approve → reject → execute audited approval loop with zero UI |
| UniFi collector | `FEATURE_UNIFI`, `collectors/unifi.go` | feeds the Wireless page | — | partial | no connector status panel |
| Wireless correlation signals (18 RF kinds) | `src/correlation/layers.py` RF layer | Investigate → RCA | — | exposed | — |

### Security (CTEM)

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Security findings / exposures / stories | `FEATURE_SECURITY_LANE`, `/api/security/{findings,exposure-stories,views,rules}` | Security → Overview · Exposures · Exposure Stories · Detection Rules · Saved Views | `security/{exposures,exposure-stories,detection-rules,saved-views}.md` | exposed | `securityFinding` (single-finding) helper unused |
| Security lane health | `/api/security/lane/status`, `internal/seclane` | none | — | **MISSING UI** | no way to see whether the lane is running — the 2026-09-02 outage class |
| On-demand security scan | `/api/security/scan` (202/429) | none | `security/run-a-scan.md` | **MISSING UI** | documented in the portal, not buildable in the product |
| Hardening rules (~28 checks) | `internal/hardening/catalog.go` | rendered as findings | `security/ctem.md` | exposed | — |
| Threat detection (11 detectors) | `internal/threatlane/catalog.go` | Security → Threat Detection | `security/threat-detection.md` | exposed | — |
| Vulnerability / advisory feed | `internal/vuln/feed.go`, `internal/advisory`, `/api/vulns` | Security → Vulnerabilities | `security/vulnerabilities.md` | exposed | — |
| Compliance frameworks | `/api/security/frameworks`, `/api/compliance` | Security → Compliance | `security/compliance.md` | exposed | — |
| Transport security posture | `/api/security/transport-posture` | Administration → Transport Security | `security/transport-security.md` | exposed | — |
| Config backup + drift | `FEATURE_CONFIG_BACKUP`, `/api/devices/{id}/config/*`, `/api/config/drift` | Infrastructure → Config Drift; `DeviceConfigPanel.tsx` | `security/{config-backup,config-drift}.md` | exposed | — |
| Packet capture | `FEATURE_PACKET_CAPTURE`, `/api/devices/{id}/pcap*` | `pages/capture/DevicePcapPanel.tsx` | `security/packet-capture.md` | exposed | — |
| Data protection | `internal/dataprotect` | Platform → Data Protection | — | exposed | — |
| Policy documents / catalog / overrides | `/api/policy/{documents,document,catalog,effective,validate}` | none | — | **MISSING UI** | 7 client helpers, zero pages |

### Notification, ITSM and reporting

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Notification channels (9 connectors) | `notify/`, `/api/notify/*` + `/test` | Administration → Notifications | `incident-response/notifications.md` | exposed | `notifySNSTest`/`notifyTeamsTest` unused — SNS and Teams have no "Send test" |
| Contact points | `/api/notify/contact-points` | Administration → Notifications | — | exposed | — |
| ITSM integrations | `/api/integrations`, `/api/itsm/*`, `internal/ticketing` | Administration → Integrations | `incident-response/integrations.md` | exposed | — |
| ITSM reconcile ("Sync now") | `FEATURE_ITSM_RECONCILE`, `/api/integrations/reconcile` | none | — | **MISSING UI** | written for NOC operators; reachable only by curl |
| Ticket outbox + audit trail | `/api/tickets/{outbox,audit}` | none (`/api/tickets/links` is used) | — | **MISSING UI** | a stuck or failed ticket is invisible in-product |
| Inbound ITSM / NMS webhooks | `/api/integrations/webhook/`, `/api/nms/webhook/` | none | — | headless-by-design | provider-authenticated inbound receivers |
| NMS vendor integrations | `FEATURE_NMS_INTEGRATIONS`, `/api/nms/*` | Infrastructure → Discovery & NMS | `infrastructure/nms-integrations.md` | exposed | — |
| Scheduled reports (7 kinds; HTML/PDF/XLSX) | `ENABLE_REPORT_SCHEDULER`, `/api/reports/*` | Analytics → Reports | `dashboards-reports/reports.md` | exposed | — |
| Report artifact links | `/api/reports/view/` | emailed link | — | headless-by-design | token-authenticated, opened outside the SPA |
| Log export | `/api/logs/export`, `/api/exports/{policy,{id}}` | Explore → Logs | `explore/logs.md` | exposed | `logIndices` helper unused |
| Export artifact links | `/api/exports/view/` | signed link | — | headless-by-design | same as above |
| Saved searches + dashboards | `/api/saved` | Explore → Saved Searches; Analytics → Dashboard List | `dashboards-reports/built-in-dashboards.md` | exposed | — |

### Iris / AI

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Iris ask / commands / feedback | `FEATURE_AI`, `/api/ai/{ask,commands,feedback}` | Copilot rail; Investigate → Troubleshooting → `IrisLane.tsx` | `iris-ai/ask-iris.md` | exposed | — |
| Iris module catalog | `/api/ai/modules` (comment: *"so the UI can show what Iris AI can answer"*) | none | `iris-ai/overview.md` | **MISSING UI** | the "what can Iris answer" panel the handler was written for |
| Iris tools (26 registered) | `ai/toolspec.go`, `FEATURE_AI_TOOLS` | invoked by the model | `iris-ai/skills.md` | headless-by-design | model-invoked, fail-closed by declaration |
| Iris skills (13 SKILL.md) | `ai/skills/*`, `ai/skill_select.go` | selected automatically inside a lane | `iris-ai/skills.md` | partial | no skill browser — a user cannot see or pick which skill ran |
| Investigation memory / recall | `ai/investigation_memory.go`, `ai/recall.go` | Iris lane | `iris-ai/memory.md` | exposed | — |
| Copilot proxy | `FEATURE_COPILOT`, `/api/copilot/*` | Copilot rail | `COPILOT.md` (docs/) | exposed | — |
| AI tenant config / datasources | `/api/ai/{tenant-config,tenants}` | Administration | `iris-ai/setup.md` | exposed | — |

### Platform and administration

| Feature | Backend evidence | UI surface | Docs | Verdict | Missing |
|---|---|---|---|---|---|
| Licence | `internal/licence`, `/api/system/licence`, `cmd/correlix-licence` | Platform → Licence | `administration/licence.md` | exposed | — |
| Backup / snapshots / coverage | `/api/system/backup/*` | Platform tools | `deploy/{back-up-and-restore,manage-snapshots}.md` | exposed | — |
| Stack health | `/api/stack/health` | Platform → Stack Health | `deploy/verify-deployment.md` | exposed | — |
| Local auth, LDAP, TACACS, OIDC, SSO | `/api/auth/*` | Platform → Authentication; Login | `administration/{authentication,okta-sso}.md` | exposed | `ssoConfig` helper unused |
| **MFA self-enrolment** | `/api/auth/mfa/{setup,activate,disable,status}` | **none** — Login handles only the *challenge*; admin can only reset | `administration/identity-access.md` | **MISSING UI** | a user cannot turn on their own two-factor |
| Users · roles · scopes · API keys · token policy | `/api/{users,roles,scopes,apikeys}`, `/api/auth/token-policy` | Administration → Identity & Access · API Access | `administration/{identity-access,api-access}.md` | exposed | — |
| Tenants and orgs | `/api/{tenants,orgs}` | Administration | `administration/tenants-orgs.md` | exposed | — |
| Audit log · access explorer · sessions | `/api/audit`, `/api/access/explain`, `/api/sessions` | Administration → Access & Audit | `administration/audit-log.md` | exposed | — |
| Break-glass | `/api/breakglass` | Administration (open only) | — | partial | `listBreakGlass`, `endBreakGlass` unused — a session can be opened but not listed or closed |
| Customer onboarding | `/api/onboard`, `/api/onboard/snmp-config` | none | `onboard-devices/overview.md` | partial | `onboardCustomer` helper unused |
| GraphQL explorer | `/api/graphql` | Platform → GraphQL Explorer | `reference/api.md` | exposed | — |
| Embedded console gate | `/api/auth/osd-gate` | nginx `auth_request` | — | headless-by-design | not a browser XHR |
| Feature flags | `/api/features` | Devices, Opsis | `reference/feature-flags.md` | exposed | — |
| CLI tools | `cmd/correlix-debug`, `cmd/correlix-licence` | terminal | `administration/debug-the-pipeline-cli.md` | headless-by-design | CLI by design |

---

## Prioritised build list

Every MISSING/partial item, one line of scope each. Ordered by the standing
priority ruling (correlation/RCA → security → BGP/ops → the rest) crossed with
"how much shipped work is currently invisible".

### P1 — invisible work with the highest operational cost

| # | Item | Scope (one line) |
|---|---|---|
| 1 | **Security lane health + Scan now** | Add a lane-status strip and a "Scan now" button (202/429-aware) to `pages/security/SecurityOverview.tsx` from `/api/security/lane/status` + `/api/security/scan`. |
| 2 | **Ticket outbox + audit trail** | New "Delivery" tab in Administration → Ticketing & Automation listing `/api/tickets/outbox` (queued/failed) and `/api/tickets/audit` filtered by correlation id. |
| 3 | **Wireless remediation approval queue** | Render `/api/wireless/actions` propose/approve/reject/execute in `pages/ActionQueue.tsx` (an approval queue already exists) with the audit trail inline. |
| 4 | **MFA self-enrolment** | Account-menu → Security panel: QR/secret from `/api/auth/mfa/setup`, code confirm via `activate`, `disable`, state from `status`. |
| 5 | **WAN circuits, endpoints and policy** | Extend `pages/WanCircuits.tsx` (already named for it) with the circuit mesh, endpoint registry, and a policy drawer bound to `GET/PUT /api/wan/policy`. |
| 6 | **Recovery-scorecard trend series** | Chart `/api/reliability/time-metrics` as MTTD/MTTR-over-time on `pages/ReliabilityScorecard.tsx`. |

### P2 — capability that exists and is documented but unreachable

| # | Item | Scope |
|---|---|---|
| 7 | **Sealed-quarantine viewer** | Depth/age summary + paged metadata list from `/api/quarantine` on Administration → Processors; keep re-attribution CLI-only (break-glass). |
| 8 | **ITSM "Sync now"** | One audited button in the Integrations tab calling `/api/integrations/reconcile`, with the drift result rendered. |
| 9 | **Synthetics / DEM page** | New Operations leaf: per-check availability and latency history, plus a monitor editor — needs a backend CRUD surface first (targets are env-only today). |
| 10 | **Active-verification settings** | A panel in Administration → Settings for `/api/settings/verification` (opt-in + read-only SSH credential, write is audited). |
| 11 | **App-ID coverage + override editor** | Add `/api/appid/status` (precedence ladder, catalog sizes) and `/api/appid/catalog` CRUD to `pages/appobs/GovernanceSettings.tsx`. |
| 12 | **Flow app/service views** | Two tabs in Explore → Flows for `/api/flows/apps` and `/api/flows/services`, honouring the honest `attributed:false`. |
| 13 | **Service catalog + application registry** | Decide the single registry (`/api/services` vs cloud business-services), then build selectors/bindings/backfill UI for the survivor; retire or merge the other. |
| 14 | **BGP alert thresholds** | Bind the unused `bgpAlertConfig`/`setBgpAlertConfig` helpers to a config drawer on Analytics → BGP Operations. |

### P3 — completeness and polish

| # | Item | Scope |
|---|---|---|
| 15 | **Seam groups** | Grouped seam roll-up with state filter + group PATCH, on Security Overview or the RCA seam panel. |
| 16 | **Wireless BSSIDs** | A BSSID sub-table under each AP on `pages/Wireless.tsx` from `/api/wireless/bssids`. |
| 17 | **Cloud network overview** | Provider/seam roll-up card in the AppObs cloud shell from `/api/cloud/network/overview`. |
| 18 | **Iris module catalog** | "What Iris can answer" panel in `IrisLane.tsx` from `/api/ai/modules`; optionally a skill browser beside it. |
| 19 | **TAC vendor-coverage panel** | Render `/api/troubleshoot/tac/knowledge` as the Iris → Knowledge surface it was registered for. |
| 20 | **Policy documents** | Surface for the 7 unused policy helpers (catalog, documents, effective, validate, overrides) — or delete them if the feature is not shipping. |
| 21 | **Port workbench depth** | Wire `portSignatures`, `portModuleTypes`, `portFilterOptions`, `portInterfaceDetail` into `PortsWorkbench.tsx`. |
| 22 | **Break-glass session list** | List and close active sessions (`listBreakGlass`, `endBreakGlass`) beside the existing open control. |
| 23 | **Small unused-helper sweep** | `deleteSnmpProfile`, `unpromoteRca`, `notifySNSTest`, `notifyTeamsTest`, `sealRotate`, `processorUnseal`, `logIndices`, `getIncident`, `securityFinding`, `ssoConfig`, `onboardCustomer`, `cloudConnector`, `cloudIdentityMap`, `cloudClearResourceMapping`, `deviceLocation`, `deviceSite` — each is one control on a page that already exists. |

---

## Headless allowlist (seeded)

`docs/audit/headless-routes.yaml`, section `headless` — nine families that are
correct as machine surfaces and will never get a page:

| Route family | Reason |
|---|---|
| `/api/auth/osd-gate` | nginx `auth_request` target for the embedded `/search` + `/netbox` consoles; emits headers, not a document. |
| `/api/exports/view/` | Token-authenticated, expiring artifact link opened directly by the recipient outside the SPA. |
| `/api/reports/view/` | Same, for report artifacts; the URL is embedded in the "report is ready" email. |
| `/api/integrations/webhook/` | Inbound ITSM webhook receiver — per-tenant opaque path token + provider signature. The caller is ServiceNow/Jira/PagerDuty. |
| `/api/nms/webhook/` | Inbound NMS vendor-controller webhook receiver (Meraki/generic), same authentication shape. |
| `/api/cloud/ingest/connectors` | Service-to-service fan-out for the cloud poller; deliberately cross-tenant, must never reach a tenant UI. |
| `/api/appid/fusion/status` | App-ID fusion worker ops metrics behind `FUSION_WORKER_ENABLED`; the user-facing view is `/api/appid/status`. |
| `/api/rca/` | Frozen ordered path-spine contract for external consumers; the SPA renders the same data via `/api/correlations/{id}/rca-path-view`. |
| `/api/quarantine/reattribute` | Platform break-glass (requirePlatformAdmin **and** `sensitive_data:admin`) — deliberately not a button. |

Section `dynamic` — two families the frontend *does* call, through a template
the literal scanner cannot resolve: `/api/protocols/ospf/*` and
`/api/protocols/isis/*`, both reached via
`` `/api/protocols/${encodeURIComponent(proto)}/…` `` in `services/api.ts`,
rendered by `pages/igp/IgpAdjacencies.tsx`.

Section `missing_ui` — the 23 debt entries above. The guard pins its size, so
the list can only shrink.

---

## Method, and its limits

`tests/test_feature_ui_coverage.py` re-derives all of this on every CI run:

1. Backend routes from `mux.HandleFunc("…")` in `src/backend/main.go` unioned
   with the path literals in `internal/openapi/openapi.go`; `/api/internal/*`
   excluded (vmalert → api, service-to-service by construction).
2. Frontend `/api/…` string literals from every non-test `.ts`/`.tsx` under
   `src/frontend/src`.
3. Both normalised to segment lists with `*` for a variable segment, so
   `/api/incidents/{id}/tac` and `` `/api/incidents/${id}/tac` `` compare equal.
4. Grouped into families (two segments after `/api`); every backend family must
   be referenced or allowlisted. New unlisted family ⇒ **CI fails**.
5. Reverse check: every frontend literal must be servable by a registered
   backend route. Currently clean.

Verified negatives (2026-09-05): adding `mux.HandleFunc("/api/widgets/frobnicate", …)`
to `main.go` fails the forward check; a frontend literal `/api/devicez/list`
fails the reverse check; adding a frontend call to an allowlisted `headless`
family is reported as a stale allowlist entry. `main.go` was restored
byte-identical after the live proof.

**Known limits of the mechanical check** — these are why this prose audit exists
beside it:

- **Family granularity hides sub-route gaps.** `/api/incidents/{id}/tac/*` rides
  along with `/api/incidents/*`, which the SPA does call. A route can be
  unreferenced while its family is covered.
- **A referenced route is not a *used* route.** `services/api.ts` is a single
  module: a literal there counts as "referenced" even when no page calls the
  helper. That is exactly how the 33 dead helpers above hid, and the route-level
  check cannot see them. The helper-usage sweep in this document is manual;
  promoting it to a second CI assertion is worth doing once the current 33 are
  resolved (it would fail today).
- **Nav reachability is not checked by the guard.** A page can exist, call the
  route, and still have no nav leaf. For this audit all 96 page components under
  `pages/` were matched against `nav.tsx` mechanically (direct JSX use, named
  import, or lazy `import("./pages/…")`); none is orphaned. Promoting that to a
  CI assertion is cheap and worth doing.
- **Feature flags are not checked.** A dormant flag with a built UI reads the
  same as one with none; the flag column above is manual.
