# Competitor Application-Identification Research

**How major observability & network-monitoring tools turn raw telemetry into named applications — cloud vs. on-prem/datacenter, and what requires an agent**

- **Date:** 2026-06-25
- **Author:** Correlix research (background deep-research pass, vendor-doc verified)
- **Context tracker:** #81 App Identity engine (flow → app enrichment)
- **Audience:** Correlix platform owners deciding how to name on-prem/datacenter apps **agentlessly** (we ingest SNMP/gNMI metrics, NetFlow/IPFIX/sFlow headers, syslog, and NGFW App-ID from firewall logs — no host agent, no packet payload).

---

## Executive summary

The central finding is blunt and consistent across every vendor we examined:

> **A real, semantic application name comes from one of two places: (1) the SOURCE declares it — an in-host agent reads the listening process / instruments the code / the router runs DPI; or (2) the TOOL manufactures it by lookup against tables it controls — ports, IP/CIDR ranges, DNS, cloud metadata, NBAR2 app-id dictionaries, or operator-authored definitions. There is no third way. Nobody reliably names an *un-instrumented, on-prem application from flow headers alone* — the best a header-only/agentless path produces is a port/protocol label plus an endpoint hostname.**

Two architectural camps dominate:

1. **Agent/source-truth camp (Datadog USM/NPM, Dynatrace OneAgent, AppDynamics, New Relic APM, Elastic/Splunk APM via OTel).** Strong, high-fidelity app names — *because a host/code agent reads the running process or instruments the runtime*. Strip the agent away and these tools degrade dramatically. Their on-prem strength **is** the agent, not the network.

2. **Agentless flow/enrichment camp (Kentik, SolarWinds NTA, Datadog NetFlow mode, ThousandEyes Traffic/Cloud Insights, New Relic flow).** No host agent. They name apps by **lookup**: port→IANA tables (weak), **Cisco NBAR2 app-ids carried in the flow** (strong, but the *router* did the DPI), DNS/PTR, cloud IP-range/metadata, and **operator-authored custom application definitions** (protocol/port/IP/ASN/domain → name). None of these tools do their own DPI on flow.

A separate, narrower **passive-DPI camp** exists (Splunk Stream, Elastic Packetbeat) — real signature/protocol classification off a SPAN/tap or host sniffer — but it still only yields a **protocol type** (`http`, `mysql`), not a business-app name, and it needs a sensor or host install plus packet payload, which Correlix does not have.

**The single biggest insight for on-prem/datacenter naming without an inline firewall:** the incumbents that name on-prem apps *well* do it with **endpoint visibility (a host agent reading the listening process / instrumenting code) — not network DPI.** The moment you remove the agent (our situation), even the giants fall back to exactly the lanes Correlix already has access to: **router-side NBAR2 app-ids decoded against an options-template name table, operator-authored IP+port+domain→app definitions, CMDB/IPAM enrichment on stable datacenter IPs, and DNS/PTR hints — with port heuristics only as a last resort.** That convergence is the opportunity: an enrichment engine that fuses NBAR2 + curated IP/CMDB mappings + DNS + NGFW App-ID into a single authoritative app identity is something none of the agentless flow tools do end-to-end, and the agent-based tools simply don't play in this lane.

---

## Per-tool findings

### 1. Datadog

**Model:** No single "name the app" engine — naming is product-specific and depends on *where the telemetry originates*. Where Datadog runs a host agent on the workload, naming happens **at the source** from local process/OS/orchestrator metadata. Where it cannot (network gear, managed cloud endpoints, external IPs), it falls back to **lookup/enrichment** (passive DNS, reverse-DNS, IANA port tables, cloud IP ranges, user-supplied tag maps). **No Datadog product does payload DPI to *guess* an unknown app's identity.**

- **Universal Service Monitoring (USM):** Datadog Agent attaches **eBPF hooks to kernel syscalls** (accept4/read/write/close; OpenSSL uprobes for HTTPS; ETW on Windows/IIS) to compute RED metrics with no code change. **But the name does NOT come from the packets** — eBPF gives the flow + metrics; the name comes from **Unified Service Tags** (`DD_SERVICE`/`DD_ENV`/`DD_VERSION`) read from `/proc/PID/environ`, falling back to `app`/`short_image`/`kube_container_name`/`kube_deployment`/`kube_service`. **Requires a host agent.** Classifier = source (host agent + local metadata).
- **Network Performance Monitoring (NPM) / now Cloud Network Monitoring (CNM):** Agent system-probe uses **eBPF** to observe TCP/UDP sockets at **IP:port:PID** granularity. Because it knows the **PID**, it joins the flow to the process and that host's service tags — so a flow endpoint is named *only when that endpoint runs the agent*. For agentless endpoints it does **passive DNS inspection over port 53** → a `domain` tag (Agent 7.17+); anything else shows as **"N/A (Unresolved Traffic)."** Requires a host agent per resolved host.
- **NetFlow mode (agentless source):** Agent acts as a flow collector (v5/v9/jFlow/sFlow/IPFIX). Naming = **IANA port→app** (Postgres 5432, HTTPS 443 — generic, not *your* app), **cloud-provider IP-range enrichment** (AWS/EC2/region), **active reverse-DNS (PTR) on private ranges** → hostnames, and **user-defined IP/CIDR/port→tag mappings**. Source devices need no agent; classification is **by Datadog via lookup**, explicitly not DPI.
- **Network Device Monitoring (NDM):** SNMP-based; names **devices and interfaces only — no app naming** (confirms our hypothesis).
- **Cloud:** Unified Service Tags on agent hosts + `domain` (passive DNS) + cloud-integration API metadata/tags for managed endpoints (S3/RDS/LB).
- **On-prem, no firewall, no cloud metadata:** *Real* name only if the **Datadog Agent runs on the host** (USM/NPM). Flow-only → generic port name + reverse-DNS hostname + manual maps. SNMP-only → nothing. Passive DNS → opportunistic `domain` tag.

**Bottom line:** Datadog's strong app naming is **agent-and-tag driven (named at the source), not network-DPI driven.** Remove the agent and cloud metadata and it degrades to port-guessing + reverse-DNS + manual mappings.

---

### 2. Dynatrace

**Model:** The inverse of a source-tagged flow model — **classification is done server-side by Dynatrace**, fed by a deep agent. OneAgent reports raw facts (process properties, intercepted requests, traces, connections); Dynatrace's server applies built-in detection rules to *derive* named Process Groups, Services, and the Smartscape topology. **Without OneAgent (or OTLP traces), Dynatrace does not produce named "services" in the APM sense.**

- **Process group detection:** OneAgent reports each process's **executable name/path, command-line args, Java system properties, environment-variable content, container metadata, Kubernetes workload info**. Server-side rules (technology-aware: Tomcat/NGINX/Apache/PHP-FPM/Node/IIS/.NET/JVM) combine with **AND** to emit a **process-group identifier that also serves as the default name**.
- **Service detection:** From **code-level instrumentation and distributed tracing** (not just process facts). OneAgent intercepts entry points (HTTP, web service, DB, messaging, remoting). Naming signals: **application identifier, URL/context-root segment, server name, listening port**, with transformations (strip versions, extract URL segment) to keep identity stable across restarts. Rules evaluated top-to-bottom, first match wins. **Only full-stack mode yields named services**; infrastructure mode gives process groups only.
- **Smartscape:** Built **by Dynatrace from agent observations + trace data** into an application→service→process→host→datacenter graph; caller→callee service edges come from distributed tracing.
- **Network zones:** purely an **agent-routing/traffic-locality** construct (which ActiveGate an agent talks to) — **nothing to do with app naming.**
- **Agentless options:** ActiveGate **extensions** pull remote metrics + topology where the *extension author's schema defines names*; **cloud integrations** name from provider API metadata; a **NetFlow extension** ingests v5/v9/sFlow/IPFIX via an OTel Collector into **flow logs/dashboards (IP/port/conversation)** — we could **not** verify it produces named applications (treat "NetFlow names apps in Dynatrace" as unverified/likely false in the APM sense).
- **Cloud / on-prem:** Same agent mechanism either way. On-prem with zero network/cloud metadata is actually Dynatrace's **strong case** — purely from binary + cmdline + Java system property + URL context root + server name — **but it requires OneAgent.**

**Bottom line:** Strongest exactly where you have a host agent in full-stack mode; its agentless/flow path is weak for *naming* (schema-defined or cloud-metadata, flows stop at IP/port/conversation).

---

### 3. Cisco ThousandEyes

**Model:** **Active synthetic testing — the application is the configured test target, not an inference over observed traffic.** You create a test (HTTP Server, Page Load, Transaction) pointing at a **URL/IP/hostname**, and that target *is* the app; pre-built SaaS templates (M365, Slack, Webex) let you pick a known app by name. The "name" is **operator-declared**.

- **Vantage points:** Cloud Agents (TE-hosted), Enterprise Agents (customer-deployed), Endpoint Agents (PC/Mac). On-prem internal app = deploy an Enterprise Agent behind the firewall and configure a test against the internal URL/IP.
- **Passive paths (newer):** **Cloud Insights** ingests AWS/Azure VPC + Transit Gateway **flow logs** (S3→SNS) + cloud API metadata; **Traffic Insights** consumes **NetFlow/IPFIX/SNMP/Cisco NBAR**. Like Kentik, these lean on **router-side NBAR + cloud flow-log/API metadata**, not TE's own DPI.
- **Requires:** active test config + a vantage-point agent (and flow-log/API integration for Insights).
- **Classifier:** operator declaration (synthetic core); router NBAR / flow-log metadata (Insights).

---

### 4. Kentik

**Model:** **Passive flow enrichment via lookup — agentless, no DPI.** Populates an `Application` dimension at ingest by a first-match precedence chain:

1. **Custom Applications** — operator rules on **protocol + port + IP + ASN** (the primary path for naming *your own* internal/datacenter apps).
2. **Cisco NBAR2** — reads the `applicationName` the **router** computed and carried in the flow.
3. **OTT Services** — Netflix/Disney+ etc. via the True Origin engine (**flow + DNS matched against a fingerprint database** + a statistical classifier — not payload DPI).
4. **Well-known Services** — port/protocol vs the Nmap services list (443→https).
5. **Protocols** — raw protocol keyword as last resort.

Plus **Flow Tags** and **Custom Dimensions/populators** (tabular enrichment keyed on subnets/IP ranges).

- **Cloud:** AWS/Azure/GCP **VPC/VNet/Transit Gateway flow logs** + cloud API metadata (security groups, tags) → app-id, project, region, container/pod.
- **On-prem, no firewall/no cloud metadata:** the **Custom Applications** path (proto/port/IP/ASN rules) and/or **NBAR2** if Cisco gear is in the path; else port-based or raw protocol. **No automatic DPI discovery of unknown internal apps.**
- **Requires:** flow export (NetFlow/sFlow/IPFIX/VPC logs) + BGP/SNMP + optional cloud API. **Agentless.**
- **Classifier:** NBAR2 = source (router); everything else = Kentik via lookup/correlation.

---

### 5. New Relic

**Model:** Two non-converging planes. **Real service identity is source-declared; the flow plane is only a port→label lookup.**

- **App/service identity:** APM agent `app_name` (config / `NEW_RELIC_APP_NAME` / JVM flag), framework auto-naming (servlet `display-name`, context path), or OTel `service.name` → entity synthesis (service entity *requires* `service.name`).
- **Process identity:** infra agent reads the OS process table → `commandName`/`commandLine` (`ProcessSample`) — a process label, not a service entity.
- **Flow identity:** ktranslate (Kentik engine) derives `application` from the **lowest numeric of src/dst port** → well-known label; optional static `-application_map`. Enriches ASN/geo/protocol/SNMP interface names. **No DPI, no SNI, no flow→service correlation.**
- **On-prem, no firewall/cloud metadata:** real name only via APM agent or OTel `service.name`; infra agent → process name; flow → port-derived label only.
- **Classifier:** app/service = source; flow `application` = collector but only a trivial port map.

---

### 6. Cisco AppDynamics

**Model:** **APM agent-based code instrumentation — app/tier/node are modeled constructs declared in agent config.** An App Agent (Java bytecode, .NET CLR profiler, Node/PHP/Python) registers to the Controller under three **operator-declared** names: **Business Application, Tier, Node** (controller-info.xml / JVM args / env). Not inferred from traffic.

- **Backends** (DBs, queues, uninstrumented HTTP) are **auto-discovered from exit-point instrumentation** and named by **Backend Detection Rules** (host/port/URL/DB-name property rules).
- **Cloud:** same mechanism; Kubernetes Cluster Agent adds **Tier Name Strategies** deriving tier names from k8s metadata.
- **On-prem, no firewall/cloud metadata:** AppDynamics' native home — name comes entirely from **agent config + code-level backend discovery**, needing neither firewall nor cloud metadata. Constraint is the opposite of flow tools: **you must instrument the runtime.**
- **Network Visibility module:** adds a Network Agent that **requires the App Agent** (not standalone); maps TCP connections onto the App Agent's existing tier/node identity — it does **not** name apps independently.
- **Classifier:** the instrumented app runtime + Controller rules (no router, no DPI).

---

### 7. Elastic

**Model:** Real names from the SOURCE (in-app APM/OTel agent); passive paths give **protocol type**, not business-app name.

- **ECS `service.name`** — "normally user given"; populated by the app's logging library or an ES ingest pipeline (grok/dissect/set), not self-populating.
- **APM agents (auto-instrumentation)** — the real path; agent sets/auto-detects `service.name` (Java `Implementation-Title`/Spring `spring.application.name`/servlet display-name; .NET entry assembly).
- **OTel** — `OTEL_SERVICE_NAME`/`service.name` (default `unknown_service`).
- **Packetbeat (the DPI-ish path)** — passive sniffer (pcap/af_packet) decoding ~15+ L7 protocols (HTTP/DNS/MySQL/PostgreSQL/Redis/Mongo/TLS) into transactions; labels the **protocol type** + optionally the **local OS process name** (host install only). Does **not** synthesize a business-app name.
- **Universal Profiling (eBPF)** — whole-host agent grouping by infra dims; a real service name needs **APM correlation**.
- **NetFlow integration** — geo/IP/port/protocol/bytes only; **no app naming.**
- **On-prem, no firewall/cloud metadata:** best = APM/OTel agent (real name); Packetbeat on host = protocol + process name; Packetbeat on SPAN/tap = protocol + endpoints only; NetFlow = no name.
- **Classifier:** APM/OTel/log-library = source; Packetbeat = platform (protocol + host process name); log pipeline = platform if configured.

---

### 8. Splunk

**Model:** Four independent planes; **the strongest passive classifier of the whole set (Splunk Stream = real DPI)**, but it still yields protocol, not a business-app name.

- **Splunk Stream (wire DPI)** — docs state it "utilizes deep packet inspection," **L3–L7**, signature/payload-based (**port-independent**). ~50 full field-extraction protocols + 200+ detection-only protocols surfaced as the `app` field. Runs on the **streamfwd sensor**.
- **Logs** — default `host`/`source`/`sourcetype` (the indexer-assigned sourcetype is the app/format identity, e.g. `cisco:asa`) + search-time extractions + **CIM** normalization (Network Traffic/Web/Auth data models).
- **Observability Cloud APM (OTel)** — source-declared `service.name`; **inferred services** = platform derives an un-instrumented dependency from the *caller's* span attributes.
- **Flow** — NetFlow via the Independent Stream Forwarder, classified by the same DPI/CIM.
- **On-prem, no firewall/cloud metadata:** (a) **Stream DPI** off SPAN/TAP/inline/PCAP/NetFlow → protocol/`app` label from packets; (b) log sourcetype + extraction + CIM if the app logs. No instrumentation = no true APM service node, only protocol/sourcetype identity.
- **Requires:** a sensor (Stream) or forwarder/HEC (logs) or OTel collector (APM) — never sensorless/logless.
- **Classifier:** APM = source; Stream + logs = platform.

---

## Comparison table

| Tool | Primary mechanism | Cloud-app naming | On-prem naming (no firewall, no cloud metadata) | Requires agent? | Classified by |
|---|---|---|---|---|---|
| **Datadog USM/NPM** | eBPF socket/syscall + **Unified Service Tags from process env** | Service tags + cloud API + passive-DNS `domain` | **Real name only if Agent on host**; else port (IANA) + reverse-DNS + manual maps | **Yes (host agent)** | Source (host agent) |
| **Datadog NetFlow/NDM** | Flow collector / SNMP | Cloud IP-range + port tables | Port→IANA name + PTR hostname + manual IP/port maps; NDM = no app naming | No (flow/SNMP) | Tool (lookup) |
| **Dynatrace** | **OneAgent** facts → server-side detection rules + tracing | k8s/cloud resource attrs feed name | binary + cmdline + Java prop + URL context-root + server name (**needs OneAgent**) | **Yes (OneAgent)** | Tool/server (Dynatrace) |
| **ThousandEyes** | Active synthetic test; app = configured target | Target SaaS endpoint / template; Insights use VPC logs + NBAR | Enterprise Agent + manually configured target | **Yes (vantage agent)** | Operator declaration |
| **Kentik** | **Passive flow enrichment (lookup, no DPI)** | VPC flow logs + cloud API metadata/tags | **Custom Application rules (proto/port/IP/ASN)** or NBAR2 | No (flow) | Tool (lookup); NBAR2 = source |
| **New Relic** | APM `app_name`/OTel; flow = port→label | APM/OTel agent name + cloud tags | APM/OTel agent (real) or infra process name; flow = port label | **Yes for real name** | Source (APM); tool (port map) |
| **AppDynamics** | **APM agent registration** (Business App/Tier/Node) | Agent config + k8s Cluster Agent strategies | **Install app agent**; name from config + backend rules | **Yes (app agent)** | Source (instrumented runtime) |
| **Elastic** | APM/OTel `service.name`; Packetbeat protocol decode | APM/OTel agent + k8s | APM/OTel agent (real); Packetbeat = protocol + host process | **Yes for real name** | Source (APM); platform (Packetbeat protocol) |
| **Splunk** | OTel APM; **Stream = real L3–L7 DPI**; sourcetype/CIM | OTel `service.name`; inferred deps from caller spans | **Stream DPI → protocol/`app`** off SPAN/tap/NetFlow; or sourcetype/CIM from logs | Sensor or forwarder (not host-APM-only) | Source (APM); platform (Stream/logs) |

---

## The 3–4 universal patterns

1. **Host-agent / process-based (endpoint truth).** A host agent reads the *listening process* (binary, command line, env vars, container/k8s metadata) or instruments the code, and the name is set **at the source**. — Datadog USM/NPM (eBPF + tags), Dynatrace OneAgent, AppDynamics, New Relic APM, Elastic/Splunk APM. **Highest fidelity; the only path that reliably names un-instrumented... — actually, that names *your own* on-prem apps. Hard requirement: an agent on the box.**

2. **Network-DPI / sensor (wire truth).** A sensor on a SPAN/tap or inline reads packet payload and classifies by signature. — Splunk Stream (true DPI), Elastic Packetbeat (protocol decoders), and **router-side Cisco NBAR2** (the DPI runs in the router, exported as an app-id). **Yields protocol/app classification but usually only a protocol type unless NBAR2 has a named signature; needs payload + a sensor/router in the path.**

3. **Flow + enrichment-lookup (header truth + tables).** No payload. Map the 5-tuple/ASN/flow fields to a name via tables the tool controls: **IANA port lists (weak), Cisco NBAR2 app-ids carried in Flexible NetFlow/IPFIX (strong, source-classified), cloud IP-range/metadata, DNS/PTR, and operator-authored custom application definitions (proto/port/IP/ASN/domain → name).** — Kentik, SolarWinds NTA, Datadog NetFlow mode, ThousandEyes Traffic/Cloud Insights, New Relic flow. **Agentless; fidelity entirely depends on NBAR2 presence + how good the curated mappings are.**

4. **Source-provided application logs (declared truth).** Read App-ID / app names that an upstream device already classified — **NGFW App-ID (Palo Alto/FortiGate), proxy/LB access logs, NBAR2 app-tables, syslog sourcetype.** The firewall/proxy/router did the work; the tool ingests and joins. — Kentik/NTA (NBAR2), Splunk (sourcetype/CIM), and **Correlix today (NGFW App-ID from firewall logs).**

---

## The on-prem / datacenter insight (no inline firewall, no agent)

**The biggest insight:** every incumbent that names on-prem/datacenter apps *well* does it with **endpoint visibility — a host agent that reads the listening process or instruments the code — not network DPI.** Datadog (USM eBPF + `DD_SERVICE`), Dynatrace (OneAgent binary/cmdline/URL-context), AppDynamics (declared Business App/Tier/Node), New Relic and Elastic/Splunk APM all share this DNA. Their on-prem strength **is** the agent. The moment you remove the agent — which is Correlix's situation — even the giants fall back to the **flow + enrichment-lookup** lane, and in that lane the realistic, vendor-proven mechanisms are exactly:

| Rank | Mechanism | Who classifies | On-prem (no firewall) fidelity | Notes |
|---|---|---|---|---|
| 1 | **Router-side NBAR2 DPI exported in Flexible NetFlow/IPFIX** (app-id + name options-template) | **Source (router)** | **Best agentless option** — names known apps + custom NBAR2 protocols | Needs NBAR2-capable Cisco gear in a **symmetric** path; eroded by **encrypted SNI/ECH** and **asymmetric routing**; NBAR2 partly mitigates via DNS-based first-packet classification |
| 2 | **Operator-authored custom application definitions** (IP/CIDR + port + domain/SNI → name) | Tool (human-curated) | **Most reliable for *your* internal apps** | High for what you defined, zero for the rest; maintenance burden — but DC IPs are stable so it sticks |
| 3 | **CMDB / IPAM / asset enrichment** (join flow IP → "Payroll tier", VIP → "ERP") | Tool (external source-of-truth) | **Very strong on-prem** (stable DC IPs, you own inventory) | Only as good/current as the CMDB |
| 4 | **DNS snooping / reverse-PTR** (IP↔host) | Source (NBAR2 DNS-class) or Tool (PTR) | Medium — labels the *endpoint*, infers app | Breaks on encrypted DNS (DoH/DoT), shared/generic PTR |
| 5 | **Port heuristics (IANA)** | Tool (lookup) | **Low** — everything-on-443 collapses to "HTTPS" | Useful only for fixed-port legacy (22/53/25); actively misleading on TLS-heavy nets |

**Why port-based naming is near-useless:** the vast majority of modern enterprise/SaaS traffic rides **443/TCP (and 443/UDP via QUIC/HTTP3)**; Salesforce, M365, Zoom, a custom internal web app, and TLS C2 all collapse into one "HTTPS" bucket, and apps deliberately use 443 to traverse firewalls. This is precisely why NBAR2 exists and why SolarWinds NTA marks so much traffic "unknown" on a TLS-heavy network.

**Practical conclusion for Correlix:** with no host agent and no inline firewall, internal-app naming has to come from a **fusion** — (1) **router-exported NBAR2 app-ids decoded against the options-template name table** where Cisco DPI gear sits in the path, (2) an **operator-owned IP+port+domain→app definition store** for apps NBAR2 has never heard of, (3) a **CMDB/IPAM join** on stable datacenter IPs, (4) **DNS/PTR** as a hint layer, and (5) **NGFW App-ID** (which Correlix already consumes) where firewalls *are* on the path — with ports only as the last-resort fallback. No single mechanism suffices; this mirrors exactly what NTA does (NBAR2 decode + editable port/app table), but **no agentless tool fuses all of these into one authoritative app identity** — that fusion is Correlix's opening. The honest ceiling without an agent or payload: we will name **known apps (NBAR2/App-ID/cloud) and apps we explicitly define (custom maps/CMDB)** very well, but we **cannot auto-discover the real name of an unknown, un-instrumented, all-on-443 internal app** — and neither can any agentless competitor.

---

## Honesty / what could not be fully verified

- **Datadog eBPF hook count** (8 syscall hooks) is from Datadog's engineering blog, not a stable doc page — version-dependent. No evidence any Datadog product does payload-content DPI to infer an unknown app's brand.
- **Dynatrace NetFlow extension naming apps:** could **not** verify it produces named applications/services — the doc shows flow logs + IP/port/conversation dashboards only. Treat "Dynatrace NetFlow names apps" as **unverified / likely false** in the APM sense. Exact SDv1 per-service-type naming format strings and SDv2 metadata→name mapping were not fetched in full.
- **Kentik** `kb.kentik.com` direct fetches were partly blocked; the first-match precedence *order* (Custom Apps → NBAR2 → OTT → well-known → protocol) came from one WebFetch + search excerpts — confident in the *set*, slightly less in exhaustive ordering.
- **AppDynamics** docs now 301-redirect to help.splunk.com (Cisco/Splunk move); several findings rely on search excerpts, though the App-Agent-required-for-Network-Visibility claim is well-corroborated.
- **ThousandEyes** Cloud/Traffic Insights detail (VPC logs via S3→SNS; NetFlow/IPFIX/SNMP/NBAR) came from search excerpts, not full-page fetches.
- **New Relic** DPI absence is a *negative* finding (no NR doc claims L7 flow classification); `-application_map` confirmed from the kentik/ktranslate repo, not an NR doc.
- **Elastic/Splunk** no single vendor page states the platform auto-extracts `service.name` from arbitrary raw logs (depends on the integration pipeline). Several `docs.splunk.com` pages returned HTTP 403; DPI/protocol-count claims corroborated via the help.splunk.com mirror.
- **Cisco NBAR2** several primary pages returned HTTP 403 to the fetcher; content cross-checked via Cisco's search index + corroborating QoS-NBAR docs. **Exact current NBAR2 application count** could not be pinned to one live primary page — treat **"~1,400–1,500+ via Protocol Packs"** as approximate.

---

## Sources

**Datadog**
- https://docs.datadoghq.com/universal_service_monitoring/
- https://www.datadoghq.com/blog/universal-service-monitoring-datadog/
- https://www.datadoghq.com/blog/ebpf-guide/
- https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/
- https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/
- https://www.datadoghq.com/blog/dns-resolution-datadog/
- https://docs.datadoghq.com/network_monitoring/netflow/
- https://www.datadoghq.com/blog/monitor-netflow-with-datadog/
- https://docs.datadoghq.com/network_monitoring/devices/
- https://docs.datadoghq.com/getting_started/tagging/unified_service_tagging/

**Dynatrace**
- https://docs.dynatrace.com/docs/observe/infrastructure-observability/process-groups/configuration/pg-detection
- https://docs.dynatrace.com/docs/observe/applications-and-microservices/services/service-detection-and-naming/customize-service-detection
- https://docs.dynatrace.com/docs/platform/oneagent/monitoring-modes/monitoring-modes
- https://docs.dynatrace.com/docs/platform-modules/applications-and-microservices/services/service-detection-and-naming/service-types/unified-service
- https://docs.dynatrace.com/docs/observe/application-observability/services/service-detection/service-detection-v1
- https://docs.dynatrace.com/docs/analyze-explore-automate/smartscape/smartscape-concepts
- https://docs.dynatrace.com/docs/manage/network-zones/network-zones-basic-info
- https://docs.dynatrace.com/docs/manage/network-zones/oneagent-connectivity
- https://docs.dynatrace.com/docs/ingest-from/dynatrace-activegate/capabilities/routing-monitoring-purpose
- https://docs.dynatrace.com/docs/observe/infrastructure-observability/extensions/netflow

**Kentik**
- https://kb.kentik.com/docs/custom-applications
- https://kb.kentik.com/docs/general-dimensions
- https://kb.kentik.com/docs/ott-service-tracking
- https://kb.kentik.com/docs/flow-tags
- https://kb.kentik.com/docs/custom-dimensions
- https://kb.kentik.com/docs/kentik-for-aws
- https://kb.kentik.com/docs/kentik-for-gcp
- https://www.kentik.com/resources/google-cloud-vpc-flow-logs-for-kentik/
- https://www.kentik.com/blog/unlocking-network-insights-bringing-context-to-cloud-visibility/
- https://www.kentik.com/kentipedia/ott-services/

**ThousandEyes**
- https://docs.thousandeyes.com/product-documentation/getting-started/getting-started-with-cloud-and-enterprise-agent-tests
- https://docs.thousandeyes.com/product-documentation/getting-started/getting-started-with-cloud-and-enterprise-agents
- https://docs.thousandeyes.com/product-documentation/cloud-insights
- https://docs.thousandeyes.com/product-documentation/traffic-insights
- https://docs.thousandeyes.com/product-documentation/integration-guides/custom-built-integrations/aws-for-cloud-insights
- https://docs.thousandeyes.com/product-documentation/global-vantage-points

**AppDynamics**
- https://docs.appdynamics.com/display/PRO42/Business+Application,+Tier,+and+Node+Naming
- https://docs.appdynamics.com/appd/23.x/latest/en/application-monitoring/tiers-and-nodes
- https://docs.appdynamics.com/appd/23.x/latest/en/application-monitoring/configure-instrumentation/backend-detection-rules
- https://docs.appdynamics.com/appd/24.x/latest/en/infrastructure-visibility/network-visibility/network-visibility-overview
- https://docs.appdynamics.com/appd/24.x/latest/en/infrastructure-visibility/network-visibility/network-visibility-concepts
- https://docs.appdynamics.com/appd/24.x/latest/en/infrastructure-visibility/network-visibility/set-up-network-visibility-on-linux/set-up-the-network-and-app-agents-on-linux
- https://help.splunk.com/en/appdynamics-saas/infrastructure-visibility/25.5.0/monitor-kubernetes-with-the-cluster-agent/auto-instrument-applications-with-the-cluster-agent/splunk-appdynamics-tier-name-strategies

**New Relic**
- https://docs.newrelic.com/docs/apm/agents/manage-apm-agents/app-naming/name-your-application/
- https://docs.newrelic.com/docs/apm/agents/java-agent/configuration/automatic-application-naming/
- https://docs.newrelic.com/docs/opentelemetry/best-practices/opentelemetry-best-practices-resources/
- https://docs.newrelic.com/docs/network-performance-monitoring/setup-performance-monitoring/network-flow-monitoring/
- https://docs.newrelic.com/docs/infrastructure/infrastructure-agent/configuration/infrastructure-agent-configuration-settings/
- https://github.com/kentik/ktranslate

**Elastic**
- https://www.elastic.co/docs/reference/ecs/ecs-service
- https://www.elastic.co/docs/reference/ecs/logging/intro
- https://www.elastic.co/docs/reference/apm/agents/java/config-core
- https://www.elastic.co/beats/packetbeat
- https://www.elastic.co/guide/en/beats/packetbeat/current/configuration-interfaces.html
- https://www.elastic.co/docs/reference/beats/packetbeat/configuration-processes
- https://www.elastic.co/docs/solutions/observability/infra-and-hosts/universal-profiling
- https://www.elastic.co/docs/reference/integrations/netflow
- https://opentelemetry.io/docs/languages/sdk-configuration/general/

**Splunk**
- https://docs.splunk.com/Documentation/StreamApp/8.1.5/DeployStreamApp/ProtocolDetection
- https://help.splunk.com/en/splunk-stream/install-and-configure-splunk-stream/8.1/protocols/supported-protocols
- https://www.splunk.com/en_us/blog/learn/deep-packet-inspection-dpi.html
- https://help.splunk.com/en/splunk-enterprise/get-data-in/9.4/configure-indexed-field-extraction/about-default-fields-host-source-sourcetype-and-more
- https://docs.splunk.com/Splexicon:Sourcetype
- https://docs.splunk.com/Observability/gdi/opentelemetry/components/resource-processor.html
- https://help.splunk.com/en/splunk-observability-cloud/monitor-application-performance/key-concepts-in-splunk-apm

**SolarWinds NTA & Cisco NBAR2/AVC**
- https://documentation.solarwinds.com/en/success_center/nta/content/nta-applications-nbar2.htm
- https://documentation.solarwinds.com/en/success_center/nta/content/nta-set-up-nbar2-on-a-cisco-device.htm
- https://documentation.solarwinds.com/en/success_center/nta/content/nta-configuring-applications-and-service-ports-sw241.htm
- https://documentation.solarwinds.com/en/success_center/nta/content/nta-adding-applications-and-service-ports-sw251.htm
- https://www.solarwinds.com/netflow-traffic-analyzer/use-cases/nbar2
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/configuration/15-mt/fnf-15-mt-book/fnf-nbar.html
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos_nbar/configuration/xe-16/qos-nbar-xe-16-book/clsfy-traffic-nbar.html
- https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/qos/b-quality-of-service/m_clsfy-traffic-nbar-0.html
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/configuration/xe-3s/cfg-avc-xe.html
- https://www.thenetworkdna.com/2022/06/nbarnbar2-vs-cbar.html
