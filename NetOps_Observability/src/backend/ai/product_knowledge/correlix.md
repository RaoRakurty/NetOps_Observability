# Correlix — Concepts & How-To

## What is Correlix
Correlix is a network observability platform: it discovers your devices, ingests
multi-protocol telemetry (SNMP, gNMI, NETCONF, syslog, flows), correlates related
signals into root-cause problems with evidence, and presents it all — dashboards,
topology, incidents, RCA — behind one pane. Its differentiator is evidence-grounded
RCA: it never claims a root cause it can't back with independent evidence.

## What is a correlation (and how correlation works)
A correlation groups related operational signals (alerts, metric anomalies, syslog,
flow changes, probe results) that share a time window and a topological or ownership
relationship into a single problem, so the NOC sees one incident instead of a storm
of alerts. The engine admits signals through a grounding gate (they must relate on
the real topology or a known seam), ranks candidate root causes against a
failure-signature catalog, and assigns an honest verdict. It reduces alert noise and
points at the likely cause with the evidence behind it.

## What is RCA (root cause analysis) in Correlix
RCA is the correlation's explanation: the likely root cause, the timeline of what
happened first and next, the supporting and contradicting evidence across signal
classes, what evidence is still missing, and the recommended owner. Open any RCA
candidate under Monitoring → Correlations to see its evidence ledger. RCA is
read-only and evidence-grounded — every claim links back to the signal it came from.

## What do the verdict tiers mean (confirmed, suspected, undetermined)
A correlation's verdict is its evidence maturity, from weakest to strongest:
- **Undetermined** — low evidence; Correlix has grouped signals but can't yet name a
  cause. It's a watch item, not an action item.
- **Suspected** — a likely root cause with meaningful but not-yet-independent
  evidence. Candidate for action.
- **Confirmed** — the root cause is corroborated by independent evidence across at
  least two signal classes. This is the highest confidence.
Confirmation requires agreement across independent streams — Correlix never shows
"confirmed" on a single weak signal.

## What is a seam
A seam is a control-plane ownership boundary between network domains — for example
the handoff between your enterprise edge and an ISP/DIA circuit, an SD-WAN overlay
vs. its underlay transport, a VPN, a DX (direct connect), or a cloud backbone.
Seams matter for RCA because they tell Correlix WHO owns a fault (you vs. a
provider) and split responsibility at the right boundary. Seam types include DIA,
SDWAN, VPN, DX, and CLOUD_BACKBONE.

## What is evidence and grounding
Evidence is the set of signals Correlix attached to a correlation, each with a
citation back to its source (a log line, a metric anomaly, a probe result, a ticket).
Grounding is the rule that a signal is only admitted to a correlation if it relates
on the real topology or a known seam — this is what keeps RCA honest and prevents
spurious "everything is related" correlations. Missing evidence is disclosed
explicitly ("OSPF adjacency-change evidence not found") rather than hidden.

## Incidents vs correlations vs alerts
An **alert** is a single rule firing on one signal (e.g. an interface down). A
**correlation** groups related alerts/signals into one root-cause problem. An
**incident** is the operational record you work and hand to ITSM. Correlix's value
is turning many alerts into few correlated incidents with a root cause, so the NOC
works problems, not noise.

## What is a tenant and an org
A tenant is an isolated customer/workspace: its data (devices, flows, correlations,
reports) is visible only to that tenant — enforced everywhere (database row
security, per-tenant indices, scoped queries). An org is an account layer above
tenants (an org owns one or more tenants). The platform owner (global tenant
super-admin) is the only cross-tenant role; everything else is strictly scoped.

## How discovery works (finding devices)
Devices enter the inventory by SNMP scan (set ENABLE_SNMP_DISCOVERY=true and
SNMP_CIDR_RANGES, and add v2c/v3 credentials in the SNMP Profile Manager under
Infrastructure), by declaring them statically, or by importing from a source of
truth like NetBox. Live reachability/health comes from the telemetry plane, not the
inventory — inventory is intent, telemetry is truth.

## How to set up SNMP discovery
1. Set `ENABLE_SNMP_DISCOVERY=true` and `SNMP_CIDR_RANGES` (narrow it to your real
   management range — the default 10.0.0.0/8 is broad).
2. Open Infrastructure → Devices → SNMP Profile Manager and add v2c community or v3
   credentials.
3. Discovery populates the inventory; live health then appears from telemetry.

## How to enable SSO (OIDC / SAML / LDAP / TACACS)
Go to Administration → Identity & Access → Authentication. Correlix supports OIDC
(e.g. Okta, Azure AD), LDAP, and TACACS+ as native config, plus a Keycloak broker
for federation. Add the provider, map roles/claims to Correlix roles, and
(optionally) require MFA for SSO logins.

## How to create a report
Open Dashboards → Reports → Guided Report Setup: pick the report kind, a schedule
(frequency/time/timezone), the output formats (HTML/Excel/PDF), and the recipients
(contact points or channels). Reports render asynchronously and deliver by email or
a secure link.

## How to connect ITSM (ServiceNow / Jira) and notifications
Under Incident Response → Integrations, connect ServiceNow or Jira; under
Notifications, configure email/Slack/PagerDuty contact points. RCA auto-ticketing
(Incident Response → RCA Auto-Ticketing) files one ticket per correlation by policy.

## What Iris AI can do
Iris AI is an evidence-grounded NOC assistant. It can summarize what's going on
right now, list the actionable incidents, explain a specific incident's RCA, show
flows/telemetry/app or integration health, look up a troubleshooting playbook, and
answer product questions like this one — all scoped to your tenant and cited. Type
`/` for guided commands.
