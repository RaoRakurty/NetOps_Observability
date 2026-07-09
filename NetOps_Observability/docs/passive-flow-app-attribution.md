# Passive-flow application attribution (#98 Phase 4)

How a passive flow anomaly earns the right to corroborate an application
outage — bounded, evidence-first, never overclaimed.

## The problem

Flow anomalies ground on the exporting interface (`<sampler>:if<N>`), which is
correct for network RCA and useless for application RCA: an application-impact
object grounds on the app entity (`app:microsoft_teams`), and evidence that
cannot reach that entity cannot confirm it. Before this phase, synthetic +
flow could never confirm an app outage in production.

## Attribution sources (strict priority)

| level | source | confidence | mechanism |
|---|---|---|---|
| 1 | `explicit_config` | high | the flow record itself carries `app_name`/`app`/`application`/`service_name` (e.g. IPFIX appId, exporter-stamped apps) |
| 2 | `appid_fusion` | high (`authoritative` band) / medium (`corroborated`) / low (else) | destination IP joins a recent fused identity from the #81 appid lane — `handle_app_identity` maintains a **tenant-scoped, TTL'd, size-capped** `dst_ip → app` index (`CORR_APPID_INDEX_TTL_S`, default 1 h; `CORR_APPID_INDEX_MAX`) |
| 3 | hostname / SNI mapping | — | **not applicable to NetFlow** (no names on the wire); DNS/SNI flow enrichment is future work |
| 4 | `prefix_mapping` | medium | operator-defined CIDR→app catalog: `CORR_APP_PREFIX_MAP="52.113.0.0/16=Microsoft Teams,10.8.0.0/16=acme_orders"`. Customer-defined only — deliberately **not** a public SaaS IP feed |
| 5 | none | — | the flow stays infrastructure-grounded; no app token, ever |

Only **high/medium** attribution creates app-grounded evidence
(`CONFIRMING_CONFIDENCE`); `low` never helps confirm.

## What changes on the wire of signals

One attributed flow feeds **two** volume series (`main.handle_flow` /
`_flush_flow_aggregator`):

- the existing per-interface series — untouched, network RCA keeps working;
- a per-`(tenant, app)` series → CUSUM → a `flow_volume_anomaly` signal with
  `entity_type=app`, `entity_id=<slug>`, tokens `(<slug>, app:<slug>,
  <sampler>)`, and `attrs.attribution_source` / `attrs.attribution_confidence`.

Same canonical kind — **no new vocabulary**; app-impact signatures already
consume `flow_volume_anomaly`, and grounding decides which object it reaches.

## Protections (all CI-tested, `test_flow_app_attribution.py`)

- **No fake attribution**: unknown app → interface grounding only.
- **Cross-app**: a Salesforce-attributed flow never confirms a Teams object
  (token grounding — different apps never co-locate).
- **Cross-tenant**: the identity index is keyed by tenant; lookups are
  structurally incapable of crossing it, and engine objects are per-tenant.
- **Time-window**: identities expire (TTL) — yesterday's identity cannot
  attribute today's flows; the engine's window logic bounds attachment.
- **Verdict**: flow-only or synthetic-only stays unconfirmed; probe + app-
  grounded flow = two independent modality classes on one app object →
  confirmed (`verdicts.assess`, unchanged).

## Verdict outcomes

| evidence | verdict |
|---|---|
| Teams synthetic failure alone | suspected |
| Teams synthetic + Teams-attributed flow drop | **confirmed** |
| Teams synthetic + unattributed interface flow drop | suspected (flow supports network RCA instead) |
| Teams synthetic + Salesforce-attributed flow drop | suspected — no attachment |
| Teams synthetic (tenant A) + Teams flow (tenant B) | suspected — never attaches |

## Remaining future work

- DNS/SNI-based flow attribution (level 3) — needs name-aware flow enrichment.
- appid fusion beyond dst-IP joins (five-tuple/session correlation).
- Site-level tokens on flow evidence (exporter→site mapping).
