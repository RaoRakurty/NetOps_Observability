# Application-Experience Correlation (external synthetic → semantic app impact)

Correlix does **external application-experience / Digital-Experience monitoring**,
not APM. It answers *"is this application reachable and healthy from where our
users are?"* by correlating **synthetic checks**, **passive flow**, **app
identity**, and **network/control-plane telemetry** into one grounded,
evidence-backed incident object. It deliberately does **not** do code-level APM in
this phase — no OpenTelemetry trace ingestion, no span storage, no in-process /
bytecode agents, no browser/mobile RUM, no transaction or per-SQL tracing. It
observes applications from the **outside**, then attributes and confirms impact.

## The problem this closes

`collectors/synthetics.go` measures a SaaS/app endpoint from a vantage point
(HTTP/TCP/ICMP; per-phase DNS/TCP/TLS/TTFB/total timings, status code, cert
expiry) and forwards a `ProbeEvent` onto `netops.probes`. Historically that only
became a **generic** `probe_loss` / `probe_rtt_anomaly` PATH signal — good for
network-path correlation, but the application signatures (`sig.ent.app.*`) key on
**semantic** kinds like `synthetic_http_fail`. So an app outage was visible as a
generic probe blip but the app-experience signature path did not light up.

## What was added

A small, additive normalization layer — the generic probe path is unchanged.

- **`src/correlation/synthetic_normalize.py`** — a pure, deterministic normalizer.
  One synthetic outcome → at most one **semantic application-experience Signal**
  whose `kind` an app signature matches, with the original probe kind preserved in
  `raw_kind`. Emits **only on a problem** (healthy check → no signal).
- **`handle_probe` (main.py)** — after the generic probe signals, also emits the
  semantic app-experience signal.
- **`sig.ent.app.saas-experience-degraded`** — a generic app-experience signature
  keyed on the semantic kinds (any app, not app-specific).

### Semantic kinds produced

`synthetic_http_fail`, `synthetic_http_5xx`, `synthetic_http_4xx`,
`synthetic_http_latency_high`, `synthetic_dns_fail`, `synthetic_tcp_connect_fail`,
`synthetic_tls_fail`, `synthetic_cert_expired`, `synthetic_cert_expiring`,
`synthetic_timeout`, `synthetic_icmp_loss`, `synthetic_tcp_probe_fail`.

### Failure reason codes (RCA narrative)

`dns_failure`, `tcp_connect_timeout`, `tcp_connect_refused`,
`tls_handshake_failure`, `certificate_expired`, `certificate_expiring`,
`http_4xx`, `http_5xx`, `http_timeout`, `ttfb_timeout`, `response_timeout`,
`reset_by_peer`, `icmp_unreachable`, `unknown_synthetic_failure`. These let the
narrative say e.g. *"TLS handshake failed before the application responded"* or
*"TCP connection timed out from the Frisco vantage."*

## Application is an ENTITY, not a modality

Modality = *how* something was observed (active_probe / passive_flow /
control_plane / device_telemetry / management_plane). The application is the
**entity** the observation is about (`EntityType.APP` / `SERVICE`). The app name is
resolved generically, in order: explicit synthetic-check **metadata** → **appid**
fusion identity → **host→app map** (`CORR_SAAS_HOST_MAP`, seed defaults included)
→ the **host** itself (honest fallback — never an invented friendly name). There is
no app-specific logic; Microsoft Teams is only a representative fixture.

## Confirmed requires independent corroboration (verdict gate unchanged)

The `≥2 independent modality classes` rule is **not** relaxed:

| Evidence | Verdict |
|---|---|
| Synthetic failure alone (one vantage) | **suspected** (single `active_probe` modality) |
| Two synthetic vantages | still **suspected** (still one modality class) |
| Synthetic + independent **passive-flow** collapse | **confirmed** |
| Synthetic + **LB/app 5xx** (device telemetry) | **confirmed** |
| Synthetic + independent, grounded network/control-plane fault | **confirmed** |

The synthetic + flow / LB signals attach to **one** application-impact object,
which names the affected app.

## Tests / fixtures

- `test_synthetic_app_experience.py` — normalization, probe-only=suspected,
  probe+flow=confirmed, app-agnostic resolution.
- `fixtures/saas-experience-{salesforce,teams,probe-only}-*.json` — CI-gated
  scenarios across apps and both verdict tiers.

## Known gaps / follow-ups

- ~~**Go `ProbeEvent` enrichment (production wiring)**~~ — **done.**
  `synthetics.go` now classifies every failed check into a `fail_class`
  (dns | tls | connect_refused | connect_timeout | timeout | reset | unknown, from
  the httptrace per-phase errors) and forwards `status_code`, `method`, `path`,
  per-phase timings (`dns_ms`/`tcp_connect_ms`/`tls_ms`/`ttfb_ms`/`total_ms`),
  cert fields (`cert_days_to_expiry`/`cert_subject`/`cert_issuer`) and the vantage
  `site_id` (`PROBER_SITE_ID`, optional) on the `ProbeEvent`. All fields are
  `omitempty`: STAMP/ICMP events keep the old wire shape byte-for-byte
  (pinned by `TestProbeEventWireContract`).
- **Full per-app flow attribution:** flow anomalies are per-interface today; app
  entity/token attach is opportunistic (design P2 appid attribution).
- **LB / app 5xx collector coverage:** `lb_5xx` / `app_error_rate_high` arrive via
  cloud logs today; an on-prem LB/app metrics collector would broaden confirmation.
- **SaaS provider status-page ingestion:** not present; a candidate corroborating
  modality (provider-reported degradation) for a future phase.
