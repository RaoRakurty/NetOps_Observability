# Golden-wire fixtures & the confirmability audit

Two honesty mechanisms added after the #98 postmortem (the synthetic
app-experience gap: collectors observed HTTP/TLS/DNS failures for weeks while
the app signatures' kinds went unemitted). Together they enforce the full
verified path:

```
real collector output → normalizer → semantic kind → entity grounding
   → signature match → independent corroboration → expected verdict
```

## Why hand-authored Signal fixtures are not enough

The per-signature fixtures (`fixtures/*.json`, `test_fixtures.py`) start from
perfect, hand-built `Signal` objects. They validate the **catalog** — but they
silently assume the raw-event→signal boundary works, and that boundary is
exactly where #98 hid. A signature can be "covered" on paper while no real
event can ever reach it.

## Golden-wire fixtures (`fixtures/golden_wire/`, `golden_wire.py`, `test_golden_wire.py`)

Golden fixtures are **raw wire shapes**: the exact JSON `collectors/
probe_events.go` puts on `netops.probes` (enriched ProbeEvent), and raw
goflow2-shaped flow records. The replay helper
(`replay_fixture_through_engine`) drives them through the SAME functions
production runs — `producers.probe_signals`, `synthetic_normalize.
synthetic_app_signal`, `producers.flow_sample` — then `engine.run_window` and
the verdict gate. Nothing is mocked at the contract boundary.

Honesty rule for the flow lane: production only produces `flow_volume_anomaly`
through the CUSUM episode detector over many cycles, so a fixture can't
"be" an anomaly. The replay runs the real parsing/grounding boundary and then
constructs the anomaly signal those fields would yield when the detector fires
(`attrs.detection_assumed = true`). Detection math is covered by the episode
tests; golden-wire proves the **grounding truth** — which today is
`entity_type=interface`, **no app token** (the Phase 4 gap, asserted in
`test_golden_synthetic_teams_plus_interface_flow_documents_attribution_gap`).

### Adding a new golden fixture

1. Capture (or author) the raw wire event exactly as the collector emits it.
2. Drop it in `fixtures/golden_wire/<lane>_<scenario>.json` with `tenant`,
   optional `env` (e.g. `CORR_SAAS_HOST_MAP` for customer app mappings), and an
   `expect` block.
3. Assert what production DOES, not what it should do — if there is a gap,
   assert the gap and name the phase that closes it.

## Confirmability audit (`confirmability.py`, `test_confirmability.py`)

For every enabled signature: which required/optional kinds have real
producers, which modality classes those producers supply, and therefore the
**maximum verdict the signature can reach today**. It never weakens the
engine's gate (≥ 2 independent modality classes to confirm; `required_
modalities` caps); it reports it.

Statuses:

| status | meaning |
|---|---|
| `confirmable_now` | matchable and ≥2 independent modality classes reach its entity — demo-ready |
| `suspected_only` | matchable but only one modality class exists |
| `entity_mismatch` | a 2nd modality exists **but cannot ground on the signature's entity** (e.g. flow anomalies are interface-grounded, app signatures need app grounding) |
| `modality_mismatch` | matches, but a `required_modalities` demand has no producer path → verdict capped |
| `normalization_pending` | required kind unemitted; phenomenon IS observed (fix the normalizer) |
| `collection_pending` | required kind unemitted; nothing observes it (build the collector) |
| `not_matchable` | a required clause has no emitted kind and no declared gap |

`python3 confirmability.py` writes `build/reports/signature_confirmability.
{json,md}` (per-signature table + producer↔signature reconciliation table).

### The P0 gate

`test_p0_signatures_are_confirmable`: every **matchable** p0 signature must be
`confirmable_now` or carry a structured entry in
`DEMO_CONFIRMABILITY_EXCEPTIONS` (reason, owner, date, target_resolution).
Unmatchable p0s are governed by the coverage ledgers (the catalog deliberately
leads ingestion — see `coverage.py`). Exceptions are temporary:
`test_exceptions_are_not_stale` deletes-or-fails them the moment the signature
becomes confirmable.

Current state (2026-07-09): 14 signatures confirmable now; 2 matchable p0s
excepted — `sig.ent.app.saas-experience-degraded` (entity_mismatch → Phase 4
per-app flow attribution / Phase 5 LB lane) and
`sig.ent.fabric.spine-leaf-path-degradation` (modality_mismatch → the
`if_errors`/`if_crc` normalization gap, #73).

## Why probe-only evidence never confirms

Every modality class has a documented blind spot; a single vantage's synthetic
failures — however many semantic kinds one raw check produces — are ONE
observation in ONE modality class. Confirmation requires an independent
witness class grounded on the same entity (verdicts.py). Teams is only a
fixture in all of this: the normalizer, grounding, and signatures are
app-agnostic (metadata → appid → customer host map → honest host fallback).
