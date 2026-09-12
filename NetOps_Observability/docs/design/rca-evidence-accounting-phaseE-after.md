# Phase E — P-027379 regenerated: after-state + visual inspection findings

Closes the evidence-accounting epic (plan: `rca-evidence-accounting-plan.md`;
before-state: `rca-evidence-accounting-phaseA-audit.md`). The regenerated
P-027379 was rendered to PDF (Gotenberg sidecar), every page rasterized and
visually inspected on 2026-07-16.

**Regenerate at any time:**
```bash
cd src/backend
RCA_EMIT_P027379=/tmp/p027379.html go test -run TestEmitP027379HTML -v .
# → HTML + the after-tables below on stdout; convert via the stack's
#   gotenberg sidecar (REPORT_PDF_SIDECAR_URL) for the paginated PDF.
```

## After — evidence accounting (was: 4 vs 6 observers, api-as-vantage, unreconciled 124/127/147/8/7/4)

- Evidence groups: 4
- Logical vantages: lan-vantage-1
- Control-plane sources: ipsec:lab-vpn-edge
- Collectors (not vantages): api
- Unclassified sources: prober (kind not established; never counted as a vantage)
- Independent confirming sources: 2 (ipsec:lab-vpn-edge, lan-vantage-1)
- Configured tests: Unavailable — configured-test inventory not stored for this case
- Test executions: Unavailable — per-execution lineage not joined at the report layer

Reconciliation ladder (renders on the report, operator detail):
147 window → 8 case-linked → 7 anomalous → 4 groups → 4 observers →
3 independence groups → 2 independent sources → 4 confidence-eligible →
2 impact-eligible classes → 4 recovery observations.

## After — coverage (was: 19s routing = "Available/Full", gapped lanes = "Normal")

| Lane | Quality | State | Ratio | Leading | Trailing | Impact-elig |
|---|---|---|---|---|---|---|
| Device health | substantial | inconclusive | 83% | 1m 58s | – | false |
| Routing & link events | point_in_time | anomalous | – | – | – | true |
| Traffic flow | substantial | inconclusive | 89% | 17s | 1m 03s | false |
| Active checks | complete | anomalous | 98% | 13s | – | true |

Impact: overall=detected · synthetic=confirmed · real-user=**not_observable**
(the false "none detected" is dead) · quality gate: **passed**, full
"Incident Analysis — Fault Confirmed" (not draft).

## Visual inspection findings (2 defects found on the rendered pages → fixed same day)

1. **"Affected vantages: api, lan-vantage-1, prober"** survived in the NOC
   quick read and Signal measurements — contradicting the accounting block
   (api = collector, prober = unclassified). Both rows renamed **"Reporting
   sources"**; the classified vantage/collector/unknown split remains the
   accounting block's job. Regression-pinned in
   `TestPhaseE_P027379Regeneration` (no "Affected vantages" label anywhere).
2. **Test executions rendered its Unavailable reason twice** with a dangling
   "failed" (template compared against bare `"Unavailable"`, missing the
   reason-suffixed form). Fixed via `FailedExecutionsBrief` (set only when the
   count is real); reason now renders once. Regression-pinned (reason string
   counted ≤ 1 in the document).

Accepted as-is after inspection (recorded, no change): per-field "predates the
accounting model" disclosure instead of a single legacy banner; expected
cadence drives the math but is not a visible table column; near-empty page 2
(pagination keeps sections unsplit); "not observable"/"not confirmed because
relevant real-traffic telemetry was insufficient" as the spec's "Not confirmed
(insufficient telemetry)" wording.
