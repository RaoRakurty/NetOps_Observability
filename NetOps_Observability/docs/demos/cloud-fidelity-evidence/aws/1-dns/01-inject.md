# AWS — DNS fault family / Route 53  (scenario `DAWS1`)

DNS is a **first-class multi-case family** (owner requirement). Run the
applicable cases below in sub-order **1a → 1c → 1b → 1d**, each revert-verified,
≥20 min soak. Exact commands: **`../../RUNBOOK.md`** → "Scenario 1 — DNS fault
family" (AWS — Route 53 block). Every case asserts BOTH
the `cloud_dns_log` signal AND that the paired change event
(CloudTrail `ChangeResourceRecordSets` → `cloud_change`) correlates.

> **TTL / propagation:** records are TTL≤60s. Soak ≥ 2×TTL + query-log delivery
> lag before capturing and again before declaring revert (see RUNBOOK §1e).

## Per-case log (fill each you run)

### 1a — NXDOMAIN burst (client-side)
- Inject cmd: ``  · Revert: none  · Inject @ ___ UTC / signal @ ___
- `cloud_dns_log` NXDOMAIN spike seen? [ ]   joins app symptom? [ ]
- Shots: 03-signal [ ]  04-rca [ ]  05-recovery [ ]

### 1c — Record misdirection (resolves, wrong target)
- Inject cmd: ``  · Revert cmd: ``  · Inject @ ___ / revert @ ___
- `cloud_dns_log` wrong-answer + app unreachable? [ ]   `cloud_change` correlated? [ ]
- Shots: 03 [ ]  04 [ ]  05 [ ]

### 1b — Record deletion / blackhole
- Inject cmd: ``  · Revert cmd: ``  · Inject @ ___ / revert @ ___
- `cloud_dns_log` resolution-fail spike? [ ]   RCA names the record? [ ]   `cloud_change` correlated? [ ]
- Shots: 03 [ ]  04 [ ]  05 [ ]

### 1d — Health-check failover flip
- Applicability (AWS): ad-hoc setup (module ships 1 alias, no failover pair) — or GAP + IaC extension
- Result / gap note: 

## Expected lane
- **Kind:** `cloud_dns_log` (+ paired `cloud_change`)
- **Log Search:** `cloud_dns_log AND (rcode:NXDOMAIN OR response:SERVFAIL)` and `cloud_change AND service:dns`

## Observed result / gaps
<!-- record any absent lane as a GAP with the reason; do NOT fabricate -->
