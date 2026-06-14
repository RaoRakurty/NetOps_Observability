# Verification Report — Correlation Engine v2, P3a (Probe Authority)

**Milestone tag:** `correlation-v2-p3a-probe-authority-verified`
**Date:** 2026-06-14
**Commits:** `2889dff` (P3a model/gate) · `91b1fd4` (inspector legibility)
**Engine pins (live):** engine `2.0.0+cfg.64baf13aa8c5` · catalog `cat-2a03b5d0d1a0`
**Design:** `docs/design/probe-authority-model.md` (research-validated:
owner research + deep-research `wf_003e5c54-216`, both converge)

This freezes a **known-good, conservative-and-safe** baseline. Per owner
direction: **do not tune verdicts further right now.**

---

## 1. Verdict gate — proven by tests (deterministic, re-runnable)

`cd src/correlation && python3 -m pytest -q` → **125 passed**, mypy + ruff clean.

The load-bearing guards (`test_verdicts.py`):
| Guarantee | Test |
|---|---|
| probe-only never confirms | `test_probe_only_never_confirms` |
| low-authority probe supports but can't confirm | `test_low_authority_probe_cannot_confirm_only_supports` |
| debug_only/lab probes excluded entirely | `test_debug_only_probe_is_excluded_entirely` |
| fate-shared evidence can't confirm + collapses to 1 observer | `test_fate_shared_probe_and_modality_cannot_confirm`, `test_fate_shared_probes_collapse_to_one_observer` |
| positive control: high-auth probe + independent modality confirms | `test_high_probe_plus_independent_modality_confirms` |

Re-run just the gate proof:
```
python3 -m pytest test_verdicts.py -k "probe_only or debug_only or low_authority or fate_shared or high_probe" -v
```

## 2. Ingestion classification — live

Synthetic lab probers are classified and excluded from customer-facing verdicts.
Last 30 min: **21/21 probe signals classified** `synthetic_lab_probe / debug_only`
(0 unclassified leaking). Log sample:
```
probe signal probe_loss: prober->nginx … scope=synthetic_lab_probe auth=debug_only
```

## 3. Live behavior — suspected → undetermined transition (end-to-end)

Background poller after the P3a deploy (probe-only objects lose their excluded
debug evidence as the window refills):
```
16:57  classified=3 unclassified=0 | suspected=4 undetermined=3   ← transition
16:59  classified=3 unclassified=0 | suspected=0 undetermined=1   ← flipped
17:01  SETTLED — suspected=0 undetermined=1
```
Synthetic probe-only objects correctly settle to **undetermined** (excluded),
never suspected/confirmed off synthetic evidence.

## 4. Zero confirmed objects (the safety invariant)

All objects ever built under catalog `cat-2a03b5d0d1a0`:
| verdict | count |
|---|---|
| undetermined | 50 |
| suspected | 319 |
| **confirmed** | **0** |

No probe-only / synthetic / low-authority / fate-shared evidence has manufactured
a confirmed verdict. The original "#7" risk is not materializing.

## 5. The engine moves beyond "safe undetermined" on REAL evidence

Real signatures are firing — the engine produces actionable `suspected` RCA when
valid evidence exists. Live example (`sig.ent.access.local-link-fault`, suspected):
```
cid: 2caa89bc-f12c-573b-83f6-e83021ee635b  v9  suspected  2 nodes / 2 signals
evidence_missing:
  · needs link_state_change
  · single modality class (device_telemetry); need ≥2
  · single observer (lan-sw2); need ≥2
  · required modality missing (no trusted witness): control_plane
```
i.e. a device-telemetry interface anomaly on `lan-sw2` matched the local-link-fault
signature → **suspected**, with an honest, specific list of exactly what would
confirm it (a control-plane link-state event from a second observer). This is the
target behavior: real evidence → actionable suspected, not blanket undetermined.

> A UI screenshot of this object (Operator View) should be attached by the owner.

## 6. Parked / next (not in this milestone)

- **P3c** — real probe Registry / binding (registry-sourced classification
  replaces inference; `classification_source=registry`).
- **P3d** — richer fate-sharing fingerprint (container ns / collector / underlay
  path hash).
- **P4** — replay-driven calibration (no quantitative accuracy claims before).
- **UI enhancements** — Operator-View contrast, display-name/entity-label layer
  (hide infra names + raw IDs + signature IDs in Operator View), triage
  badges/columns (quality / planes / grounding / authority / owner), recommended
  next action, stronger evidence cards. In progress; not part of the verdict
  contract.
- **Demo fault** — controlled local-link / BGP / DIA fault injection to drive a
  `confirmed` (owner-run device fault or synthetic injection).
