# Path Behavior Health — adaptive, baseline-relative path scoring

Status: **DESIGN (owner-specified 2026-06-15) — MVP in build** · Surfaces: Go API + React
Related: `front-page.md` (#69 — health score §4; PBH supplies the latency/jitter/loss
signal classes for path scopes + panel 7 Hot paths), `correlation-engine.md` (#67 — the
engine detects probe *episodes*; PBH is the steady-state score), `cloud-ingestion.md`
(#68 — seams supply owner-of-fix), memory `netops-observability-boards-active-measurement`.

---

## 0. The question it answers

> **"Is this path behaving normally right now, compared to its own expected behavior?"**

Not "is latency > 80 ms" — 80 ms is normal for one path and severe for another. The score
is **baseline-relative percentile distance**, carries **confidence**, and feeds **owner-of-fix**.
Detection alone is commodity; *detection + path evidence + owner-of-fix* is the differentiator.

## 1. Honest telemetry reality (what we can build on TODAY)

| Spec input | Emitted today? | MVP decision |
|---|---|---|
| latency (`probe_rtt_ms`, `probe_owd_ms`, `synthetic_icmp_rtt_ms`) | ✅ `{probe,dst}` / `{check,dst}` | use directly |
| jitter / PDV (`probe_pdv_ms`) | ✅ `{probe,dst}` | use directly |
| loss (`probe_loss_pct`, `synthetic_icmp_loss_pct`) | ✅ | use directly; burstiness = short-window variance (computable) |
| retransmits, ECN, queue-drops | ❌ not emitted | **omit** (documented gap); loss = loss% + burstiness only |
| direction (up/down) | ❌ probes are one-way (prober→dst) | single direction in MVP; direction-aware = V1 when bidir probes exist |
| provider / ASN | ❌ no label | tier-1 baseline (route/provider) **deferred**; cascade starts at per-path |
| route fingerprint (AS-path/hop hash) | ❌ (traceroute exists but dormant `FEATURE_TRACEROUTE`) | route-fingerprint baseline + route-change confidence = V1 (wire from traceroute/seam) |
| hour-of-week | derivable, but VM can't bucket natively | **deferred** to V1 (needs precompute / recording rules) |

**Rule honored:** *do not block the page on baseline data we don't have.* Ship the cascade
with the tiers we can compute live, label confidence, auto-upgrade as tiers light up.

## 2. Path identity (MVP)

`path_id = "<probe|check>:<dst>"` (e.g. `stamp:10.70.245.120:8620`). This is the only stable
path key the telemetry gives us now. The richer fingerprint
(`src_site·dst_service·dst_region·cloud·ASN·underlay·route·direction·traffic_class·hour_of_week`)
is the V1/V2 target — added as labels/enrichment land (cloud-ingestion #68, traceroute, SoT).

## 3. Severity model (per signal → badness)

Short-window current value is **`p95` over the last 5 min**, never a single raw sample
(one spike must not alarm).

```
latency_severity = clamp((cur_latency_p95_5m − base_lat_p50) / (base_lat_p99 − base_lat_p50), 0, 2)
jitter_severity  = clamp((cur_jitter_p95_5m  − base_jit_p50) / (base_jit_p99 − base_jit_p50), 0, 2)
loss_severity    = clamp( log(1 + loss%/0.1)/log(1 + 100/0.1) + 0.3·burstiness, 0, 2)   # log-scale; loss is non-linear in pain
route_instability_severity = 0  in MVP (no route data) — EXCLUDED from the blend, not counted as 0-healthy
```

Degenerate baseline guard: if `p99 ≤ p50` (flat/insufficient), that signal contributes **no
severity** and is excluded (never divide-by-zero, never fabricate).

### 3.1 Combine — weighted blend with an anti-averaging floor

```
blend = max( Σ wᵢ·sevᵢ / Σ wᵢ ,  0.8 · max(sevᵢ) )      # over AVAILABLE signals only
score = blend                                            # 0 = normal … >1 = worse than historical-bad
```

Weights renormalize over **available** signals — a missing signal (e.g. route instability) is
dropped, NOT scored 0 (absence ≠ healthy; scoring it 0 would dilute a real problem). The
`0.8·max` floor stops one severe dimension being averaged away (front-page §4 principle).

Default **enterprise** weights: loss 0.40 · latency 0.25 · jitter 0.20 · route 0.10 · confidence 0.05.
**AI/GPU-sensitive** path weights: loss/drops/retrans 0.45 · jitter/microburst 0.25 · latency 0.15 ·
congestion 0.10 · route 0.05 (loss/jitter dominate — inference/RAG/agent flows feel loss + microbursts
more than steady latency). Path traffic-class → weight profile is a lookup; MVP defaults to enterprise
(no traffic-class label yet).

### 3.2 Health bands

`0.00–0.40 Healthy · 0.40–0.75 Watch · 0.75–1.00 Degraded · >1.00 Severe`.

## 4. Baseline-source priority cascade (the key decision)

Pick the **strongest tier with sufficient data**; always surface which tier was used.

| # | Tier | Condition | UI wording |
|---|---|---|---|
| 1 | path + direction + hour-of-week + route/provider | rich labels present + samples | "Compared with this path's normal behavior" |
| 2 | path + direction + hour-of-week | hour-bucket has samples | "Compared with this path at this time of week" |
| 3 | path + direction (all-time) | per-path ready (≥500 samples **or** ≥7 days) | "Compared with this path's normal behavior" |
| 4 | class fallback (Branch→SaaS / →cloud / →DC / ISP transit / VPN-SDWAN / cloud inter-region / edge-inference) | new/sparse path | "Compared with similar &lt;class&gt; paths" |
| 5 | conservative global fallback | nothing else | "New path — using fallback baseline" |

**MVP ships tiers 3 / 4 / 5** (per-path live percentiles via VM `quantile_over_time`, class
default table, global default). Tiers 1–2 (route/provider, hour-of-week) are V1 as those
labels/precompute land. Class table is small + conservative, keyed by a coarse path class we can
infer now (probe type + dst shape); honest "we don't know the class" → global fallback.

## 5. Confidence (every score carries it)

| Confidence | Rule |
|---|---|
| Low | < 3 days **or** < 100 samples, **or** fallback baseline (tier 4–5) |
| Medium-low | 3–10 days |
| Medium | 10–21 days |
| High | 21+ days **and** stable route **and** probe not sparse |

Reducers (drop one level): recent route change · sparse/missing probe · different ISP/ASN than
baseline. A score without confidence misleads the NOC — confidence is never optional.

## 6. Owner-of-fix (fault domain)

Output one of: `customer_lan · branch_edge_sdwan · isp_carrier · cloud_provider_edge ·
saas_provider · insufficient_evidence`. **MVP = `insufficient_evidence`** for end-to-end probes
with no segment evidence (honest). Upgrades as evidence arrives: traceroute hop/segment deltas,
the #67 correlation object's seam grounding (`control_plane_owner` already maps to owner-of-fix),
and "no branch-edge CPU/mem saturation" negative evidence. This is the differentiator — wired to
the seam model rather than guessed.

## 7. API shape (UI-friendly — numbers AND explanation)

`GET /api/paths/health` (list, worst-first) · `GET /api/paths/health?path_id=…` (one).
Tenant-scoped (org_id / RLS-consistent with the rest). Example item:

```json
{
  "path_id": "stamp:edge→azure-eastus", "health_state": "degraded", "score": 0.86,
  "confidence": "high",
  "baseline": { "source": "path", "source_label": "this path's normal behavior",
                "window": "21d", "sample_count": 18240,
                "latency_p50": 35, "latency_p99": 90, "jitter_p50": 4, "jitter_p99": 28 },
  "current": { "latency_p95_5m": 82, "jitter_p95_5m": 22, "loss_pct_5m": 0.4 },
  "severities": { "latency": 0.84, "jitter": 0.75, "loss": 0.18, "route": null },
  "reason": "Latency and jitter are elevated compared to this path's normal baseline.",
  "likely_fault_domain": "insufficient_evidence",
  "evidence": ["Latency p95 (82 ms) near this path's historical bad range (90 ms)",
               "Jitter elevated vs typical 4 ms"]
}
```

## 8. NOC wording (never backend jargon)

Show: Health state · Confidence · Current vs typical range · Bad range · Reason sentence · Likely
owner · Evidence · Baseline type. **Never** show "percentile distance", "p99 normalization",
"route fingerprint hash", "cross-plane cascade". Use: *compared to normal · typical range · bad
range · path changed · likely owner · upstream issue · provider handoff · cloud edge · "new path —
using fallback baseline" · "route changed recently, confidence reduced"*.

## 9. Data model

MVP computes baselines **live from VM** (`quantile_over_time(m[window])`) — no precompute tables
needed for tiers 3–5, which keeps the page un-blocked. V1 adds precompute for hour-of-week/route
tiers and snapshot history:

- `path_baselines` (org_id, path_id, metric, direction, hour_of_week, provider_asn,
  route_fingerprint, traffic_class, window, sample_count, p50/p90/p95/p99, confidence, ts) — V1 precompute.
- `path_health_snapshots` (org_id, path_id, ts, latency/jitter/loss/route severities, combined_score,
  health_state, confidence, baseline_source, explanation, likely_fault_domain, evidence_json) — V1 history.
- `path_route_fingerprints` (org_id, path_id, observed_at, provider_asn, as_path_hash, hop_hash,
  cloud_edge_region, route_changed, previous_fingerprint_id) — V1, fed by traceroute/seam.

All RLS + org_id, same isolation discipline as every tenant table.

## 10. Guardrails

No black-box score (every score explains itself) · no AI confidence without evidence · never
Severe from one raw spike (5-min p95) · never compare a new route against an old route at high
confidence · no global threshold for all paths · don't overfit baselines with too few samples
(readiness gates) · never hide why the score changed.

## 11. Phasing

**MVP (now):** pure scoring core (severity curves · weighted blend + floor · bands · confidence
rules · baseline-cascade selection · explanation + fault-domain strings), fully unit-tested
(normal/degraded/severe/new-path-fallback/low-sample/route-change/jitter-only/loss-dominant);
`GET /api/paths/health` reading per-path VM percentiles (tier 3) + class/global fallback (tiers
4–5); NetworkPath/Hot-paths UI shows state·confidence·ranges·reason·owner·evidence·baseline-type.

**Strong V1:** hour-of-week + direction + route-fingerprint + provider/ASN baselines (tiers 1–2),
route-change confidence reduction, precompute tables, snapshot history, richer explanations.

**Differentiated V2:** AI-flow classification (LLM API / RAG / model-gateway / inference-edge /
GPU-RDMA where visible) + AI Flow Impact panel ("38% of degraded sessions touched the Azure OpenAI
endpoint; degradation is upstream-heavy"). Path-role baselines (user→edge, edge→cloud, cloud→cloud,
model→tool, agent→agent) for the 2027–2033 AI-traffic shift.

## 12. Acceptance criteria

Stable path → own baseline · new path → class/global fallback + Low confidence · route change →
confidence reduced or baseline split · score explains the change · UI hides math terms · NOC can
answer: is it bad? · compared to what? · how confident? · who owns the fix? · what's the evidence?
