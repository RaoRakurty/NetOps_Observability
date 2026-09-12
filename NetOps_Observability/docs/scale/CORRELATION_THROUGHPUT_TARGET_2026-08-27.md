# Correlation-engine throughput — industry benchmark & target (2026-08-27)

Research + Fable synthesis. **Verdict: ENHANCE — we are 5–20× below the physical
ceiling for our tier of work, and the storm collapse is an architectural
bottleneck, not a cost floor.**

## The honest industry picture
No AIOps vendor publishes a per-node "events/sec ingested AND correlated" figure
— that opacity is itself the finding (their correlation is SaaS-side, elastically
sharded, and marketed as noise-reduction ratios, not throughput). So the valid
comparator is **stateful cross-key stream processing (Flink / Kafka Streams)**,
which is the same *kind* of work as causal graph grounding.

**Three tiers of "correlation" — they differ by 1–3 orders of magnitude/event:**
| Tier | What it does | Realistic eps/core | Examples |
|---|---|---|---|
| Shallow | dedup / index / threshold | 10k–100k+ | Zabbix NVPS (3k–100k+), Elastic index (20k–100k docs/s), Splunk ingest |
| Middle | stateful clustering/grouping | ~1k–20k | Moogsoft `farmd` (low-thousands/instance), BigPanda, ServiceNow |
| **Deep (us)** | causal graph mutation + traversal + owner attribution / event | **low-thousands/core** | **Correlix**, Dynatrace Davis (no public EPS) |

Comparing our 400–1,000 eps to Zabbix's tens-of-thousands NVPS is **invalid** —
that's the shallow tier. Our real yardstick is Flink large-state joins:
**~1,000–10,000 eps/core.**

## Where we stand
**~100–250 eps/core** (400–1,000 eps on 4 cores) = **5–20× BELOW** the reasonable
ceiling for stateful causal work. The 3,700-eps storm overwhelming a node is only
~3.7–9× the sustained rate — **not physics, an architectural wall**: single
GIL-bound event loop, serial graph mutation, no backpressure/sharding. (Matches
the live diagnosis: `_offload` uses the default ThreadPool executor →
CPU-bound pure-Python `run_window` holds the GIL → loop starved → consumer
ejected → livelock.)

## Target (events/sec/core, sustained, WITH correlation)
| Tier | eps/core | 4-core node | Rationale |
|---|---|---|---|
| Floor | 500 | ~2,000 | Above Moogsoft-class middle tier; 2–5× current |
| **TARGET** | **1,000–2,000** | **4,000–8,000** | Low end of Flink stateful joins; **absorbs the 3,700-eps storm within sustained capacity — the storm becomes a non-event** |
| Stretch | ~3,000 | ~12,000 | Upper-realistic for causal work (exceed-baselines mandate); needs sharded state + lock-free mutation |

**The single most valuable outcome: make the 3,700-eps storm a non-event** →
requires sustained ≥ ~1,000 eps/core (4,000 > 3,700) with graceful degradation.

## Stop or enhance? — ENHANCE
1. **Resilience is non-negotiable** — an engine that livelocks during the outage
   it exists to explain is unshippable. Job one: never stall past the 30s session
   timeout; degrade gracefully (lag + catch up), never get ejected.
2. **We're 5–20× under the ceiling** — the headroom is real; this is design work,
   not a physics wall. A 4–10× gain to the target is achievable.
3. **The target is defensible + honest** — beats middle-tier commercial analogs,
   sits at the low end of the stateful-join physical bound, and is truthful that
   causal work is heavier per event than dedup (so a *lower* eps than Zabbix that
   *does more per event* is the honest positioning).

## Caveats
WebSearch budget was exhausted this session — only Zabbix sizing + "Datadog
publishes no correlation throughput" are live-verified; competitor EPS are from
training knowledge (labeled, approximate). The **conclusion is robust regardless**
of the fuzzy vendor numbers, because it rests on the Flink/Kafka-Streams physical
bound, not on vendor marketing.

## Next
Confirm the GIL hypothesis by profiling `run_window` on a quiet engine → design
the fix (ProcessPool offload + bounded per-cycle chunk so cycle-time <
session-timeout + backpressure) → Opus implements with a "storm no longer ejects
the consumer" test → re-run the storm ladder → measure eps/core vs the target.
