# Golden examples

Representative Iris AI answers — the expected *shape* of each answer-mode
card. The eval suite (`docs/ai/evals.md`) enforces the invariants behind these.
All are grounded, tenant-scoped, and honest about gaps.

## `/status` — current_state_summary

```
Current Operations Summary
Correlix sees 25 active correlation groups — 0 confirmed, 2 suspected, 23 undetermined.

Recommended focus  ISP / DIA egress latency (suspected, 100%)
Why first          classified RCA · suspected · clear ownership domain
Watch items        23 low-evidence correlations under investigation
Most impacted      wan-r2, leaf1, leaf2
Next actions       1. Validate the DIA loss/latency window …
Badges             Suspected
```

## `/explain P-XXXXXX` — problem_explanation (with an evidence gap)

```
RCA  P-628EA6
ISP / DIA egress latency — suspected (Confidence: Candidate)
Summary       Probe loss on the DIA egress corroborates a provider-side …  [problem:…]
Missing evidence  • OSPF adjacency-change evidence not found
Recommended owner  Network / Provider team, pending confirmation
Next actions  1. Confirm the loss window on the provider-facing interface …
Badges        Suspected · Missing evidence
```

## `/playbook bgp flap` — investigation_plan (Network Expert KB)

```
Network Expert Knowledge   [Guidance]
Curated guidance for: BGP Adjacency / Session Flap — general best-practice,
not live evidence about your network. Verify against Correlix evidence.
• BGP Adjacency / Session Flap (owner: Network / Routing) …
Recommended owner  Network / Routing
Next actions  1. Establish the flap cadence from the transition counter …
Citations  [playbook:bgp-adjacency-flap]
```

## Evidence-only fallback (provider down)

Same structured card, `Provider: none`, badge **Evidence-only mode** — the
narrative is the deterministic summary, never a raw "provider unavailable" line.

## Verified answer

When the model invents a citation, it's stripped and the card shows a **Verified**
badge + "1 unsupported reference removed (not in the evidence)."
