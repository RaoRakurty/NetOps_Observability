# Directed Topology for Causal Direction (the C7 unblock)

**Status:** design / decision-of-record (2026-06-23). Research-backed; supersedes the
tier-inference heuristic floated in the C7 re-audit. Owner endorsed "research-backed
methodology." Implementation is sequenced into tested increments (bottom of doc).

## Problem (from the C7 re-audit)

Causal direction (§4.3) claims `A→B` only when ≥2 of 3 votes agree: **(1) onset order**,
**(2) topology up/down**, **(3) OSI layer**. Vote #2 **abstains** today because the engine
has only **undirected** adjacency (`TopologyAdjacency` = unordered pairs) and **ownership-
boundary** seams. So same-layer cross-device pairs (fabric flaps — where vote #3 also
abstains) are left with only onset → never reach the 2-vote bar (~46% of live edges are
`direction_basis="none"`). We need a **directed** traffic-path topology.

## Research finding that drives the design

The market leaders all derive causal direction from a graph whose edges are **directed by
observation or measurement — never inferred from undirected wiring**:
- **Dynatrace Davis** — fault-tree over a *directed dependency graph* (Smartscape: service→
  process→host), edges observed from instrumentation.
- **ThousandEyes** — *directed active paths* (hop-by-hop traceroute) + routing topology
  (the "% Routes" BGP heuristic).
- **NetBrain** — doesn't use topology direction (reasons from resolution history).

Each uses **one** direction source. **Decision: we fuse three**, observed-over-inferred,
with confidence + honest abstention. That fusion is the differentiator.

## Architecture — the DirectedTopology oracle

A source-agnostic evidence layer with one question:

```
orient(a, b) -> Orientation{ verdict, confidence, source }
   verdict ∈ { A_UPSTREAM (a→b), B_UPSTREAM (b→a), AMBIGUOUS, UNKNOWN }
```

- **UNKNOWN** = no source covers this pair → vote #2 abstains (today's behavior; safe).
- **AMBIGUOUS** = a source sees balanced/bidirectional traffic, OR top sources conflict →
  abstain (the owner's key point: traffic flows both ways; we never assume one).
- **A_UPSTREAM / B_UPSTREAM** = a confident directed answer → vote #2 fires that way.

**Sources, in precedence order (measured beats inferred — the research principle):**

| Prec | Source | Direction signal | Best for | Confidence |
|------|--------|------------------|----------|------------|
| 1 | **Active path trace** (traceroute directed hops; STAMP/probe paths) | the *measured* forwarding path, hop order = direction | low-volume / any probed path | highest |
| 2 | **NetFlow observed direction** | `src→dst` + `in_if→out_if` volume; **dominant** direction wins, balanced → AMBIGUOUS | high-volume live paths | high |
| 3 | **Routing topology** (BGP-LS / IGP SPF) | the routers' computed directed forwarding path | backbone / paths without probes or flows | medium |

**Fusion:** take the highest-precedence source with a confident verdict; if the top two
covering sources **conflict**, return AMBIGUOUS (abstain — never average a contradiction).
Every orientation carries its `source` + `confidence` → fully auditable in the evidence log.

**Safety (preserved):** vote #2 is still one of three; a wrong/abstaining orientation can
**never force** a false claim (it needs a 2nd agreeing vote). Replay-safe: the orientation
inputs are embedded per snapshot (like seams), so a directed edge replays deterministically.

## Foundation — the EntityResolver (the keystone; also closes G2)

All three sources speak **IPs + ifIndexes**; correlation entities are **device / device:ifName**.
A shared resolver bridges them — and the data **already exists** in the Go backend:
- **IP → device**: discovery device `Address` (mgmt IP) + interface IPs.
- **ifIndex → ifName**: `ifNameMap` (IF-MIB ifName/ifDescr), already collected by CDP/LLDP.

The Go backend exports a tenant-scoped `entity_resolver.json` (mirroring `seams.json` /
`topology_links.json`); the correlation service loads it (mtime-cached). This is the same
canonicalization seam as **G2** (trap `sourceIP:peer`, flow `sampler:ifIndex`) — building it
once closes G2 for traps + flows AND unblocks every direction source. **Honest fallback:** an
unresolved endpoint → the source can't orient that pair → UNKNOWN (abstain), never a guess.

## Why this exceeds industry

- **Multi-source fusion** vs the leaders' single source — coverage across low-volume
  (traceroute), high-volume (NetFlow), and unprobed backbone (routing).
- **Bidirectional honesty** — NetFlow sees both directions; balanced → AMBIGUOUS, never an
  assumed direction (the failure mode of every static/inferred-topology approach).
- **Confidence + provenance on every arrow**, inside an **evidence-grounded** RCA with the
  2-of-3 safety bar — measured direction that can't, alone, manufacture a wrong root cause.

## Implementation sequence (each its own increment, tested to 100%)

- **C7.1 · EntityResolver foundation** — Go export (`entity_resolver.json`: IP→device,
  device+ifIndex→ifName, tenant-scoped) + correlation load. Closes G2 for traps/flows too.
- **C7.2 · DirectedTopology oracle + vote-#2 integration** — the source-agnostic oracle +
  fusion/abstention + wiring into `_direction`; abstains until a source is fed (safe no-op).
  Pure + unit-tested + replay-safe. *(Buildable now, independent of C7.1.)*
- **C7.3 · NetFlow direction source** — directed per-pair volume on the C6 lane → oracle.
- **C7.4 · Active-path-trace source** — traceroute directed hops + probe paths → oracle.
- **C7.5 · Routing source** — BGP-LS/IGP SPF direction → oracle (when lab data exists).

Each lands behind the oracle seam, so the engine's direction logic changes **once** (C7.2)
and never again. Direction-policy changes are validated before trusting a new source (the
research-before-implementing rule).
