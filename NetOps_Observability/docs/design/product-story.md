# Product Story — RCA-First Hybrid Network Observability

Status: **CANONICAL GTM framing (owner, 2026-06-11)** — all positioning, packaging,
navigation, docs, and roadmap decisions align to this. Supersedes any earlier
"monitoring platform with AI correlation" framing.

---

## Main product story

> **RCA-first hybrid network observability.**

We are not selling collection breadth. We are selling the answer: *what broke,
where along the hybrid path, who owns the fix, and the evidence behind that
verdict* — across app, LAN, SD-WAN, underlay, colo/POP, and cloud seams.

One-line narrative (from the #67 sign-off):

> Topology-grounded, replayable, signature-tested RCA objects that identify
> ownership-transition failures across app, LAN, SD-WAN, underlay, Equinix/colo,
> and cloud seams — separating suspected from confirmed verdicts based on
> independent evidence coverage.

## Core engine (THE product)

| Pillar | What it is | Design home |
|---|---|---|
| **Correlation objects** | persistent, versioned causal graphs of incidents | `correlation-engine.md` |
| **Evidence timeline** | human-readable supports/contradicts/discriminates log per object | `correlation-engine.md` §2.3 |
| **Seam-aware topology** | ownership transitions (DX/VPN/SDWAN/DIA/CLOUD_BACKBONE) as first-class causal objects + bootstrap engine | `cloud-ingestion.md` §4 |
| **Signature catalog** | practitioner failure signatures as declarative, CI-tested data | `correlation-engine.md` §4.5 |
| **Replayable RCA** | same inputs + pinned versions ⇒ same object; falsifiable on recorded incidents | `correlation-engine.md` §5/§8 |
| **Suspected vs confirmed verdicts** | verdict tier gated by independent evidence coverage (≥2 modalities × ≥2 observers), `undetermined` honest | `correlation-engine.md` §4.5 |

## Supporting features (optional add-ons)

Device monitoring · Flows · Topology maps · Path monitoring · Alerts · Reports ·
ITSM sync · Dashboards · Automation.

These are **attachable add-ons, not the story** (owner: "supporting features will
be like add-ons if needed to be"). Consequences:

- **Positioning/demos lead with the engine** — the killer demo is a cross-seam RCA
  (LAN → SD-WAN → underlay → cloud/POP), not a dashboard tour.
- **Packaging**: the core engine is the base product; supporting features are
  modular — they feed the engine signals (their telemetry value) and consume its
  verdicts (their UX value), but each must be individually detachable without
  weakening the core story.
- **Navigation/front page** (#69): the landing page is the engine's output
  (top issues, verdicts, evidence, what changed); supporting features live behind
  it as drill-downs and configuration.
- **Roadmap weighting**: engine-pillar work outranks supporting-feature work by
  default; a supporting feature gets priority only when it strengthens a pillar
  (e.g. path monitoring → seam bracketing).

Related: `rca-market-research.md` §5 (why this white space is defensible),
tracker #67/#68/#69, memory `netops-frontpage-rca-direction`.
