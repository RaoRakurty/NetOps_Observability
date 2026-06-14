# Probe Authority & Independence Model (Correlation Engine — Step 3)

**Status:** design merged from owner research + market/standards review (2026-06-14).
Supersedes the initial "synthetic = low-trust" sketch.

---

## 0. The correction that drives this design

The first cut framed probe trust as **synthetic vs non-synthetic** and made
`synthetic_lab_probe` / `internal_self_probe` low-authority by name. **That is
wrong.** In the market, synthetic/active testing is legitimate, first-class
evidence — the trust distinction is **vantage, intent, independence, and
fate-sharing**, not "is it synthetic."

Market grounding (how the category actually models it):
- **Cisco ThousandEyes** — separates **Cloud Agents** (TE-operated, globally
  distributed), **Enterprise Agents** (inside the customer org), and **Endpoint
  Agents** (user-side). Different *vantage classes*, not synthetic-vs-real.
- **Catchpoint** — public synthetic nodes vs **Enterprise Nodes** deployed inside
  the customer.
- **Datadog Synthetics** — **Private Locations** for internal/private endpoints
  alongside managed public locations.
- **Kentik** — global agents + **private agents** for inside-out testing from
  branches, VPN edges, cloud networks.
- **New Relic** — **multi-location synthetic conditions**: "N of M locations must
  fail simultaneously" before alerting, because "a single, short-lived [single
  location] failure does not indicate a problem." (verified, primary docs) —
  i.e. **multi-vantage agreement is the corroboration mechanism**, and a single
  vantage is deliberately *not* trusted to confirm.

Standards grounding:
- **RFC 7799** (Active and Passive Metrics and Methods) — formally distinguishes
  **active (synthetic)** vs **passive (real-traffic)** vs **hybrid** measurement
  and defines *observation points*. Active is valid measurement; the method just
  has to be declared.
- **RFC 2330** (IPPM Framework) — measurement **error sources, calibration,
  repeatability**. Probes carry methodological caveats (a probe is not proof).
- **RFC 9232** (Network Telemetry Framework) — telemetry plane taxonomy that our
  evidence-modality classes mirror (management/control/forwarding + external).
- **RFC 8632** (YANG Alarm Management) — alarm **correlation**, *root-cause
  resource*, *impacted resources*, *related alarms* — the vocabulary our
  `corr_objects` should align to.

Academic caution (network tomography / fault localization): active probing
reduces ambiguity **only when probe paths and dependencies are understood**;
correlated end-to-end observations that share a path violate independence
assumptions. Microsoft **Pingmesh** shows active latency measurement is valuable
*at scale* but is a *measurement system, not proof by itself*. ICMP/probe traffic
may **not fate-share with real application traffic** (different MTU, filters,
protocol, port handling) — so a healthy probe ≠ healthy app path, and a probe
cluster that shares fate proves less than it appears.

**Product framing (the one-liner):**
> Active-probe evidence is valid. Its **authority** depends on **vantage, intent,
> and independence**; **fate-shared** probes do not independently corroborate; and
> **no probe-only object confirms** — confirmation needs a non-fate-shared,
> sufficient-authority probe **plus a second independent modality**.

---

## 1. Data model

Probe trust is **derived from rich metadata**, not asserted from a single label.

### 1.1 Source-of-truth fields (from the probe registry/binding)

| Field | Values |
|-------|--------|
| `probe_intent` | `customer_path` · `service_dependency` · `platform_self_check` · `lab_test` |
| `vantage_type` | `public_cloud_agent` · `enterprise_agent` · `endpoint_agent` · `private_location` · `internal_collector` · `local_container` |
| fate inputs | `agent_id` · `host_id` · `source_ip` · `egress_ip` (NAT/public) · `site` · `egress_interface` · `seam_id` · `target` · `protocol` · `schedule_id` |

### 1.2 Derived fields (computed at ingestion, carried on the signal)

| Field | Meaning |
|-------|---------|
| `authority` | `high` · `medium` · `low` · `debug_only` — derived from (`intent` × `vantage`) |
| `independence_group` | fingerprint from the fate inputs (for pairwise fate-sharing) |
| `probe_scope` | **UI-friendly projection** of intent/vantage (see §1.4) |
| `classification_source` | `registry` · `inferred` · `unknown` (honesty about how we know) |

### 1.3 Authority derivation (`intent` × `vantage`)

- `customer_path` + (`enterprise_agent` | `endpoint_agent` | `private_location`) → **high**
- `customer_path` + `public_cloud_agent` → **medium/high**
- `service_dependency` (any real vantage) → **medium**
- `platform_self_check` | `internal_collector` → **low**
- `lab_test` | `local_container` → **debug_only**
- unknown / unclassified → **low** (fail-closed)

### 1.4 `probe_scope` projection (UI label only — not the source of truth)

- `customer_path` ← `customer_path` intent + real customer/user/service route
- `service_dependency` ← dependency target (DNS, API, cloud endpoint)
- `internal_self_probe` ← `platform_self_check` / `internal_collector`
- `synthetic_lab_probe` ← `lab_test` / `local_container` / debug probe
- `unknown` ← unclassified

---

## 2. Fate-sharing / independence (the most important part)

Two probe signals are **not independent just because there are two of them** —
they may share a failure path. Treat a probe pair as **fate-shared** if they
share too many fate inputs.

**Conservative rule v1 (ship this):**
```
fate_shared(a, b) = (a.agent_host == b.agent_host)
                 OR (a.source_egress == b.source_egress)      # same NAT/public egress
                 OR (a.seam_id == b.seam_id AND a.target == b.target AND a.schedule_id == b.schedule_id)
```
Richer fingerprint (later): add host/VM/container ns, collector process, site,
egress interface, protocol/traffic class, underlay path hash.

Fate-shared probes collapse into **one independence group** → they count as a
single independent observation, never two.

---

## 3. Verdict gate rules

| Probe type (intent + vantage) | Authority | Open object | Support `suspected` | Confirm |
|---|---|---|---|---|
| `customer_path` from enterprise/endpoint agent | High | Yes | Yes | Only with another modality |
| `service_dependency` probe | Medium | Yes | Yes | Only with another modality |
| public cloud agent → public endpoint | Med/High | Yes | Yes | Only with another modality |
| internal platform self-check | Low | Maybe | Weak support | **No** |
| lab / debug / local-container probe | Debug/Low | Debug-only / weak | Weak support | **No** |
| unknown classification | Low | Maybe | Weak | **No** |

Gate invariants:
1. **No probe-only object confirms.** Confirmation always needs a second,
   independent modality (`device_telemetry` | `control_plane` | `passive_flow`).
2. **Fate-shared probes are not independent observers** — they don't satisfy a
   multi-observer requirement.
3. **Confirmation requires a confirm-authority probe** (`high`/`medium`,
   non-fate-shared) **for any signature whose required modality is `active_probe`**
   (e.g. DIA egress latency). A `low`/`debug_only` probe can SUPPORT (→ `suspected`)
   but never satisfy the `active_probe` requirement for `confirmed`.
4. **No trustworthy signal at all** (every witness is low/debug probe, nothing
   else) → `undetermined`, not `suspected`. (Honest: we have nothing to stand on.)

This preserves the existing corroboration model (≥2 modality classes × ≥2
independent observers) and refines *what counts as an independent, trustworthy
probe observer*.

---

## 4. Where classification lives

Do **not** infer everything from the raw signal after the fact — brittle.

```
Probe Registry / Binding   intent, vantage, target, seam, owner, expected path, schedule
        │  (probe_id)
        ▼
Probe Event                probe_id + runtime metadata (agent_id, source_ip, egress, ...)
        │
        ▼
Ingestion                  enrich from registry → derive authority/scope/independence_group
        │                  fail-closed: unknown metadata → low authority, classification_source=unknown
        ▼
Correlation Engine         uses authority + independence_group + modality rules (pure, replay-safe)
        │
        ▼
Inspector                  shows probe_scope, authority, fate-sharing, and WHY it can/can't confirm
```

Replay-safety: derived fields are **stored on the signal** (in `attrs`, already
byte-faithfully archived), so a replay re-reads the same classification — no
post-hoc re-inference, deterministic.

---

## 5. Reconciliation with the WIP code

| WIP (initial) | Merged (this design) |
|---|---|
| `ProbeScope` enum is the source of truth | `ProbeScope` is a **UI projection**; `probe_intent` + `vantage_type` + `authority` are the model |
| `trusted: bool` (high-auth scope = trusted) | **`authority` 4-level** (`high`/`medium`/`low`/`debug_only`); confirm-authority = `{high, medium}` |
| low-auth probes all share one fate bucket | proper **`independence_group` fingerprint** + pairwise `fate_shared()` |
| "synthetic = untrusted" framing | "authority = f(vantage, intent, independence)"; synthetic is legitimate |
| classify at ingestion (only) | classify at **registry/binding**, enrich at ingestion, fail-closed |

Verdict-gate consequences are largely **unchanged in outcome for the lab** (its
probes are `platform_self_check`/`local_container` → low/debug → can't confirm),
but the *model* is now defensible and customer-correct.

---

## 6. Phased implementation (conservative first)

- **P3a (ship now):** signal fields (`probe_intent`, `vantage_type`, `authority`,
  `independence_group`, `probe_scope`, `classification_source`) in `attrs`;
  pure derivation + `fate_shared()` in `signals.py`; verdict gate uses authority +
  fate-sharing (`verdicts.py`); fail-closed defaults at ingestion (`main.py`);
  tests proving probe-only / low-authority / fate-shared can't confirm.
- **P3b:** Inspector surfacing (probe_scope, authority, fate-sharing, why-can't-confirm).
- **P3c:** real **Probe Registry** (binding store) — registry-sourced classification
  replaces inference; `classification_source=registry`.
- **P3d:** richer fate fingerprint (underlay path hash, container ns, collector).

---

## 7. Cross-validation (research complete, 2026-06-14)

Owner research + the `deep-research` pass (`wf_003e5c54-216`: 100 agents, 18
sources fetched, 82 claims → 25 verified, 24 confirmed / 1 killed, 9 synthesized)
**converge**. The model is validated; two design decisions surfaced (§8).

**Confirmed (high confidence):**
- **Vantage classification by ownership/location is real and architectural** —
  ThousandEyes splits vendor-operated **Cloud Agents** (outside-in) vs
  customer-deployed **Enterprise Agents** (inside-in). Maps to our `vantage_type`.
  (docs.thousandeyes.com)
- **Fate-sharing with the real user path is a *validity requirement*** — TE
  advises deploying agents "on the same network as the user" so "QoS, firewall,
  and routing… are also applicable to the test traffic." Inverse failure is
  documented: probes "meet a different fate" than real traffic (EPFL
  correlated-links: traceroute runs on the control-plane CPU, not the data-plane
  ASIC), and **007 rejects out-of-band synthetic probes entirely** because "the
  probe traffic does not capture what the end user and TCP flows see." (ACM/NSDI)
- **N-of-M / quorum multi-vantage agreement is THE corroboration mechanism** — a
  single synthetic vantage failure is treated as noise (New Relic "4-of-6";
  Datadog "fail from N of M"). This is "support-but-don't-confirm-alone" in
  production. (docs.newrelic.com, docs.datadoghq.com)
- **Independence is a formal precondition** — tomography is valid only under a
  measurement/link-independence assumption; fate-shared probes violate it and
  errors **cascade** beyond the affected element.
- **Identifiability needs a non-fate-shared known-good reference path** through
  the suspect element — not merely more probes along the suspect path
  (NetBouncer). Diversity of *paths*, not count of probes.
- **Probe-only overfits noise** → must be regularized with domain knowledge and
  gated detection→confirmation (our grounding gate + verdict tiers).
- **A second, independent modality sharply improves fidelity** — Flock's
  active+passive fusion cuts inference error **1.2–55×**. Strongest empirical
  basis for "confirmation = non-fate-shared probe **+** independent modality."

**Caveats / limits (don't over-claim):**
- The **link-fate-sharing → probe-fate-sharing** bridge is an analytical
  extension (defensible, not verbatim in sources). Our agent-host/egress/seam
  fingerprint is a reasonable engineering choice, not an attested standard.
- 007/NetBouncer are **datacenter/Clos passive** systems (007 votes on passive
  TCP retransmits, not active synthetic probes) — logic transfers conceptually,
  not by design, to WAN/Internet synthetic vantages.
- Only **ThousandEyes/Datadog/New Relic** survived verification; Catchpoint /
  Kentik / AppNeta / SolarWinds did not (open question — likely also rely on
  multi-vantage quorum).
- **Refuted (0-3, excluded):** "path-overlapping probes share fate within a
  tomography cycle" — do NOT use intra-cycle path overlap as fate evidence.
- The 4-way taxonomy is a **defensible synthesis**, not a named industry standard.

## 8. Open design decisions (need owner sign-off before finishing P3a)

1. **`lab_test` / `debug_only` probes — bar from customer RCA entirely, or
   weak-support-only?** The literature's strongest stance (007) *abandons*
   out-of-band synthetic probes rather than down-weighting them — suggesting
   `debug_only` should not contribute to *any* customer-facing verdict (debug
   views only), not merely "support but not confirm." **Recommendation:**
   `debug_only` = excluded from customer-facing object verdicts (visible in Debug
   view only); `low` = may SUPPORT (→ suspected) but never confirm.
2. **Second-modality confirm threshold** — must the corroborating modality
   *independently* cross a fault bar (Flock-style), or only be *consistent* with
   the probe verdict? **Recommendation (conservative):** require the second
   modality to be an independently-admitted episode (its own anomaly), not merely
   "not contradicting" — i.e. a real independent witness, matching our existing
   ≥2-modality × ≥2-observer gate.
3. **High-confidence path diversity (future):** identifiability argues for
   *multiple non-fate-shared vantages* for the strongest verdicts. Defer as a
   `confirmed`-vs-`confirmed-high` refinement (P3d).
