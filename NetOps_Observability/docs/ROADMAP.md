# Open Work — Prioritized Roadmap

The forward-looking queue of **genuinely-open** work, prioritized as a principal
architect would: by value to the core differentiator (**RCA-first correlation — the
engine *is* the product**), correctness/operator-trust, dependency order, and risk.

Verified against live code + the running system on **2026-06-23** (post stale-claim
audit). Companion to `docs/TRACKER.md`, which is the historical done-log; **this file
is the live open queue.** When an item ships it graduates: mark ✅ here, log it there.

## Maintenance discipline (world-class process — non-negotiable)

1. **Update this file in the SAME commit** that changes an item's state. No silent drift.
2. **Verify before building** (the G2/G3 lesson): prove an item's premise against live
   code + data *first*; "already done / moot" is a valid outcome. Don't trust a status —
   trust the code + running system.
3. **CI guards mechanical drift**: `scripts/tracker_staleness.py` + `tracker-ci.yml` fail
   on a NOT-STARTED item that already has shipping commits. *Premise-drift* (a gap that
   went moot with no commit — G2/G3) is unautomatable; re-audit periodically by hand/agent.
4. **Re-prioritize** when an item closes or a new one lands. Priorities are claims, not law.

Legend: 🔴 P0 now · 🟠 P1 next · 🟡 P2 soon · ⚪ backlog (owner-gated / deferred) · ✖ not planned
Effort: S (hours) · M (1–2 days) · L (multi-day, phased)

---

## 🔴 P0 — core engine trust + correctness (the moat, operator-facing)

### R1 · G4 — OSI causal-layer enrichment + RCA layer-stack UI  ⟶ *in progress*
**Why P0:** directly strengthens the differentiator — explains the causal chain in the
mental model operators already use (root layer → symptom → impact), and sharpens
direction inference (correctness). Lab-validatable; no dependencies; owner-specced.
**Scope:** *(engine)* `osi_layer`/`causal_layer` as a first-class signal attribute;
per-kind layer ordering in direction inference; layer coverage in the evidence summary;
prevent confirmation from pure same-layer duplicate evidence. *(UI)* RCA Layer-Stack
panel (observed/not-observed per L1–L7) + layer-reasoning narrative + root→symptom→impact.
**Dependency:** none. **Effort:** L.
**⚠ Research-first gate (per verify/research-before-building):** the *methodology* (isolate
by OSI layer) is standard, but whether an evidence-grounded cross-layer causal *explanation*
in the engine is differentiating vs at-parity is unverified. Before coding: a focused pass —
how ThousandEyes / Dynatrace / NetBrain / Kentik / Selector / Datadog do cross-layer causal
RCA + layer-stack explanation; diff G4 against it; keep only what meets/exceeds the bar.
**Exit:** research diff recorded → kinds tagged; direction prior uses per-kind layer; verdict
exposes layer coverage; Layer-Stack panel renders root/symptom/impact; tests — **incl. proof
the existing confirms (local-link-fault, dia-egress) still pass.**

### R2 · #76 — engine-side internal-stack exclusion
**Why P0:** honesty of the core. The engine still forms correlation objects mixing the
platform's OWN stack with customer faults; today only the UI hides them (`9157f94` et al.).
RCA must be the *customer's* network (decision #76). A correctness/trust gap, not cosmetic.
**Dependency:** none. **Effort:** S–M. **Exit:** internal-stack signals dropped/segregated
*before* object formation; an internal node never appears in a customer `corr_object`; test.

---

## 🟠 P1 — coverage that compounds (the three-layer growth model)

### R3 · Telemetry signal coverage + signature expansion (VLAN / STP / HSRP-VRRP / MAC / firewall) [#73 + catalog]
**Why P1:** the real "more to build." Grounding is protocol-agnostic and done; growth is
**Layer-2 signal kinds** (collect + normalize) + **Layer-3 signatures** (one catalog dict
each). Every family widens RCA coverage and, once a 2nd modality exists, confirms for free.
**Dependency:** a family's collection must exist before its signature (don't author a
signature for data we don't ingest). Multi-vendor research re-run is **owner-gated** (token
spend, #73). **Effort:** L, incremental per family. **Exit (per family):** canonical kind in
`producers.py` + a signature dict + a CI fixture. Concrete next: wire the firewall family
(FortiOS/PAN) into the correlation producers.

---

## 🟡 P2 — operationalize RCA (close the loop to action)

### R4 · #78 — RCA → ServiceNow auto-ticketing
**Why P2:** turns a confirmed RCA into action — **one ticket per `corr_object_id`** (not
per raw alert). High product value; design captured (`docs/design/rca-ticketing.md`);
depends on a stable corr_object (have it). Sequenced *after* the engine-trust work (R1/R2)
so we only auto-ticket on trustworthy verdicts. **Effort:** L (data model → adapter →
API → UI → E2E, per the design doc). **Exit:** the doc's P1–P5 phases.

### R5 · Wire the Command-Center row-actions (Assign owner / Create ticket)
**Why P2:** small, complements R4; the buttons render but have no handlers
(`correlix-enhancement-before-after.md` ⬜). **Effort:** S. **Exit:** owner-assign persists;
"Create ticket" drafts from the evidence bundle (ties into R4).

---

## ⚪ Backlog — owner-gated / deferred-by-choice

- **#53 Event-pipeline management** (alert suppression, maintenance windows, triage lifecycle) — needs an owner product decision (research/discuss); the `corr_signals` feed + Events Explorer already ship.
- **#16 Enterprise-tenancy heavy three** (Tenant→Project→Env ownership, workload identities, ClickHouse `PARTITION BY tenant_id`) — deferred by choice; destructive/greenfield.
- **Placeholder pages** — Device Geomap, Vulnerability/Compliance external CVE feeds — blocked on data sourcing.

---

## ✖ Consciously NOT planned (recorded, not silently dropped — 2026-06-23 review)

These were considered and cut from the active queue. The knowledge is preserved where
noted, so they can be revived if the calculus changes.

- **G2b — independence-aware verdict gate for unresolved trap sources** — cut: risk
  (regressing validated confirms) outweighs value, and the lab can't validate it. The
  residual NAT false-independence risk is documented in `correlation-engine.md` §4.2 and
  the grounding-foundation memory; G2a already removed the wrong-guess (ambiguity) half.
- **§4.2 same-site / same-ASN grounding rungs** — cut: low value (adjacency covers the
  interior class) and no input feeds them. Remains documented as "specified, not wired" in
  §4.2; revive only if a site/ASN metadata source lands.
- **#33 remaining typed-repo conversions** — cut: not real work. Bounded config stores
  (api_keys, snmp_creds, roles, profiles) stay cached by design with multi-instance reload.

---

*Last reviewed: 2026-06-23 (post stale-claim audit, owner-approved prune). Next review: when R1 closes.*
