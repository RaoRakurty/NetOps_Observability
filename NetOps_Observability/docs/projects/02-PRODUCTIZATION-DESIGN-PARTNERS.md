# Project 2 — Productization & Design Partners  🔴

**Status: NOT STARTED — the next session opens with the gap report** (step 6 of
the required workflow below). Filed 2026-09-01 from the owner directive that
redefined the portfolio: Project 1 (Scale Testing) is DONE, this project takes
its slot, and Security CTEM / Troubleshooting renumber to Projects 3 / 4.

**Goal:** take the engine Project 1 proved and make it a product a design
partner can deploy, understand, and get correct RCA value from — fast.

**Model rule:** Fable designs + grades; Opus builds.

---

## Primary goals (owner-enumerated)

- **Operator-first UI** — the product is judged through a NOC operator's eyes,
  not an engineer's.
- **RCA hero experience** — the RCA story is the hero surface of the product.
- **Deployment simplicity** — trivial to stand up; friction is a defect.
- **Pilot readiness** — a design partner can run a real pilot end to end.
- **Customer integrations** — meet customers where their tooling already is.
- **Time-to-Correct-Useful-RCA** — the TTUR-proper programme (tracker **205**).
- **Design-partner feedback** — a working loop that turns partner input into
  ranked product change.
- **Reference-capacity regression** — the V1 qualification stays green on every
  release (tracker **203**).
- **Marketing / demo readiness** — the story is demonstrable and tellable.

## Success metrics — explicitly NOT device count

Device count was Project 1's axis and is **not** a success metric here. These are:

1. Time to customer value
2. Time to useful RCA
3. Operator comprehension
4. Pilot deployment success
5. Demo effectiveness
6. False-positive RCA rate
7. Customer-reported time saved
8. Incident-resolution improvement
9. Deployment friction
10. Design-partner retention

## REQUIRED opening workflow (owner-mandated; do these in order, first session)

1. **Inspect the repository + the Project 1 docs** before proposing anything.
2. **Confirm scale status + the benchmark artifacts** (what is proven, where).
3. **Identify existing qualification tests** already in the tree.
4. **Identify existing UI / productization pieces** already built.
5. **No duplication** — never rebuild what already exists.
6. **Produce a concise gap report** (this is the project's opening deliverable).
7. **Produce a prioritized task plan** from that gap report.
8. **Work in small reviewable phases.**
9. **Preserve the green scale regression at all times.**
10. **Never alter benchmark semantics without versioning the qualification
    profile** (V1 → V2, never a silent edit).
11. **No giant uncontrolled refactor.**

## Final principle

Every unit of work in this project is judged by whether it helps a NOC operator
answer, immediately and with evidence:

> **What broke? Why does Correlix believe that? What is affected? Who owns it?
> What evidence supports the conclusion? Is it recovering?**

Making those six answers fast, correct, and self-evident to the operator is the
highest-value objective of this project.

## Cross-links

- **Tracker 203** — release regression gate: wrap `CORRELIX_REFERENCE_CAPACITY_V1`
  into a rerunnable release suite (the "reference-capacity regression" goal).
- **Tracker 205** — Time-to-Correct-Useful-RCA (TTUR proper): define Useful RCA,
  measure p50/p95/p99, classify the tail before optimizing.
- **Marketing artifacts (delivered 2026-09-01, private-by-default; owner shares):**
  - Scaling report: https://claude.ai/code/artifact/625c0c16-465b-42a1-b75a-ebcb84a0930c
  - Marketing capabilities brief: https://claude.ai/code/artifact/c80bf963-3b57-48f2-9cff-89332c4503e9
- `docs/HOSTING_SIZING_GUIDE.md` — what to tell a customer to provision.
- `docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` — the qualified reference
  capacity profile this project must keep green (and must version to change).
- `docs/scale/PROJECT1_DONE_2026-09-01.md` — the proven baseline this project
  productizes.

## Fable recommendation (not owner-decided)

Force-rank wave 1 to three of the nine goals: **RCA hero experience**,
**deployment simplicity**, and **reference regression** (tracker 203). Rationale:
the first two dominate every listed success metric a design partner will feel in
week one, and the third is the safety net that lets the other two move fast.
This is a recommendation only — the owner ranks the goals.
