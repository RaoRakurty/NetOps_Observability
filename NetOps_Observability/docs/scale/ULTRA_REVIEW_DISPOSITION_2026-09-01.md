# Project 1 ultra review — disposition record (2026-09-01)

The owner-triggered `/code-review ultra` over the Project 1 execution window.
This is the record of what the review found, what was dispatched for fixing,
and the disposition of everything that was NOT dispatched. Residual work is
filed as tracker rows 206–208 (below); nothing else from the review remains
untracked.

## Shape of the review

- **Scope:** 271 commits / 345 files (the Project 1 execution window).
- **Yield:** 45 candidate findings → **4 refuted by the review itself**
  (#7, #12, #34, #40) → ranked survivors dispatched or dispositioned below.

## Fix dispatch — 10 lanes (agents in flight this session)

Ten fix agents were dispatched concurrently. **Lane 3 (#8) is already
committed (`e63e3021`)**; every other lane is **in flight, commits landing**.
The NEXT SESSION must (a) verify every lane's commit landed, (b) deploy the
fix wave, and (c) rerun the V1 qualification per the new regression gate
(tracker 203).

| Lane | Findings | Area |
|------|----------|------|
| 1 | #2 + #1 | bgp_ops §3a tenant scoping + rune handling |
| 2 | #5, #3, #4, #6 | timeintel quartet |
| 3 | #8 | **PEM private-key redaction — DONE `e63e3021`** (stateful block scanner, fail-closed at EOF) |
| 4 | #9 | tombstone durability |
| 5 | #22, #26, #21 | scripts |
| 6 | #28–#31 + #20 | gnmi / chain |
| 7 | #15, #16, #17, #19 + #18 | evidence-plane quartet (**CRITICAL #15**) |
| 8 | #23, #24, #41 + #35-driver | harness / A-B-off overlay |
| 9 | #11, #13, #36 | secbus / hardening / compose-env |
| 10 | #32, #33 | BgpOps frontend |

Per owner: **no deploy tonight** — the session pauses after commits land; the
next session owns deploy + V1 rerun.

## Dispositions (findings not sent to a fix lane, or fixed differently)

- **#35 — fixed driver-side.** The ratified aggregation-plane default (ON at
  the 2 %-share config) **stands**; the A/B "agg-off" comparison is now a
  driver-side overlay in the harness (lane 8), not a change to the shipped
  default.
- **#37 — as-designed.** The behavior the review flagged is the deliberate
  tracker-174 reversal (the loop-independent health sidecar answers while the
  engine loop is busy). Flag only if **vmalert paging is unverified** —
  **next-session check:** confirm vmalert actually pages on the sidecar's
  signal; if it does not, reopen #37 as a real finding.
- **#38 — already covered.** This is the alias-shadowing ORDER-BY class;
  tracker **row 200** already enumerates all the latent sites and the fix.
- **#25 / #27 — noted, no action.** #25's trigger conditions are not reachable
  in the deployed configuration; #27 is a documented, accepted trade-off. Both
  stay visible here rather than as tracker rows.
- **#12 / #34 / #40 / #7 — refuted by the review itself** during its own
  verification pass; no code change, no row.
- **#10 — REAL but not dispatched; filed as tracker row 206** (needs design:
  shadow reset + orphan-partition handling; migration runs check-only in prod
  today, so there is no live exposure).
- **#14 — latent;** the evidence-plane lane-7 agent may cover it in passing.
  Verify at next-session lane check; file a row then if it survives uncovered.
- **#39 — filed as tracker row 207** (chhttp retry classification).
- **#42–#45 — cleanup batch, filed as tracker row 208** (one row, four items).

## Residual tracker rows filed today

- **206 (Med)** — corr_repartition mid-copy TTL-shrink wedge (finding #10).
- **207 (Low)** — chhttp treats ClickHouse code 307 `TOO_MANY_BYTES` as
  retryable (finding #39).
- **208 (Low)** — review cleanup batch (findings #42–#45).

## Next-session checklist (carried in one place)

1. Verify all 10 lanes' commits landed (lane 3 already at `e63e3021`).
2. Check whether lane 7 also discharged latent #14; file a row if not.
3. Verify vmalert paging on the health sidecar (the #37 condition).
4. Deploy the fix wave.
5. Rerun the V1 qualification (`CORRELIX_REFERENCE_CAPACITY_V1`) under the
   tracker-203 regression gate.
