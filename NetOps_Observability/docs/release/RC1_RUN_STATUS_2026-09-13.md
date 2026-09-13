# RC1 run status — live tracker with ETAs

Started 2026-09-13 04:58 UTC. Updated every ~4 h by the running session (cron) and at every
merge. `docs/TRACKER.md` remains the authority on row state; this page adds
who is on it, where it is, and when it is expected. Times are local box time.

**Standing decision: DO NOT tag `v0.9.0-rc1`.** Blockers A–F unchanged; four need a human.

## Board

| # | Item | Owner | Status | Started | ETA | Notes |
|---|---|---|---|---|---|---|
| D5 | Branch protection on `main` — 21 checks, strict, enforce_admins, conversation resolution | Fable | ✅ DONE | Sun 04:58 | — | Re-read live: 21/strict/admins/conv all true, approvals 0, force-push+deletion off. Rulesets: none existed; bypass actors: none (sole collaborator is the owner, admin). `bundle` check left unrequired (failing, stale bundle). |
| D5 | Tag ruleset `release-tags-immutable` on `refs/tags/v*` | Fable | ✅ DONE | Sun 04:58 | — | id 23134136, active, rules deletion+update+non_fast_forward, no bypass actors. Creation allowed (the owner pushes the tag once); dev tags untouched. |
| D5 | Docs: runbook live-state, Decision-5 doc → APPLIED, pending register, consistency test | Opus | ✅ DONE (merged 1e3cd70b) | Sun 04:58 | Sun 05:58 | |
| 306 | `visibleSaved` cross-tenant leak, read + write paths | Opus | ✅ DONE (6e1dac8f, merged; row deleted) — write half was open too: rename/delete/plant a report in a hidden tenant | Sun 04:58 | Sun 07:58 | isolation test required |
| 298 | `runSitesImport` read oracle → third outcome `refused` | Opus | ✅ DONE (77ef4606, merged; row deleted) — also closed an overwrite path that wrote over a hidden tenant's site | Sun 04:58 | Sun 07:58 | decision taken: refused = writes nothing, discloses existence only |
| 307 | four `collectors/redis.go` reads carry the 290 fold | Opus | ✅ DONE (86839690, merged; row deleted; guard baseline now empty) | Sun 04:58 | Sun 07:58 | callers disposition + baseline entries deleted |
| 296 | SR Linux hardening fails open on 2 of 3 path spellings | Opus | ✅ DONE (9657160c, merged; row deleted; residue filed as 310) | Sun 04:58 | Sun 06:58 | decision taken: match all three spellings AND refuse unrecognised SRL form as UNASSESSED |
| 308 | memflat false leak call on VictoriaMetrics | Opus | ✅ DONE (58ce94c8, merged; row deleted) | Sun 04:58 | Sun 07:58 | quiet-interval two-end-sample anchor, NOT a wider --mem-factor |
| 309 | correlation cannot read `netops.controller_events` | Opus | ✅ DONE (50c5e54e, merged; row deleted) — premise half wrong: grant existed; fixed the read-back + per-lane metric/rule/Q1b gate. Post-deploy: re-run apply-acls, restart correlation, Q1b must PASS | Sun 04:58 | Sun 06:58 | ACL matrix + explicit observable refusal + a gate that judges it |
| 238a | verify 29 licence reviews against 7 conditions, sign only passes | Opus | ✅ DONE (3f93abb7, merged) — 25 signed, 2 need an owner call (xz-libs 5.6.3-r1 C7, .python-rundeps C3) | Sun 04:58 | Sun 07:58 | each failure reported individually |
| 238b | strip six distlib PE launchers from the correlation runtime image | Opus | ✅ DONE (20ece8a3, merged) — both Syft shapes gone; keep pip (recommendation with evidence in tracker 238); residue filed as 311 | Sun 04:58 | Sun 08:58 | both Syft representations must vanish; pip regression; report if dropping pip is stronger |
| D | Blocker D engineering half: release-mode fail-closed artifact signing (`CORRELIX_RELEASE_BUILD=1`, key import from a not-yet-existing secret, verify-before-upload, provenance in MANIFEST) | Opus | ✅ DONE (82be3e50, merged) | Sun 07:51 | Sun 10:51 | leaves the tag build failing closed until the owner creates the distribution key secret |
| G6 | CODEOWNERS (placeholders only) · pin the 6 unpinned `@v4` actions · licence-gate five reject cases proven | Opus | ✅ DONE (bad0aab4, merged) — licence gate was FAIL-OPEN on a missing/empty enterprise text; closed with 16 tests. Owner note: directive names `LicenseRef-Correlix-Enterprise.txt`, tree uses `Correlix-Enterprise.txt`; not renamed | Sun 08:37 | Sun 10:37 | engineering-safe; no personnel invented |
| G8 | Decision 8: one fail-closed `release-check` entry point (`scripts/release-gate.py`) with PASS/FAIL/BLOCKED-HUMAN/CI-ONLY table + JSON for the RC1 report | Opus | ✅ DONE (ffc4fe95, merged) — `make release-check` → NO-GO today: 20 PASS · 4 FAIL (2 unsigned reviews + no bundle yet) · 6 BLOCKED-HUMAN (A B C D/F) · 8 CI-ONLY; also closed a gosec zero-files hole in backend-ci | Sun 08:37 | Sun 11:37 | does not touch the existing storm-SLO `release-gate` target |
| 300 | identity namespacing — Phase 1 inspection + design of record (docs/design/IDENTITY_NAMESPACING_2026-09-13.md) | Fable | ✅ DONE (92bcf524) | Sun 04:58 | Sun 08:58 | inspection only, no code |
| 300 | Phases 2–3 store+schema+migration (agent 300-store), then 4–6 doors+fan-out+tests (agent 300-doors) | Opus | 🔄 store DONE (1db02c1e, merged) → doors running | Sun 08:37 | Sun 12:37 | ~3–4 working days in the register; parallelised where the phases allow |
| — | merge agent branches, tracker rows deleted, full gate, push, CI green | Fable+Opus | 🔄 gate run 2 green except 6 lint findings (with doors agent); push after doors | Sun 08:37 | Sun 12:58 | after the first wave lands |
| — | main → feature merge (main is not an ancestor of the branch; strict mode needs it) | Fable | ⏳ queued (before the RC1 PR) | — | Sun 12:58 | routine merge, no rewrite |
| — | customer bundle rebuild from the final commit | Opus | ⏳ queued | — | after 300 | ~210 commits stale today |
| — | lab deploy (.122) + qualify | Fable+Opus | ⏳ queued | — | after 300 | verify served bundle markers |
| — | final RC1 preparation PR merged under the full ruleset → FINAL_RC1_SHA → release-only gates | Fable | ⏳ queued | — | after 300 | then STOP; the tag is the owner's |

## Human blockers (unchanged)

**NEW: two licence reviews need your call** — `xz-libs 5.6.3-r1` (C7) and `.python-rundeps` (C3); see tracker 238. · **Blocker D human action is now exact:** create repo secret `CORRELIX_DIST_SIGNING_KEY` (armored SECRET half of the DISTRIBUTION key — not the tag key, never the licence key; non-interactive); until then every tag build fails closed by design. · A licence text (counsel) · B CLA terms (counsel + admin) · C signed tag (release owner) · D artifact-signing key (security owner) · F custody (owner). **E is now closed by D5 above.**

## Log

- 2026-09-13 04:58 UTC — Decision 5 applied and re-read. Nine agents launched on disjoint files. 300 Phase 1 inspection started.
- 2026-09-13 07:51 UTC — first wave fully merged (306 298 307 296 308 309 238a 238b + D5 docs + test-leak + neighbours + PE-check); gate run 2 green except 6 lint findings in the store package (with the doors agent) ; disk crisis at 100 % cleared to 87 % by removing dead worktrees/caches; residues filed 310 311 312; signing fail-closed agent started.
- 2026-09-13 08:37 UTC — scheduled tick. Shipped since last: signing fail-closed on tag builds (82be3e50), PE-check escalation (76bc3f86), neighbours raw-error fix, docs corpus sync. Running: 300 doors (Phases 4–6, incl. 6 lint fixes), CODEOWNERS/pins/licence-gate cases, Decision-8 release-check entry point. Blockers unchanged: A B C F human; D now exact (secret `CORRELIX_DIST_SIGNING_KEY`); two licence reviews need an owner call. Filed 313 (image push-before-attest). Nothing pushed yet — next push after doors land and gate run 3 is green.
