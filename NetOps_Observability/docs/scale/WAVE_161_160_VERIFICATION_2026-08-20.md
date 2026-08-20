# Wave: tracker 161 + 160, live 1K verification

Run `08192339borh`, 1000 devices, 5-minute burst, cleanup disabled.
Build: `a0711da3`. Fleet purged of all prior `mlx-*` residue first (1073 stale
devices removed) so the run started from a clean identity space.

**Verdict: the correctness objectives of this wave PASS. Consumer stability
FAILS, and the cause is memory — which is the next task in the sequence.**

---

## 1. The 161 fix

`POST /api/devices` now honours the contract that 201 means the requested
identity exists:

| status | meaning |
|---|---|
| `201 Created` | the requested identity was created and is retrievable |
| `200 OK` | the request resolved to an existing canonical device; nothing was created under the requested identity. Body is the surviving device; `X-Device-Requested-Id` and `X-Device-Canonical-Id` name both sides |

`ResolveIdentity` answers "what became of this record" from `dedupeWithOwners`
— the same dedupe the read path runs — so the create-time answer cannot drift
from what `GET /api/devices` shows. `dedupeDevices` is now a thin wrapper over
it: one implementation of the merge, not two.

Harness side: `onboard` requires the returned canonical id to equal the
requested name and FAILS when any create was absorbed; the burst's registry gate
verifies **this run's identities** against the enrichment file instead of
waiting on a fleet-wide count.

## 2. Result: 1000/1000

| | previous runs | this run |
|---|---|---|
| devices created | 1000 (claimed) | **1000, absorbed 0** |
| registry gate | count 2000 ≥ 1000 ✓ (while 73 were missing) | **missing_identities: 0** |
| device coverage | **927/1000**, pinned | **1000/1000**, from the first sample |
| `unexplained_missing` | 0 (but blind) | **0** |
| run-attributable DLQ | 95–137 unclassified | **0** |
| accounting | FAIL | **PASS** — `600001 injected == 600001 persisted + 0 DLQ + 0 counted rejections` |

Coverage was 1000 in the first sample taken during the burst and never moved,
which is the opposite of the 927 signature (pinned below target while rows
climbed).

## 3. The 160 fix, proven live

**Unforced, during the run** — correlation-2:

```
23:49:00,654 clickhouse insert retry     table=netops.corr_signals attempt=1/4
                                         ch_code=- kind=transport rows=100 backoff=0.15s
23:49:00,870 clickhouse insert RECOVERED table=netops.corr_signals attempt=2 rows=100
```

A transport failure — precisely the case the old code folded into `False` and
quarantined. **100 rows recovered** that would previously have been lost while
the offset advanced. Duplicate check across the run: **158,743 rows, 158,743
distinct `signal_id`, 0 duplicates** — the retry reused the content-hash token.

**Controlled injection, run INSIDE the deployed container** (so it tests the
shipped artifact, not a local copy):

| case | result |
|---|---|
| retryable (241), never recovers | 4 attempts = the cap; **bounded** |
| → dead-letter record | `reason=ch_insert_rejected`, `ch_code=241`, `query_id=qid-241`, `retries_exhausted=true`, `payload_truncated=false` |
| → identity preserved | tenant `acme-inject`, signal `inj-1`, **payload parses back to the exact row** |
| permanent (16 NO_SUCH_COLUMN) | **1 attempt**, no retry, no loop; `retries_exhausted=false` |
| retryable then recovers on attempt 3 | 3 attempts, **same token every time**, **0 dead-letter records** |

## 4. Consumer stability: FAIL, and it is memory

| metric | result |
|---|---|
| `UNKNOWN_MEMBER` | **0** ✅ |
| consumer restarts | **0** (`RestartCount=0` both replicas) ✅ |
| `CommitFailedError` | **3** (00:01:34, 00:04:42, 00:08:15) ❌ |
| rebalances | reached **#10** |
| event-loop stalls | **104**, worst **112,802 ms** |

The ladder reported `commit_failed: 0` because it samples during the DRAIN phase
and all three landed after it — another measurement-window gap, recorded rather
than smoothed over.

The cause is not the code paths this wave touched. Correlation sat at **786–788
MiB against a 789 MiB cap (99.7%) for the whole drain**, and a 113-second event
loop stall is far beyond the 30 s session timeout, so the member is ejected and
the pending commit fails. Stalls began at 23:43 — during the burst, as memory
approached the cap — not at the start.

So the "expulsions eliminated" result from the previous wave holds only while
there is memory headroom. Once the process is pinned at the cap for a long
drain, instability returns. **Memory is now the direct cause of consumer
instability**, which makes it the correct next target.

## 5. Still failing, untouched by this wave

* **memory** — 99.7% of cap (memflat FAIL)
* **drain** — final lag 431,356; peak 517,314

## 6. Acceptance

| criterion | verdict |
|---|---|
| device accounting = 1000/1000 | ✅ |
| no false-success onboarding responses | ✅ |
| canonical identity semantics deterministic and documented | ✅ |
| zero unexplained attribution loss | ✅ |
| zero silent ClickHouse signal loss | ✅ |
| retry behaviour proven live | ✅ |
| exhausted/permanent writes durably recoverable before offset advance | ✅ |
| zero unexpected `UNKNOWN_MEMBER` | ✅ |
| zero unexpected `CommitFailed` | ❌ 3 |
| zero unexpected consumer restarts | ✅ |

**Wave verdict: FAIL on the stability criterion**, PASS on every 161/160
correctness criterion. The failure is a known, already-sequenced problem
(memory) rather than a defect in what this wave changed.

## 7. Evidence

In `data/miniladder/20260819T233902Z-08192339borh/`: `FREEZE_verify.txt`,
`coverage_verify.csv`, `ch_retry_live.log`, `inject160_output.txt`,
`report.json`, `lag-curve.json`.

## 8. Safe to proceed to memory profiling

Yes — and it is now the blocking item, not merely the next one. Both fixes are
verified and the failure that remains points directly at it.
