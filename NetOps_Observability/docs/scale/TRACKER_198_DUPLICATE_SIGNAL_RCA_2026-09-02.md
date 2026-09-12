# Tracker 198 — duplicate `corr_signals` row with no rebalance: root cause (2026-09-02)

Read-only investigation (Project 2, P1 bucket). Line numbers refer to
`src/correlation/main.py` at `4c0d8eee` unless noted.

## Evidence (155c run dir; the corpus itself is purged)

| source | value |
|---|---|
| `arm-control/metrics-{pre,post}-run.txt` `corr_signal_batch{event="rows_flushed"}` | repl-4 +140, repl-5 +210 = **350 rows flushed** |
| `rows_replay_deduped` / `rows_quarantined` | **0 / 0** on both replicas |
| `accounting-control.json` | 361 rows / 360 unique; `audit_change: 11` (Go bridge `src/backend/audit.go:412`, per-event uuid5, never the Python batcher) |
| `terminal-row-mechanism.json` | control arm: no partition move, `lifecycle_merge_candidates: 0` |
| `arm-summary.json` `offset_rewind_run` | forward progress only — no rewind |
| twin `events.jsonl` | 1,282 events, **0 duplicate `payload_digest`**, `produce_failures: []` |

350 batched + 11 audit = 361 = rows landed. **No server-side re-insert; both
copies were appended as separate rows.**

## Mechanism

`signal_id = uuid5(SIGNAL_NS, "{source}|{native_id}|{ts_ms}")`
(`src/correlation/signals.py:716`). For `device_alarm` (312 of 361 rows):

```
src/correlation/producers.py:922
native_id = f"{host}|alarm|{facility}|{mnem or '?'}|{ifname or '-'}|{ts_ms}"
```

**No message content.** Two *different* syslog lines from one host with the
same facility + mnemonic, no interface (or the same one), stamped in the same
millisecond, get the **same `signal_id`**. The twin emits exactly that
(`scripts/lab/twin/emitters.py:490` builds a whole due batch in one loop;
the control journal holds ~200 same-device/same-millisecond pairs with
distinct payloads).

Whether such a pair yields one row or two is decided by the batcher, not by
intent:

- `CHBatcher.add` drops the second copy when both sit in the live/parked
  batch (`:8213`) — **silently, no counter**;
- the post-flush replay guard `_flushed_uncommitted` (`:8219`) drops it —
  counted (`rows_replay_deduped`), and that counter is 0;
- `note_committed()` (`:8192–8196`) clears the whole guard on every offset
  commit, which runs after every message at `CORR_COMMIT_EVERY_S=5` /
  `N=100` (`:8751`, `:10816`, `:10915`) — guard lifetime ≈ 5 s.

A colliding pair that straddles one commit boundary is written **twice**.
~200 candidate pairs × P(straddle) × P(same facility/mnemonic/interface)
≈ 1 per arm — matching 155c (control 1) and 155d (control 1).

**Ruled out:** batcher retry under a fresh token (flushed == landed; the
parked batch re-sends under the same content-hash token, `:8235–8250`);
ownership/merge/continuation re-emit (`batch_signal` is called only at
intake; nothing re-persists a signal on a new version; control arm had 0
moves, 0 merge candidates); duplicate produce (0 duplicate digests); offset
rewind (none).

## Blast radius

The duplicate is the lesser harm. `_BUFFERED_IDS` (`:1719`) dedups the engine
window by `signal_id`, so correlation, evidence and accuracy are unaffected
(s11 345/345). Only `count()`-style readers inflate by one row
(`events_feed.go:304/336`, `cloud_security.go:157`, `cloud_enrich.go:121`,
`cloud/signals.go`). **The worse twin of the same defect is the silent path:**
when the pair lands in one batch, `:8213` and `:1719` discard a genuinely
distinct alarm from the durable spine, replay and the window — uncounted
evidence loss.

## Smallest correct fix (builder brief)

1. **Root:** make the id identify the event — append a short content
   discriminator to the alarm `native_id` (`producers.py:922`), e.g.
   `|{sha1(msg)[:8]}`. A true Kafka redelivery carries byte-identical text,
   so idempotent dedup is preserved; two distinct lines stop colliding. Audit
   the other `native_id` builders for the same omission (`producers.py:373,
   628, 1016, 1262`).
2. **Visibility:** count the silent in-batch collapse at `:8213`
   (`corr_signal_batch{event="rows_identity_collapsed"}` on `/metrics`) so
   this class can never be invisible again.
3. **Do not** add `corr_signals` to `CH_DEDUP_SAFE_TABLES` / a
   ReplacingMergeTree (`:7684`): the two rows differ in content and token, so
   it would not collapse them, and it would mask the real bug.

**Tests (§11):** (a) two syslog events identical except `message`, same
timestamp to the ms → different `signal_id`; byte-identical event → same
`signal_id`; (b) the in-batch collapse of a byte-identical duplicate still
yields one row AND increments the new counter; (c) the counter is exported.
The V1 qualification's `corr_signals` row count (informational, never gated)
may rise slightly on the next leg because fewer distinct alarms are collapsed.
