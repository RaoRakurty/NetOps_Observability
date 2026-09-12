# P3 Aggregation-Plane sizing on the ratified 2.5K workload — 2026-08-29

**Verdict: on `t-nominal-2.5k` there is essentially NO aggregation opportunity of the
kind memo §16 assumes.** 900,001 raw events carry **44,280 promoted signals**, of which
**31,955 (72.2 %) are first occurrences of a fresh identity** and **12,325 (27.8 %) are
repeats** — spread so thinly in time that **no identity ever repeats inside 120 s**. A
bounded event-time aggregation window (§16's key) removes **0 % at 60 s, 1.6 % at 300 s,
7.9 % at the engine's own 397 s reach**. Only an unbounded (whole-run) identity key
reaches the 27.8 % ceiling — and that is state the engine already holds. There are
**zero state transitions and zero recovery events in the entire run**, and **one source
/ one vantage per identity**, so §17's high-value classes and §18's corroboration
dimensions are unexercised. **Size P3 against a different workload before designing it.**

## 1. Method (two independent sources, they agree to ±1 event)

| | source | records | signals |
|---|---|---|---|
| A offline | harness generator re-instantiated exactly (`_burst_lanes` + `_syslog_event`, profile `t-nominal-2.5k` = one `("fleet",1.0,"production",1000.0)` lane, 15 min), parsed by the real `producers.syslog_control_signal` | 900,000 | 44,279 |
| B live | Kafka `netops.syslog` **partition 3, offsets 63,059,833→63,970,676** (910,844 records, 2026-08-29 11:38–11:58 UTC), `hostname LIKE 'mlx-%'` filtered, same parser | 900,001 | 44,280 |
| C engine | ClickHouse `corr_signals_archive` for the same window (signals actually attached to incidents) | 139,399 rows | 43,043 unique |

Scripts: `p3_agg_offline.py` (A), `p3_agg_live.py` (B) — both in this scratchpad; C is
plain SQL (`SET tenant_scope='__all__'`). A ≡ B ≡ C on every identity count (K1: 31,954
/ 31,955 / 31,953), which validates the offline generator as an exact stand-in.

> **The profile is `production` mix, not `EVENT_MIX_REALISTIC`** (100 realistic slots +
> 1,900 noise slots). Measured promotion **4.92 %** — so 855,721 raw lines (95.1 %) are
> classified to `None` and never reach the engine. That filter is already an aggregation
> plane of sorts, but it cannot be made cheaper by *aggregation*: the lines are all
> distinct, from distinct devices. The ~789 s of `handle.syslog` is parse cost, and only
> an early mnemonic reject (not a key) can cut it.

## 2. Unique semantic events under the candidate keys (live, n = 44,280)

| key | definition | unique | reduction vs raw signals |
|---|---|---:|---:|
| — | raw promoted signals | 44,280 | — |
| **K3** | K2 + 60 s event-time bucket | 44,280 | **0.0 %** |
| **K4** | K2 + 300 s bucket | 43,578 | **1.6 %** |
| (K4′) | K2 + 397 s bucket = engine temporal reach | 39,642* | 7.9 %* |
| (K4″) | K2 + 900 s bucket = whole run | 35,794* | 16.8 %* |
| **K2** | (tenant, entity_id, kind, severity) | 31,955 | 27.8 % |
| **K1** | (tenant, entity_id, kind) | 31,955 | 27.8 % |
| **K5** | K2 + parsed state (up/down/FULL→DOWN) | 31,955 | 27.8 % |
| (K6) | (tenant, **device**, kind, 60 s) — coarser than entity | 37,927 | 14.3 % |
| (K7) | (tenant, **device**, 60 s) — device-per-minute | 15,003 | 66.1 % |

\* computed on source C (43,043) and shown as its own percentage.
**K1 = K2 = K5 exactly**: severity is a pure function of state, and every identity has
exactly one state for the whole run (§4). Adding severity or state to the key buys
nothing. Bucketing buys nothing until the bucket approaches the whole run.

## 3. Per-kind repeat structure (live)

| kind | raw | identities (K1) | unique K3 (60 s) | repeat factor K3 | repeat factor K1 | first | repeat |
|---|---:|---:|---:|---:|---:|---:|---:|
| link_state_change | 20,330 | 20,256 | 20,330 | **1.00** | 1.00 | 20,256 | 74 |
| bgp_adjacency_change | 7,974 | 2,500 | 7,974 | **1.00** | 3.19 | 2,500 | 5,474 |
| ospf_adjacency_change | 5,318 | 2,216 | 5,318 | **1.00** | 2.40 | 2,216 | 3,102 |
| lldp_neighbor_change | 3,998 | 3,998 | 3,998 | **1.00** | 1.00 | 3,998 | 0 |
| stp_topology_change | 3,547 | 1,572 | 3,547 | **1.00** | 2.26 | 1,572 | 1,975 |
| device_alarm | 3,113 | 1,413 | 3,113 | **1.00** | 2.20 | 1,413 | 1,700 |

Repeats per identity over the whole run: **p50 1, p95 3, p99 4, max 6, mean 1.39**
(31,955 identities). Device-scoped kinds (bgp/ospf/stp/alarm) carry all the repetition;
interface-scoped kinds are nearly one-shot because `if_n = seq % 48` re-keys the entity.

## 4. Causal-significance classification (memo §17/§18)

| class | count | share | rate |
|---|---:|---:|---:|
| **first occurrence of identity** (sync) | 31,955 | **72.2 %** | 35.3 /s |
| **state transition** (sync) | **0** | 0.0 % | 0 /s |
| **recovery transition** (sync) | **0** | 0.0 % | 0 /s |
| **repeat, no state change** (aggregatable) | 12,325 | **27.8 %** | 13.6 /s |

Raw EPS 993.7 · signal EPS 48.9 · unique-semantic (K3) EPS 48.9 · duplicate EPS 13.6 ·
state-changing EPS 35.3 · recovery EPS **0.000** · peak signal EPS in any 1 s **800**
(a 10 s plan chunk lands in one produce call, so signals arrive in 15 spikes).

**Distinct sources per identity: 1. Distinct vantages per identity: 1.** Every signal is
`source=syslog`, `modality=control_plane`, observer = the device itself.

**Why transitions are zero — a harness artifact, verified live.** `_burst_lanes` sets
`dev_i = seq % 2500` and `_syslog_event` sets `state = "down" if seq % 2 == 0 else "up"`;
2,500 is even, so **each device's parity — and therefore its state — is fixed for life**.
ClickHouse confirms on the real run: of 2,500 devices, **2,499 emit exactly one state**
(1 emits two), and **all 30,540 state-bearing K1 identities have exactly one state**
(20,250 `up`, 20,250 `down`). The ratified workload contains no flap, no recovery, and
no contradictory-vs-corroborating structure.

## 5. Funnel and amplification, before vs after aggregation

| stage | today | after ideal K1 aggregation |
|---|---:|---:|
| raw events (durably retained either way) | 900,001 | 900,001 |
| promoted signals reaching the engine | 44,280 | **31,955 (−27.8 %)** |
| unique signals archived against incidents | 43,043 | ~31,000 |
| incidents | 10,672 | 10,672 (unchanged — every identity still first-occurs) |
| object versions persisted | 40,884 | ≥ 29,500 at best (see below) |
| material changes (cause ∨ tier ∨ affected) | 10,332 | 10,332 |
| **root-cause (verdict) changes** | **2,916** | **2,916** |

| ratio | today | after |
|---|---:|---:|
| raw → verdict amplification | **308.6 : 1** | 308.6 : 1 (raw is lossless by design) |
| signal → verdict amplification | **15.19 : 1** | **10.96 : 1** |
| version → verdict (evaluation waste) | **14.02 : 1** | ~10.1 : 1 *if* versions scale with signals |
| version → material change | 3.96 : 1 | 3.96 : 1 |
| archive write amplification | 3.24 archive rows per unique signal | unchanged |

Verdict-change count is a property of the causal graph, not of the input rate, so the
Aggregation Plane cannot improve raw→verdict at all; its whole reachable prize is the
27.8 % of signals that are repeats, and only ~8 % of that is reachable inside the
engine's own 397 s temporal reach.

## 6. Conclusions for the P3 design

1. **Do not design P3 against this workload.** `t-nominal-2.5k` is a *fan-out* storm
   (31,955 distinct identities in 15 min), not a *repetition* storm. Its duplicate mass
   is 27.8 % of a stream that is already only 4.9 % of raw, i.e. **1.4 % of raw events**.
2. **Time-bucketed keys are worthless here** (0 % at 60 s). If P3 ships a bucketed key it
   must be justified on a workload with sub-bucket repetition — S4-chatter (0.5 % of
   devices in <10 s flap loops) or S1-2.5k's 10 %-blast-radius storm lane are the
   candidates. **Recommend re-running this measurement on `s1-2.5k` and `s4-chatter`
   before any P3 code.**
3. **The engine's real cost is not duplicate signals.** 40,884 versions for 2,916 verdict
   changes and 10,332 material changes; `persist.decision` = 2,426 s of ~3,900 s engine
   time. Version damping (memo §9) attacks 14 : 1; aggregation attacks 1.28 : 1.
4. **§18's corroboration dimensions cannot be tested at all** on this data: one source,
   one modality, one vantage per identity, zero recoveries. Any priority scoring built
   now would be validated against a workload that exercises none of its inputs.
5. **The one real front-plane win is early rejection, not aggregation**: 95.1 % of raw
   lines are parsed only to be dropped. A cheap mnemonic/severity pre-filter ahead of the
   full classifier is a measurable `handle.syslog` (789 s) lever and is orthogonal to P3.
