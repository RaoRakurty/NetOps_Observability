# RCA hero demo — rehearsal checklist

Run this **end to end before every live demo**, on the machine and the stack you
will actually present from. A rehearsal that passes on a different host is not a
rehearsal.

Fill the **actual** column every run. This sheet is the *demo effectiveness*
instrument for the pilot metrics
(`docs/runbooks/pilot-playbook.md` §4, metric 5) — an empty timing column means
that metric is **not yet measured** for this demo.

**Run record**

| field | value |
|---|---|
| date / time (UTC) | |
| presenter | |
| host | |
| stack build (`/admin/version`) | |
| injection method | `demo_fill --degrade` · `twin.py run` |
| audience | |
| overall verdict | **PASS** / **FAIL** |

---

## A. Pre-flight (target 15 min, T-15 before the audience)

| # | check | pass condition | fail action | target | actual |
|---|---|---|---|---|---|
| A1 | `scripts/install-correlix.sh status` | every service running/healthy **and** the `:8000` probe answers | do not demo — fix the stack | 1:00 | |
| A2 | Root filesystem free space | **≥ 10 GiB** free | free space first; below OpenSearch's flood-stage watermark the router discards evidence documents and the incident renders thin | 0:30 | |
| A3 | Host clock | in sync (NTP) | fix before injecting — event time comes from the emitted timestamp, and skew puts symptoms outside the correlation window | 0:30 | |
| A4 | Login | `POST /api/auth/login` returns a `token`; UI login succeeds | reset the admin credential (`scripts/reset-admin.sh`) | 0:30 | |
| A5 | `GET /api/health` | returns `status: healthy` | triage before demoing | 0:30 | |
| A6 | `python3 scripts/seed_demo_data.py` | exits 0; flows / metrics / tunnels / findings seeded | rerun; check ClickHouse + VictoriaMetrics are up | 3:00 | |
| A7 | `python3 scripts/demo_fill.py --once` | exits 0; the tick line reports non-zero counts for **syslog, traps, probes, metrics** | a zero count on any of those four means that pipeline is down — fix it, do not demo around it. `traceroute=0` is tolerable: that lane writes to the Valkey cache (compose service `redis`) and only feeds the Flow Trace panel, which is not on the demo path | 2:00 | |
| A8 | Panels have depth | Analytics → Device Monitoring and Interface Performance render series, not empty states | rerun A6/A7; check the VM push landed | 1:00 | |
| A9 | Explore → Logs | returns rows for `signal=syslog` | syslog lane down — check the host `:5514` binding | 0:30 | |
| A10 | Explore → Flows | returns rows | flow seed did not land | 0:30 | |
| A11 | Clean starting state | no leftover incident from a previous run visible on Command Center | run [`RESET.md`](RESET.md) | 1:00 | |
| A12 | Browser parked | logged in, Command Center in tab 1, RCA page in tab 2, terminal visible | — | 0:30 | |
| A13 | Second screen / share tested | the terminal tick output **and** the browser are both legible to the audience | — | 1:00 | |

**A-block gate:** any FAIL in A1–A11 = **do not demo**. A12/A13 failing is
recoverable in the room.

---

## B. Act 1 — injection (target 2:00)

| # | check | pass condition | fail action | target | actual |
|---|---|---|---|---|---|
| B1 | Injection starts | `demo_fill.py --duration 300 --step 30 --degrade` prints its first `tick (degraded): …` line | check the compose project is reachable from the shell | 0:15 | |
| B2 | Syslog lands | new rows in Explore → Logs within ~30 s | syslog lane down | 0:30 | |
| B3 | Series bend | interface / BGP-peer-state series move in Analytics → Device Monitoring | VM push failed | 0:30 | |
| B4 | Incident appears | a row on Command Center **and** in Operations → Incidents | the engine admitted no evidence — check the admission rule (`docs/INGESTION.md` §"What reaches correlation") and `corr_ingest_prefilter_total` | 1:00 | |
| B5 | **One** incident, not a wall | the fault presents as a single correlated row, not N unrelated alerts | this is the whole pitch — if it fragments, stop and investigate before demoing again | — | |

---

## C. Act 2 — the six-question header (target 3:00)

Each row must be answerable **from the header, above the fold, without
scrolling**. Score 6/6 or name the miss.

| # | question | pass condition | actual answer given | ✓/✗ |
|---|---|---|---|---|
| C1 | **What broke?** | Case title + **Root cause** row names the object, or states the honest non-claim ("Not confirmed — possibly because of X" / "Not identified — no cause hypothesis has supporting evidence yet") | | |
| C2 | **Why believe it?** | Verdict pill + Confidence + **Decision** callout render; *Ruled out* and "How was this verified?" reachable one section down | | |
| C3 | **What is affected?** | **Affected** row shows devices/peer/apps, or **"Not yet determined"** — never a bare `0` | | |
| C4 | **Who owns it?** | **Owner** / **Possible owner** names a seam party (ISP · carrier · cloud provider · app team) or "Not yet narrowed — NOC triage" | | |
| C5 | **What evidence?** | **Evidence** row reads *N symptoms · M independent sources · duration*; the density strip renders | | |
| C6 | **Is it recovering?** | **Incident** pill reads Active / Recovering / Recovered, distinct from the verdict pill | | |
| C7 | Vocabulary | the word **"Signals"** appears nowhere in the operator UI (it is "Observations") | | |
| C8 | No fabricated numbers | no percentage, count or duration on screen that the engine did not measure | | |

**Score: ___ / 6** (C1–C6). C7 and C8 are hard fails regardless of score.

---

## D. Act 3 — path, evidence, owner (target 2:00)

| # | check | pass condition | target | actual |
|---|---|---|---|---|
| D1 | Path renders | **Network path & causality** draws a typed path | 0:30 | |
| D2 | Break is visible | exactly **one** red break hero — on the device, or on the seam boundary, never both | 0:30 | |
| D3 | Honest gaps | undiscovered spans are dotted / "path not fully discovered", never invented hops | 0:15 | |
| D4 | Ownership line | the seam's responsible party is named on the path | 0:15 | |
| D5 | Evidence matrix | lists observations with their observer; independence is visible | 0:30 | |

---

## E. Act 4 — recovery, PDF, ticket (target 2:00)

| # | check | pass condition | target | actual |
|---|---|---|---|---|
| E1 | Lifecycle | the Incident pill moves, or the case is honestly still Active | 0:15 | |
| E2 | Time impact | phase split renders; inferred stages are **labelled inferred** | 0:30 | |
| E3 | Recovery Scorecard | `#/analytics/scorecard` opens; "Not measured" states are shown, not skipped | 0:30 | |
| E4 | **PDF export** | ⤓ Export PDF downloads; the PDF carries the same graph the page drew | 0:30 | |
| E5 | Ticket card | renders the confirmed *or* the held ("auto-ticketing holds until independent evidence confirms") outcome | 0:15 | |

---

## F. Post-run

| # | action | done |
|---|---|---|
| F1 | Total elapsed recorded (target **10:00** of narration) | |
| F2 | [`RESET.md`](RESET.md) run | |
| F3 | Questions the product could not answer → `feature-request.yml` | |
| F4 | Anything answered **wrongly** → `rca-verdict-feedback.yml` | |
| F5 | This sheet filed with the run record | |

---

## Known failure modes, and what they actually mean

| symptom | most likely cause |
|---|---|
| Logs arrive but no incident forms | The lines did not clear the admission rule — informational severity with no typed symptom marker. Check `corr_ingest_prefilter_total`; see `docs/INGESTION.md` §"What reaches correlation". Usually correct behaviour, not a bug. |
| Incident forms but the header is sparse | Single-modality evidence. The engine is refusing to over-claim — present it as such (SCRIPT.md Act 2). |
| Panels render empty | `seed_demo_data.py` / `demo_fill.py` did not reach ClickHouse or VictoriaMetrics (neither is host-exposed; both are reached via `docker compose exec`). |
| Incident is thin, evidence missing | Root filesystem crossed OpenSearch's flood-stage watermark mid-run and evidence documents were discarded. Check A2. |
| Symptoms land outside the window | Host/device clock skew. Check A3. |
| A stale incident from the last run is on screen | [`RESET.md`](RESET.md) was not run. |
