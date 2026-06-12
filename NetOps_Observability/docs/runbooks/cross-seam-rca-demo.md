# Cross-seam RCA demo — Correlation Engine v2 build ⑦ (#67)

The killer-demo deliverable of the agreed build order: prove, on the live
stack, that a fault becomes a **topology-grounded, multi-observer, replayable
correlation object with an honest verdict** — and provide the owner runbook
for the full cross-seam act (LAN → SD-WAN → underlay → cloud/POP) on the lab.

Two halves:

* **Act L (local, executed 2026-06-12, transcript below)** — a real outage of
  a scratch service observed by two independent vantage points. Proves the
  whole pipeline end-to-end live: probe evidence lane → spine → grounding
  gate → object → versioning → zero-drift replay — and, critically, what the
  engine **refuses** to claim.
* **Act X (cross-seam, owner-run)** — the WAN/fabric fault on the clos lab
  that exercises seam grounding, the control-plane lane, multi-modality
  confirmation and direction. Scripts below; needs lab-host access.

---

## 1. What build ⑦ wired (the missing evidence lanes)

The engine is only as honest as its evidence diversity. Before this build the
spine carried a single lane (Telegraf metrics → CUSUM → `device_telemetry`).
Two lanes were added:

**Probe lane (`active_probe`)** — the STAMP sender and the synthetics runner
(both the `api` collector and the `prober` sidecar) now POST every
observation to Vector (`PROBE_EVENT_SINK_URL`, http_server :8689) → topic
`netops.probes` → `handle_probe`:

* loss ≥ 5 % (or a failed check) → discrete `probe_loss` signal
  (warn < 25 % ≤ high < 75 % ≤ crit), entity `path:<prober>-><host>`;
* RTT runs through the same CUSUM episode detector → `probe_rtt_anomaly`
  episodes with onset uncertainty;
* observer block: `observer_id` = `PROBER_ID` (compose sets `api` / `prober`
  — two distinct vantage points), `observer_type=vantage_agent`,
  `collection_path=direct`. Wire contract pinned by
  `collectors/probe_events_test.go` ↔ `test_producers.py`.

**Control-plane lane (`control_plane`)** — `handle_syslog` now extracts
adjacency/link events before the legacy burst counter:

* `%BGP-5-ADJCHANGE` / `%OSPF-5-ADJCHG` → `bgp|ospf_adjacency_change`,
  entity = device, `entity_tokens` include the **peer IP** (both ends of a
  dropped session emit the same peer token → that shared token is exactly
  what the grounding gate needs);
* `%LINK-*-UPDOWN` / `%LINEPROTO-*-UPDOWN` → `link_state_change`, entity =
  `device:interface`;
* down ⇒ high, up ⇒ warn; event time = the RFC5424 timestamp, not ingest
  time; observer = the device itself (`collection_path=direct`).

Both lanes dead-letter on missing provenance — never guess.

---

## 2. Act L transcript (2026-06-12, live stack)

Setup: scratch nginx (`corr-demo-target`, NOT part of the compose project so
the external watchdog stays silent) added to both observers' synthetic
target lists. ~4 healthy probe cycles, then `docker stop corr-demo-target`
at **14:23:45Z**.

| t+ | what happened |
|----|---------------|
| 16 s | `probe_loss` crit (100 %) from observer `prober` (http + tcp checks) |
| 17 s | `probe_loss` crit from observer `api` — second, independent vantage point |
| 43 s | engine cycle: object **`9f0537bd-0787-547e-a6fc-6692acaec13c` v1 open**, 2 nodes, 1 edge |
| 73 s | v2 (new loss signals attached — content-hash versioning, append-only) |
| ~3 m | target restored; loss signals stop; object quiesce-closes after the window drains |

The one edge — **grounded, not co-occurrence**:

```
path:prober->corr-demo-target:probe_loss  →  path:api->corr-demo-target:probe_loss
grounding: topo  shared:corr-demo-target   weight 0.90   direction: none (no claim)
```

The verdict — **the honesty story**:

```
top_hypothesis: undetermined     verdict_tier: undetermined
evidence_missing:
  sig.ent.cloud.region-degradation: needs probe_latency_departure|probe_loss   (≥3σ, segment-scoped)
  sig.ent.cloud.region-degradation: needs lb_5xx|cloud_gw_anomaly|cloud_health_event
  sig.ent.internet.dns-impairment:  needs dns_latency_high|dns_failure_rate
```

Two independent observers agree the path is dead — but with one modality and
no cloud-side witness, no catalog signature may claim a root cause. The
engine says *what would confirm* instead of guessing. (The fixture battle in
build ④ exists precisely because an earlier draft over-claimed cloud blame
from one probe_loss.)

Replay, against the live store:

```
GET /correlations/9f0537bd-…/replay →
{ "stored_version": 3, "engine_pin_match": true, "catalog_pin_match": true,
  "clean": true, "differences": [] }
```

Full-window archive slice present (4+ rows per version in
`corr_signals_archive`) — the object is re-runnable forever.

---

## 3. Act X — the cross-seam act (owner runbook)

Goal: one fault at the WAN boundary / fabric produces a **seam-grounded,
multi-modality, ≥2-observer `confirmed` object with direction**. Everything
below is owner-run (lab-host access + seam inventory are owner workflow).

### 3.1 One-time: bind the probe path to the DIA seam

The active seam `sm-f50987032a4d` (WAN boundary 172.40.40.52) does not yet
intersect probe-path tokens. Declare the binding — "probes to 10.70.245.120
cross this seam" — by adding the target to the seam endpoints (this is the
#69 Observability-Bindings idea in v0 form):

```bash
TOK=$(curl -s -X POST http://localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<admin password>"}' | jq -r .token)
curl -s -X PATCH http://localhost:8000/api/seams/sm-f50987032a4d \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"endpoints":{"interface":"0","on_prem":"172.40.40.52","probe_target":"10.70.245.120"}}'
```

After the next seam export (`/data/enrichment/seams.json`), probe episodes to
`.120` ground as `seam:sm-f50987032a4d` instead of `topo:shared` — and the
hypothesis verdict can inherit the seam's `control_plane_owner: isp`.

### 3.2 Stage A — middle-mile degradation (suspected, honestly)

On the lab host (10.70.245.120), degrade the WAN path for ~5 minutes:

```bash
# all platform→lab probes (STAMP, ICMP, TCP:22) gain latency + loss
sudo tc qdisc add dev <wan-if> root netem delay 80ms 10ms loss 15%
sleep 300
sudo tc qdisc del dev <wan-if> root
```

Expected: `probe_rtt_anomaly` episodes (STAMP from `prober`, ICMP/TCP from
both observers) + `probe_loss` — seam-grounded via the §3.1 binding, but
**one modality** → tier stays `suspected` with `evidence_missing` naming the
absent device-side witness. The correct verdict for a middle-mile event we
cannot see inside: that *is* the DIA visibility cliff.

### 3.3 Stage B — fabric link fault (confirmed, with direction)

Down one leaf↔spine link at the veth level (a "pulled cable", reversible):

```bash
sudo containerlab inspect -a | grep -i 'leaf1\|spine1'   # find the link
sudo ip link set <clab-veth-leaf1-spine1> down
sleep 240
sudo ip link set <clab-veth-leaf1-spine1> up
```

Expected evidence chain (one object):

* `%BGP-…ADJCHANGE` syslog from **both** leaf1 and spine1 →
  `bgp_adjacency_change` control_plane signals sharing the peer-IP token
  (grounded edge, two observers);
* `%LINEPROTO/LINK UPDOWN` → `link_state_change` (interface entity);
* interface-counter CUSUM episodes from Telegraf (`device_telemetry`,
  third modality class);
* verdict gate: ≥2 modality classes × ≥2 independent observers →
  **confirmed**; direction from onset order + layer prior (interface/device
  below path) when probes are also affected.

### 3.4 Replay both objects

```bash
curl -s http://localhost:8000/... # via the correlation service:
docker compose exec correlation python -c \
  "import urllib.request,json;print(json.load(urllib.request.urlopen('http://localhost:8000/correlations/<id>/replay')))"
```

`clean: true` is the acceptance bar — same archived window, same pins, same
object, byte-identical.

### 3.5 Full narrative (no lab required)

The LAN→SD-WAN→underlay→cloud/POP storyline end-to-end is pinned by the CI
golden fixture `src/correlation/fixtures/golden-dallas-window.json`
(the #67 §6 Dallas scenario incl. an ungrounded bystander that must stay
excluded). `pytest test_replay.py` replays it on every PR.

---

## 4. Verification checklist (what build ⑦ proved live)

- [x] probe events on the bus from two distinct observers (api, prober) × 4 kinds incl. STAMP
- [x] `probe_loss` signals < 20 s after fault, correct severity tiers, dead-letter = 0
- [x] grounding gate: edge admitted ONLY via shared-token topology grounding; gap hints = 0 false edges
- [x] object versioning v1→v3 on evidence change, append-only, archive slice per version
- [x] verdict honesty: `undetermined` + named evidence shortfalls (no single-modality over-claim)
- [x] `/replay` clean against the live store (engine + catalog pins match)
- [ ] seam-grounded probe edges (needs §3.1 owner binding)
- [ ] control-plane lane live fire + `confirmed` tier (needs §3.2/3.3 lab fault; parser unit-tested)
