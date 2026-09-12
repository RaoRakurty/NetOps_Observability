# Live proof — Security verdicts + BGP operations (lab stack, 2026-09-03)

Run window: **2026-09-03 05:06Z – 05:19Z**. Executed against the running
Correlix lab stack on `:8000` (HTTP behind nginx — `https://localhost:8000`
fails the TLS handshake, `wrong version number`; every command below is plain
HTTP), authenticated as the platform admin.

| Fact | Value |
|---|---|
| Repo HEAD at run time | `c454f53c` (the task named `500acabb`; four commits landed after it) |
| `netops-api-1` image built | `2026-09-03T04:36:04Z` — **contains** `36f66cf4` (security verdicts) and `8fb50b4a` (BGP watchlist/bogons), both 04:28 |
| `netops-frontend-1` image built | `2026-09-03T00:50:53Z` — **predates** `e8e85f85` (04:15 one-page BGP view), `36f66cf4` (04:28 security UI), `5f788707` (04:49 licences) |
| `netops-correlation-7` image built | `2026-09-03T00:49:12Z` |
| Tenant under test | `lab` = `t_d3d501aa08e2395893b378a453b8af67`, owns `spine1`/`spine2` (Nokia SR Linux, 172.40.40.11/.12) |
| App-state backend | file/KV — `DATABASE_URL` is **empty** in the api container, so the BGP watchlist is on `bgpwatch.WatchFileStore` (`/data/bgp_watchlist.json` → host `data/api/bgp_watchlist.json`) |

Devices were **never** written to. No container was restarted. Every object
created for this run was deleted (§Cleanup).

---

## Verdict summary

| § | Item | Verdict |
|---|---|---|
| A1 | Security verdicts are real per scan | ✅ PASS |
| A1b | The findings **page** still reads "mostly Unknown" | ❌ **DEFECT L-01** |
| A2 | Frameworks catalogue / HIPAA opt-in / compliance scorecards / isolation | ✅ PASS |
| A3 | Exposure stories | ❌ still empty (known D-01) |
| A4 | New security UI strings in the served bundle | ❌ **DEFECT L-02** — frontend image is 4 commits stale |
| B1 | Watchlist persists on the file backend | ✅ PASS |
| B2 | `rpki_invalid` alert → Kafka → engine → `corr_signals` | ✅ PASS |
| B3 | Resource lookup (RPKI / visibility / AS-path / RDAP / geofeed) | ✅ PASS |
| B4 | Near-live feed | ❌ **DEFECT L-03** — 9 polls, 0 errors, 0 updates, no explanation |
| B5 | Bogon set + BMP sighting + isolation | ✅ PASS |
| B6 | Cleanup | ✅ PASS (two in-memory residues disclosed) |

---

## A. Security verdicts

### A1 — scan → findings (✅ PASS)

```
$ curl -s -X POST 'http://localhost:8000/api/security/scan?as_tenant=t_d3d…af67' \
       -H 'Authorization: Bearer <redacted>' -d '{}'
HTTP 202  {"queued":true,"tenant_seg":"t_d3d501aa08e2395893b378a453b8af67"}
                                                       # 2026-09-03T05:06:17Z

$ curl -s 'http://localhost:8000/api/security/lane/status?as_tenant=t_d3d…af67'
HTTP 200
 last_scan_id       = scan-t_d3d501aa08e2395893b378a453b8af67-20260903T050617.414Z
 outcome=ok  trigger=manual  duration_ms=635
 findings_emitted=30  findings_truncated=0  devices_assessed=2
 metrics: emitted_posture=28  emitted_exposure=2  dead_lettered_total=0
          emit_failures_total=0  lost_total=0  ungroundable_total=0
```

**30 findings / 2 devices = 15 per spine** (was 32). Per-spine breakdown
(`GET /api/security/findings?as_tenant=…&since=2026-09-03T05:00:00Z`, HTTP 200,
`total: 30`) — identical for `spine1` and `spine2`:

| status | count | rule ids |
|---|---|---|
| **Fail** | 6 | `http-server-nontls` (SC-8, high) · `mgmt-api-unencrypted` (SC-8, high) · `snmp-v1v2c-community` (IA-5, high) · `no-remote-aaa` (AC-2, medium) · `no-ntp-server` (AU-8, medium) · `tls-no-client-auth` (IA-3, low) |
| **Pass** | 3 | `local-user-weak-secret` · `no-central-logging` · `snmp-default-community` |
| **NotApplicable** | 5 | `telnet-vty-enabled` · `snmp-no-source-acl` · `no-service-password-encryption` · `weak-enable-password` · `ssh-not-v2` |
| **Unknown** | 1 | `advisory-unassessed` |

**The expected FAIL set is matched exactly, in both directions** — all six
expected rules fail, and nothing else does.

Every `NotApplicable` carries a device-specific reason, e.g.

```json
{"status":"NotApplicable","raw_rule_id":"ssh-not-v2","control":"SC-8",
 "status_detail":"SR Linux implements SSHv2 only — there is no SSHv1 to fall back to and no version knob to …"}
{"status":"NotApplicable","raw_rule_id":"telnet-vty-enabled","control":"AC-17",
 "status_detail":"SR Linux implements no telnet server anywhere in its management model — the control cannot …"}
```

The one `Unknown` carries its reason:

```json
{"status":"Unknown","raw_rule_id":"advisory-unassessed","evidence_class":"exposure",
 "status_detail":"OS product/version not present in sysDescr — advisory exposure not assessed",
 "id":"bcf417117a269a4ba2a854cb96d144d26a55d4f24eebdeef8b9e7802496c9679"}
```

A `Fail` carries a real evidence locator:

```json
{"status":"Fail","raw_rule_id":"no-ntp-server","control":"AU-8","severity":"medium",
 "evidence_ref":{"locator":"running-config:spine1#no-ntp-server","kind":"config-line",
                 "ruleset_version":"correlix-hardening-2026-08-27"},
 "id":"41dd49fbe491540f88ceb50da84a28452ecf72dd50973a3484a5b7ac1381bf12"}
```

### A1b — DEFECT L-01: the operator still sees "all Unknown" (❌)

The per-scan result is right; **the page is not.** `current=true` is documented
as "collapses to the latest verdict per finding identity", but the collapse key
includes the scan id, so it can never collapse two scans:

`src/backend/internal/secbus/event.go:183`
```go
func nativeIDOf(f secfindings.Finding, entityID, kind string) string {
	raw := strings.Join([]string{
		"security", kind, f.EvidenceClass, f.ControlID, entityID, f.ScanID, f.ID,
	}, "|")
```
`src/backend/secapi/query.go:263` → `body["collapse"] = map[string]any{"field": FieldNativeID}`

Observed native_id:
`security|security_posture|posture|AU-8|spine1|scan-…-20260903T050617.414Z|no-ntp-server`

Live consequence:

```
$ curl -s '…/api/security/findings?as_tenant=t_d3d…af67&limit=500&current=true'
HTTP 200  total: 572   page-1 statuses: Unknown 444 · Fail 24 · Pass 12 · NotApplicable 20
   scans represented: 050617.414Z(30) 045317.880Z(30)
                      043736.040Z(64) 042309.011Z(64) 041332.507Z(64) 041027.075Z(64)
                      040523.613Z(64) 035954.277Z(64) 034325.938Z(56)
   Unknown rows carrying status_detail: 4 of 444
```

440 of the 444 Unknowns are pre-fix verdicts from 03:43–04:37Z that were never
superseded and never will be, because the newer catalogue no longer emits those
rule identities. **The owner's original complaint — "verdicts were all Unknown"
— is still the literal answer the Findings page gives**, and it also poisons the
compliance scorecard (`AC-17` reports `Fail` with 168 findings although the
current scan says `NotApplicable`; `current_findings: 602`).

Same run also re-confirms the A4 defect: `GET /api/security/findings/<id>`
→ **HTTP 404 `{"error":"finding not found"}`** for `41dd49fb…` (an id the list
route had just returned).

### A2 — frameworks, HIPAA, compliance, isolation (✅ PASS)

```
$ GET /api/security/frameworks?as_tenant=t_d3d…af67          HTTP 200
  configured: false
  nist-800-53-r5     "NIST SP 800-53 Rev5"  Rev 5 (Release 5.2.0)  enabled=true
  cis-controls-v8    "CIS Controls v8.1"    8.1                    enabled=true
  hipaa-security-rule "HIPAA Security Rule" 45 CFR 164.312         enabled=false
  nist-csf-2.0       "NIST CSF 2.0"         2.0                    enabled=false
  pci-dss-v4         "PCI DSS v4.0.1"       4.0.1                  enabled=false
  + benchmarks[] with sections_verified per platform (cis-cisco-ios-17 true,
    cis-arista-eos false with the reason recorded)

$ PUT /api/security/frameworks?as_tenant=t_d3d…af67
      [{"framework_id":"hipaa-security-rule","enabled":true}]       HTTP 200
$ GET /api/security/frameworks?as_tenant=t_d3d…af67                 HTTP 200
  configured: true — 800-53 ✓, CIS ✓, HIPAA ✓, CSF ✗, PCI ✗
```

Five frameworks, the two shipped defaults on, the closed catalogue as designed.

```
$ GET /api/security/compliance?as_tenant=t_d3d…af67                 HTTP 200
 enabled = [nist-800-53-r5, cis-controls-v8, hipaa-security-rule]  configured=true

 NIST SP 800-53 Rev5   scope=18 checks=16 assessed=13 pass=2 fail=7 unassessed=3  Fail  22.2 %
 CIS Controls v8.1     scope=18 checks=16 assessed=13 pass=2 fail=7 unassessed=3  Fail  22.2 %
 HIPAA Security Rule   scope=10 checks=8  assessed=8  pass=2 fail=6 unassessed=0  Fail  25.0 %
```

One scorecard per **enabled** framework, HIPAA present the moment it is enabled.
The projections are real, not tags — same 800-53 control, different citation:

| 800-53 control | CIS Controls v8.1 | HIPAA Security Rule |
|---|---|---|
| AC-17 | CIS-12 | 164.312(a)(1) |
| AC-2 | CIS-5 | 164.312(a)(2)(i) |
| AC-4 | CIS-13 | — |
| AU-2 | CIS-8 | 164.312(b) |

**Isolation (second tenant).** Created `qa-live-proof-temp` =
`t_7ddfd9f76baa59240e8652cccf3ccd93` (`POST /api/tenants` → HTTP 201):

```
GET /api/security/frameworks?as_tenant=t_7ddf…cd93   HTTP 200
    configured=false · HIPAA enabled=false          ← lab's selection NOT visible
GET /api/security/compliance?as_tenant=t_7ddf…cd93   HTTP 200
    enabled=[nist-800-53-r5, cis-controls-v8]  configured=false
    current_findings=0  assessed_findings=0
    NIST 800-53: assessed=0  score_percent=null  verdict=Unknown   ← null, not 0 %
    CIS v8.1:    assessed=0  score_percent=null  verdict=Unknown
GET /api/security/findings?as_tenant=t_7ddf…cd93     HTTP 200
    {"items":[],"next_cursor":null,"total":0}
```

Score is `null` where nothing was assessed — an unassessed control is never
reported as a pass.

### A3 — exposure stories (❌ still empty, known D-01)

```
$ GET /api/security/exposure-stories?as_tenant=t_d3d…af67   HTTP 200   []
$ GET /api/security/posture?as_tenant=t_d3d…af67            HTTP 200
  coverage {assessed_assets:2, total_assets:2, unassessed:0}
  funnel   {discover:602, scope:2, prioritize:242, validate:0, mobilize:0}
```

Unchanged from the A4 scenario run: the list is empty while the engine reports
`corr_evidence_events_total{class="security",outcome="grounded"} = 60`. Recorded
only; the fix is in flight.

### A4 — served SPA bundle (❌ DEFECT L-02)

```
$ curl -s http://localhost:8000/                       HTTP 200
    → /assets/index-D_eSINQ_.js , /assets/index-DbhWBhZ8.css
$ curl -s http://localhost:8000/assets/SecurityCompliance-BR89osqP.js   HTTP 200  10 870 B
$ curl -s http://localhost:8000/assets/Exposures-DZrsUanU.js            HTTP 200   6 768 B

grep -c -F on the served chunks:
  "Why unassessed"  → 0        "Add framework" → 0
  "HIPAA"           → 0        "CIS Controls"  → 0        "status_detail" → 0
```

The strings exist in the tree — `src/frontend/src/pages/security/parts.tsx:220`
(`<h4 className="sec-facet-h">Why unassessed</h4>`) and
`src/frontend/src/pages/security/ComplianceFrameworks.tsx:129` (`Add framework…`)
— and in the **local** `src/frontend/dist` built 04:29
(`parts-BrTjsSNE.js`, `SecurityCompliance-vtjBzxz1.js`, 16 771 B). They are not
in the image that is serving.

Every chunk hash differs, so this is the whole SPA, not one page:

| chunk | served (image 00:46) | local dist (04:29) |
|---|---|---|
| SecurityCompliance | `BR89osqP` 10 870 B | `vtjBzxz1` 16 771 B |
| Exposures | `DZrsUanU` | `C60Re2WL` |
| BgpOps | `CGsNJ1pt` | `DLg8Ovld` |
| BogonsPanel | `BhcxbyaG` | `Dol5fIWb` |
| LiveFeedPanel | `CsKZozCx` | `DgiLrDXp` |
| PrefixesPanel | `B9YoMy05` | `7wde3WYJ` |

`netops-frontend-1` was **recreated** at 04:53:04Z but from the **same image
built 00:50:53Z**. So `e8e85f85` (one-page BGP outage view), `36f66cf4`
(security UI) and `5f788707` (`/licenses/` page) are **not deployed**. Fix is
the standing rule: `npm run build` in the main tree, then
`docker compose build frontend`, then verify a marker string in the served
bundle.

---

## B. BGP operations

### B1 — watchlist on the file backend (✅ PASS)

```
2026-09-03T05:12:16Z
POST /api/bgp/watchlist?as_tenant=t_d3d…af67
  {"resource":"1.1.1.0/24",     "note":"live-proof … APNIC anycast, RPKI valid"}
    HTTP 200 {"kind":"prefix","ok":true,"resource":"1.1.1.0/24"}
  {"resource":"93.175.146.0/24","note":"… RIPE RPKI test prefix, VALID ROA"}
    HTTP 200 {"kind":"prefix","ok":true,"resource":"93.175.146.0/24"}
  {"resource":"93.175.147.0/24","note":"… RIPE RPKI test prefix, INVALID ROA"}
    HTTP 200 {"kind":"prefix","ok":true,"resource":"93.175.147.0/24"}

GET /api/bgp/watchlist?as_tenant=t_d3d…af67   HTTP 200 — all three, added_by "admin",
  created_at 05:12:16.504 / .676 / .840Z
  incidents_status {enabled:true, interval:"5m0s", cooldown:"1h0m0s",
                    evidence_topic:"netops.bgp", peer_rule_enabled:true,
                    notify_wired:true, evidence_wired:true}
```

Durability on the FILE backend, read from the host bind mount (not edited):

```
$ ls -la data/api/bgp_watchlist.json
-rw------- 1 rao rao 570 Sep  3 05:12
$ cat data/api/bgp_watchlist.json
{"t_d3d501aa08e2395893b378a453b8af67":[
  {"resource":"1.1.1.0/24","kind":"prefix","note":"live-proof 2026-09-03 — APNIC anycast, RPKI valid",
   "added_by":"admin","created_at":"2026-09-03T05:12:16.504993772Z"}, … ]}
```

Tenant-keyed, mode 0600. (Backend selection: `main.go:927` — PG when
`platformdb.ActivePG()`, else the file register; `DATABASE_URL` is empty here.)

### B2 — evaluator → alert → Kafka → engine (✅ PASS)

Sweep cadence `bgpwatch.DefaultInterval = 5m` (`internal/bgpwatch/evaluate.go:37`);
`FEATURE_BGP_ALERTS=true`. Sweep at **05:14:49.516Z** (run #4).

```
GET /api/bgp/alerts?as_tenant=t_d3d…af67&limit=200   HTTP 200
 alerts: 1   incidents: 3
 metrics (tenant-scoped): runs_total=4  prefixes_evaluated_total=3
   alerts_notified_total=1  alerts_suppressed_total=0  alerts_resolved_total=0
   bogon_sightings_total=2  run_errors_total=0  observe_errors_total=0
   peer_errors_total=0  sighting_errors_total=0  evidence_skipped_total=0
```

The one alert — **only** the RIPE INVALID prefix:

```json
{"id":"bgp:t_d3d501aa08e2395893b378a453b8af67:93.175.147.0/24:rpki_invalid",
 "rule":"bgp_rpki_invalid","severity":"high","class":"rpki_invalid",
 "resource":"93.175.147.0/24",
 "summary":"RPKI INVALID for 93.175.147.0/24 from AS12654 — a ROA exists but names a different origin AS.",
 "detail":"… A stale ROA and a hijack look identical here — check the ROA before assuming an attack.",
 "labels":{"class":"rpki_invalid","prefix":"93.175.147.0/24","source":"bgp-watch"},
 "fired_at":"2026-09-03T05:14:49.5160622Z"}
```

Incidents, all three watched prefixes classified:

| prefix | class | severity | evidence |
|---|---|---|---|
| 93.175.147.0/24 | `rpki_invalid` (also `visibility_loss`) | high | origins `{AS12654:55}`, peers_seeing 48 / 327 |
| 93.175.146.0/24 | `none` | info | origins `{AS12654:64}`, peers_seeing 278 / 327 |
| 1.1.1.0/24 | `none` | info | origins `{AS13335:64}`, peers_seeing 110 / 111 |

**Evidence reached the bus and the engine.** Correlation container log:

```
2026-09-03 05:14:53,082 INFO correlation evidence signal bgp_rpki_invalid:
    class=bgp entity=93.175.147.0/24 sev=high seam=
```

VictoriaMetrics (`corr_evidence_events_total`, job=correlation):

```
class="bgp"      outcome="orphan"   = 1   (first non-zero at 05:15)
class="bgp"      outcome="invalid"  = 0
class="bgp"      outcome="grounded" = 0
class="security" outcome="grounded" = 60
```

`outcome=orphan` is **the designed and tested outcome**, not a failure: a prefix
is never a device-registry row, so it is kept, filed under its own tenant and
counted — `src/correlation/test_bgp_grounding.py:578`
`test_a_prefix_the_registry_never_heard_of_is_orphan_not_misattributed`. What
matters is `invalid=0` (nothing rejected, nothing dead-lettered) and that the
row landed:

```sql
-- clickhouse-client, SET tenant_scope='__all__'
SELECT ts, tenant_id, source, kind, entity_id, severity
  FROM netops.corr_signals WHERE source='bgp' ORDER BY ts DESC LIMIT 10;

2026-09-03 05:14:49.516  t_d3d501aa08e2395893b378a453b8af67  bgp  bgp_rpki_invalid  93.175.147.0/24  high
```

Full chain proven: **watchlist → 5-minute evaluator → alert → `netops.bgp` →
correlation consumer → `netops.corr_signals`, tenant-correct end to end.**

### B3 — resource lookup (✅ PASS, live upstream data)

`GET /api/bgp/resource?resource=1.1.1.0/24&view=…&as_tenant=…` (all HTTP 200):

| section | result |
|---|---|
| `rpki` | `status: valid`, validator `routinator`, ROA `{origin 13335, prefix 1.1.1.0/24, max_length 24, validity valid}`; `rpki_origin: AS13335` |
| `routing_status` | visibility v4 **110 / 111 RIS peers**; first_seen origin 19855 @2001-11-14; last_seen origin 13335 @2026-09-03 |
| `paths` | **23 RRCs** with per-peer AS-path / communities / next-hop (e.g. RRC01 London LINX/LONAP, `as_path "15692 13335"`, latest 05:12:52Z) |
| `view=updates` | RIPEstat `bgp-updates`, real seqs and AS paths (e.g. `path [53046,61626,268581,13335]` @2026-09-02T21:14:54) |
| `view=whois` (RDAP) | APNIC, `name "APNIC-LABS"`, country AU, registration 2011-08-10, remarks "APNIC and Cloudflare DNS Resolver project / Routed globally by AS13335" |

`GET /api/bgp/rpki?as_tenant=…` (no `resource` → validates the whole watchlist),
HTTP 200, `from_watchlist:true`, sorted worst-first:

```
93.175.147.0/24  origin=AS12654  state=invalid  reason=origin_as  validator=routinator  roas=1
1.1.1.0/24       origin=AS13335  state=valid                      validator=routinator  roas=1
93.175.146.0/24  origin=AS12654  state=valid                      validator=routinator  roas=1
```

Exactly the RIPE test-prefix expectation: `.147` INVALID, `.146` VALID.

`GET /api/bgp/aspath-graph?prefix=1.1.1.0/24` — HTTP 200, `source: bgp-state`,
**299 nodes / 315 edges / 371 paths**, `edges_capped:false`, real AS names
(`13335 CLOUDFLARENET` depth 0 origin; transit `1299 TWELVE99`, `6461 ZAYO-6461`,
`9002 RETN-AS`, `199524 GCORE` …).

`GET /api/bgp/geofeed?resource=1.1.1.0/24` — HTTP 200, **honest empty state**:
`{"published":false,"entries":[],"rows_scanned":0,"rows_dropped":0,"truncated":false,"fetched_at":"2026-09-03T05:13:31Z"}`
— no error, no invented rows; this prefix simply publishes no RFC 8805 geofeed.

### B4 — near-live feed (❌ DEFECT L-03)

`FEATURE_BGP_LIVE_FEED=true`. The runtime came up correctly and picked the
watchlist up immediately:

```
GET /api/bgp/feed?as_tenant=t_d3d…af67&limit=500     HTTP 200     (05:16:55Z)
 status  enabled=true polling=true capped=false interval=1m0s producer=ripestat-poll
         resources=[1.1.1.0/24, 93.175.146.0/24, 93.175.147.0/24]
         buffered=0 written=0 dropped=0 ring_size=2000
 metrics polls_total=9  poll_errors_total=0  poller_active=1
         updates_written_total=0  updates_dropped_total=0  updates_in_ring=0
 updates: 0   next: 0   gap: false
```

Nine clean polls, zero errors, **zero updates**. Root cause, measured:

```
GET /api/bgp/resource?resource=1.1.1.0/24&view=updates&hours=1
  → query_starttime 2026-09-03T01:59:52   query_endtime 2026-09-03T01:59:52   n=0
```

RIPEstat's `bgp-updates` dataset is **~3 h 15 m behind wall-clock** (newest data
01:59:52Z at 05:17Z). The poller's first window is `now − feedLookback` with
`feedLookback = 30 * time.Minute`
(`src/backend/internal/bgpdepth/feed.go:61`, used at `:591`), which lies entirely
inside that blind spot, and each subsequent poll advances the cursor no further.
On this deployment the feed can therefore **never** produce an update, while the
status block reports `enabled/polling` with no note saying why the panel is
empty — a silent empty state (§10). Not a crash, and `LiveFeedPanel` renders,
but "feed not enabled" never appears either: the honest message the operator
needs ("upstream has no data newer than 01:59Z") is not on the wire.

### B5 — bogons, BMP sighting, isolation (✅ PASS)

`FEATURE_BMP=true`, `BMP_LISTEN=:11019`, published on the host
(`docker-compose.yml:2145`). Attribution requires a device row at the source
address; from the host the api container sees the bridge gateway **172.18.0.1**
(`netops_netops`, api at 172.18.0.9). Registry set up read-only via the API:

```
POST /api/devices?as_tenant=t_d3d…af67
  {"id":"qa-bmp-live-proof","name":"qa-bmp-live-proof","address":"172.18.0.1",
   "vendor":"synthetic","os":"bmp-synthetic-session.py","type":"router","source":"manual"}
HTTP 201  (05:14:47Z)

$ python3 scripts/bmp-synthetic-session.py --host 127.0.0.1 --port 11019 \
      --sysname qa-live-proof --hold 6                       # 05:14:56Z
  -> Initiation 82 · Peer Up 126 · RM 99 (8.8.8.0/24) · RM 95 (192.0.2.0/24)
  -> RM 93 (10.0.0.0/8) · Termination 12
  session closed cleanly            EXIT=0
```

```
GET /api/bgp/bmp/sessions?as_tenant=t_d3d…af67    HTTP 200  count=1
 {"id":"bmp-1","device_id":"qa-bmp-live-proof","remote_addr":"172.18.0.1:36294",
  "router":"qa-live-proof","state":"closed",
  "opened_at":"2026-09-03T05:14:56Z","closed_at":"2026-09-03T05:15:02Z",
  "close_reason":"router terminated: administratively closed",
  "peers":[{"address":"192.0.2.1","as":65001,"rib":"adj-rib-in-pre-policy",
            "announced_prefixes":3, …}]}
```

```
GET /api/bgp/bogons?as_tenant=t_d3d…af67          HTTP 200
 set  {source:"IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890) + …",
       date:"2026-09-02", blocks:31}
 feed {enabled:false, note:"Only the embedded RFC/IANA special-purpose set is in force.
       Set FEATURE_BGP_BOGON_FEED=true to also fetch the Team Cymru full-bogons list …"}
 sightings: 2
  {"prefix":"192.0.2.0/24","entry":{"block":"192.0.2.0/24","reason":"special_purpose",
     "rfc":"RFC 5737","why":"Documentation (TEST-NET-1)"},
   "source":"bmp","peer":"192.0.2.1","count":1,
   "first_seen":"2026-09-03T05:14:56.668531443Z"}
  {"prefix":"10.0.0.0/8","entry":{"block":"10.0.0.0/8","reason":"special_purpose",
     "rfc":"RFC 1918","why":"Private-use address space"},
   "source":"bmp","peer":"192.0.2.1","count":1,
   "first_seen":"2026-09-03T05:14:56.669650667Z"}
```

The set is in force with 31 blocks, `192.0.2.0/24` is sighted with its block and
reason and `source: bmp`, sub-second after the announce (the "note immediately"
path from `8fb50b4a`). `8.8.8.0/24` correctly produced **no** sighting.
`FEATURE_BGP_BOGON_FEED=false` is reported honestly rather than silently.

**Isolation — every BGP surface, as `t_7ddf…cd93`:**

| call | result |
|---|---|
| `GET /api/bgp/bogons` | HTTP 200 · `sightings: 0` · set still 31 blocks (the set is platform-global, sightings are not) |
| `GET /api/bgp/bmp/sessions` | HTTP 200 · `count: 0` · "No router is exporting BMP to this platform" |
| `GET /api/bgp/watchlist` | HTTP 200 · `watchlist: []` |
| `GET /api/bgp/alerts` | HTTP 200 · alerts 0, incidents 0, all counters 0 |
| `GET /api/bgp/rpki` | HTTP 200 · `results: []` |
| `GET /api/bgp/feed` | HTTP 200 · `polling:false`, `resources:[]`, note "Add prefixes or …" |

No cross-tenant leak on any BGP surface.

---

## Cleanup (✅)

| object | action | result |
|---|---|---|
| watchlist `1.1.1.0/24` | `DELETE /api/bgp/watchlist?resource=…` | HTTP 200 `{"ok":true}` |
| watchlist `93.175.146.0/24` | same | HTTP 200 `{"ok":true}` |
| watchlist `93.175.147.0/24` | same | HTTP 200 `{"ok":true}` |
| `data/api/bgp_watchlist.json` | re-read | `{}` — empty |
| device `qa-bmp-live-proof` | `DELETE /api/devices/qa-bmp-live-proof?as_tenant=…` | HTTP 204; `GET /api/devices` → only `spine1`, `spine2` |
| tenant `qa-live-proof-temp` | `DELETE /api/tenants/<id>?confirm=qa-live-proof-temp` | HTTP 204 (type-to-confirm guard worked: bare DELETE → HTTP 400 "deletion not confirmed"); `GET /api/tenants` → only `global`, `lab` |
| lab HIPAA selection | `PUT … [{"framework_id":"hipaa-security-rule","enabled":false}]` | HTTP 200; enabled set back to `[nist-800-53-r5, cis-controls-v8]` |

**Disclosed residue** (nothing writable was left behind; no container was
restarted, which is what would clear these):

1. `configured` for tenant `lab` is now `true` instead of its original `false`.
   The *effective* selection is byte-identical to the shipped default, but the
   API has no "un-choose" verb, so the "not configured, showing defaults" note
   no longer renders. Cosmetic; a `PUT` cannot undo it.
2. Two in-memory bogon sightings (`192.0.2.0/24`, `10.0.0.0/8`) and one closed
   BMP session record (`bmp-1`, `qa-bmp-live-proof`) remain under tenant `lab`.
   Both stores are process-memory with bounded retention and no on-disk artefact;
   they clear on the next api restart.
3. Nine security scans from tonight (03:43–05:08Z) remain in OpenSearch — pre-
   existing, not created by this run beyond the one scan at 05:06:17Z. They are
   the substance of defect **L-01**.

---

## Defects raised by this run

| id | severity | defect |
|---|---|---|
| **L-01** | **HIGH** | `current=true` never collapses: `nativeIDOf` puts `f.ScanID` inside the collapse key (`internal/secbus/event.go:183`) while the query collapses on `native_id` (`secapi/query.go:263`). The Findings page shows 572 rows / 444 Unknown — 440 of them stale pre-fix verdicts that can never be superseded — and the compliance scorecard counts them (AC-17 `Fail`, 168 findings, vs `NotApplicable` in the current scan). The owner-visible symptom "verdicts are all Unknown" therefore survives the fix. |
| **L-02** | **HIGH** | `netops-frontend-1` runs an image built 00:50:53Z; the container was recreated at 04:53 from that same image. Every SPA chunk hash differs from the local `dist` built 04:29. `e8e85f85` (one-page BGP screen), `36f66cf4` (security UI: "Why unassessed", "Add framework") and `5f788707` (`/licenses/`) are **not deployed**. |
| **L-03** | MEDIUM | Near-live feed can never emit on this deployment: `feedLookback = 30m` (`internal/bgpdepth/feed.go:61`) is far shorter than the measured ~3 h RIPEstat `bgp-updates` latency, and the status block reports `enabled/polling` with no note explaining the permanent zero. |
| **L-04** | MEDIUM | (re-confirm of A4/D-02) `GET /api/security/findings/{id}` → HTTP 404 for an id the list route just returned. |
| **L-05** | LOW | `GET /api/bgp/watchlist` still returns `incidents` for prefixes that have been deleted from the watchlist (evaluator state is not pruned on delete). Ages out on the next sweep window. |
| — | — | (recorded, already tracked) exposure-stories list still `[]` — D-01. |
