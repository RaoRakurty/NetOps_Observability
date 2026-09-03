# Real-world scenario tests — Troubleshooting features (Project 4)

**Run:** 2026-09-03, against the **live lab stack** on `localhost:8000`.
**Method:** persona + trigger → steps → expected → observed → verdict. Every
number below was read off the running system (API response, VictoriaMetrics,
ClickHouse, container log) or off the device itself over SSH. Nothing is inferred.

**Fixtures used (all removed — see §9):**

| Object | Value |
|---|---|
| Tenant under test | `lab` = `t_d3d501aa08e2395893b378a453b8af67` |
| Devices | `spine1` 172.40.40.11 · `spine2` 172.40.40.12 — Nokia **SR Linux v26.3.2**, 7220 IXR-D3L |
| Scoped operator (created for this run) | `qa-lab-op`, role `operator`, bound `tenant:t_d3d501aa…` |
| Foreign principal (created for this run) | tenant `qa-foreign` = `t_ee34a57aceb56e3fd6f42d66c004e35d`, user `qa-fgn-op` (operator) |

**Deployment state at run time (verified from `docker inspect netops-api-1`):**

| Flag | Value | Note |
|---|---|---|
| `FEATURE_CONFIG_BACKUP` | `true` | as briefed |
| `FEATURE_PROTOCOL_DIAG_COLLECT` | **`false`** → set to `true` mid-run | **the brief said ON; it was OFF.** See D-6 |
| `PROTOCOL_DIAG_SSH_USER` / `_PASSWORD` | empty | falls back to `CONFIG_BACKUP_SSH_*` (documented precedence) — worked |
| `FEATURE_AI` | empty (⇒ on) · `FEATURE_COPILOT` `true` | Iris reachable |
| `COPILOT_API_KEY` | **empty** | ⇒ every Iris answer is `evidence_only: true`. Correct and expected |
| `FEATURE_AI_TOOLS` | `false` | this gates the *copilot agent loop*, NOT the skills path — skills ran fine |
| `STORE_BACKEND` | `file` | relevant to D-1 |

Verdict key: **PASS** · **PASS-with-notes** (feature behaves correctly; a
coverage or premise gap is recorded) · **FAIL**.

## Results at a glance

| # | Scenario | Verdict |
|---|---|---|
| 1 | IGP adjacency check before a maintenance window | **PASS** |
| 2 | "Is the link to leaf3 really up?" — interfaces by VRF | **PASS-with-notes** (D-7) |
| 3 | Protocol diagnostics: live collect → analyze → TAC export | **PASS** on the machinery · **FAIL** on SR Linux coverage (D-2) |
| 4 | Investigation surface, API path | **PASS** |
| 5 | Iris co-pilot — three real questions | (a) **FAIL** (D-3) · (b)(c)(e)(f) **PASS-with-notes** · (d) **FAIL → PASS** after D-1 |
| 6 | Iris audit trail — argument NAMES only | **PASS** |
| 7 | Error boundary | **PASS** |

Twelve defects filed. Two were fixed in this run (**D-1** P0 · **D-10** MEDIUM),
one is handed off to the `vendorprofile` owner (**D-2** HIGH), the rest are
recorded with a located fix.

---

## Scenario 1 — IGP adjacency check before a maintenance window

**Persona/trigger.** A NOC operator (`qa-lab-op`) is about to take a leaf down and
wants to know the IS-IS state of `spine1` first: how many adjacencies, what hold
timers, how big the LSDB, how often SPF has run — and whether any of it is guessed.

**Steps.** `GET /api/protocols/isis/{adjacencies,summary,health}?device=spine1`
and the same three for `ospf`, as the operator. Cross-checked against
VictoriaMetrics and then against the device itself over SSH.

**Observed — `isis/health?device=spine1`:**

```json
{"adjacencies_up":4,"adjacencies_down":0,"neighbor_count":4,"levels":["L2"],
 "areas":{"areas":["49.0001"]},
 "lsdb":{"lsp_count":6,"scope_label":"isis_level","by_scope":[{"scope":"L2","count":6}]},
 "spf_runs":{"runs":10,"by_scope":[{"scope":"L2","count":10}]},
 "timers":{"scope_kind":"adjacency","rows":[
   {"scope":"0100.0000.0011","ifname":"ethernet-1/1.0","level":"L2","hold_seconds":30}, …×4]},
 "coverage":{"events":true,"live_series":true,"lsdb":true,"areas":true,"spf_runs":true,"timers":true},
 "stability":{"flaps_per_hour":0,"score":100,
   "basis":"0 adjacency down-transitions over 24h, counted from syslog/trap adjacency-change events"},
 "notes":null,"source":"events+live_series"}
```

`isis/summary` returned both spines: `spine1` adjacencies 4 / lsp 6 / spf 10,
`spine2` adjacencies 4 / lsp 6 / spf 6, area `49.0001`, zero flaps.

**Cross-check A — VictoriaMetrics (`netops-victoria-1:8428`):**

| Query | Result |
|---|---|
| `device_isis_adj_state{device="spine1"}` | 4 series, all `= 3` (up), `isis_neighbor` `0100.0000.0011…0014`, `transport="gnmi"` |
| `device_isis_adj_hold_seconds{device="spine1"}` | 4 series, all `= 30` |
| `device_isis_lsp_count{device="spine1"}` | `= 6` (`isis_level="L2"`) |
| `device_isis_spf_runs_total{device="spine1"}` | `= 10` |
| `device_isis_area` | `{area="49.0001", device="spine1"}` and `…spine2` `= 1` |

**Cross-check B — the device itself** (`ssh admin@172.40.40.11
'show network-instance default protocols isis adjacency'`):

```
Network Instance: default   Instance: fabric
| ethernet-1/1.0 | 0100.0000.0011 | L2 | 10.0.1.1 | :: | up | 2026-08-04T18:53:00.100Z | 30 |
| ethernet-1/2.0 | 0100.0000.0012 | L2 | 10.0.1.3 | :: | up | 2026-08-04T18:52:57.700Z | 30 |
| ethernet-1/3.0 | 0100.0000.0013 | L2 | 10.0.1.5 | :: | up | 2026-08-04T18:52:57.900Z | 30 |
| ethernet-1/4.0 | 0100.0000.0014 | L2 | 10.0.1.7 | :: | up | 2026-08-04T18:53:01.400Z | 30 |
Adjacency Count: 4
```

API == VictoriaMetrics == device, on all four identities, the level, the hold and
the count. No fabricated field.

**Observed — OSPF (absent protocol).** Every OSPF depth field came back **`null`
with a note naming the series and its transport**, never `0`:

- `adjacencies_up: null`, `neighbor_count: null`, `levels: null`
- `lsdb.lsp_count: null` + *"no LSDB/LSA-count series is collected for these devices (`device_ospf_lsdb_count` comes from OSPF-MIB `ospfAreaLsaCount` …); LSDB size is not reported rather than reported as zero"*
- `spf_runs.runs: null` + *"…`ospfSpfRuns`, which is PER AREA and needs a device that answers `ospfAreaTable`"*
- `timers.rows: null` + *"…`ospfNbrTable` has no hello or dead column, so a per-neighbour OSPF timer cannot be collected over SNMP"*
- `coverage: {events:true, live_series:false, lsdb:false, areas:false, spf_runs:false, timers:false}`

**Verdict: PASS.** The honesty contract holds in both directions — every IS-IS
number is corroborated by two independent sources, and every OSPF number the lab
cannot produce is `null` + a note that names the missing series *and its MIB
object*, which is the standard the design set.

*Note (cosmetic, D-8):* `ospf/summary` — a **fleet** roll-up — carries the
per-device note text *"no live series collected for **this device**"*.

---

## Scenario 2 — "Is the link to leaf3 really up?" (interfaces by VRF)

**Persona/trigger.** Same operator, same maintenance: which interfaces does
`spine1` have, in which VRF, and are they up?

**Steps.** `GET /api/devices/spine1/interfaces/by-vrf` as the operator.

**Observed (complete response, 777 bytes):**

```json
{"device":{"id":"spine1","name":"spine1","vendor":"nokia"},"window":"5m",
 "dialect":{"term":"VPRN","term_plural":"VPRNs","vendor":"nokia","vendor_known":true},
 "coverage":{"vrf_labels":false,"transport":"none","transport_inferred":false,
   "interfaces":0,"in_groups":0,"ungrouped":0,"utilisation":false,"errors":false,
   "notes":[
     "No interface state series exists for this device — nothing is collecting device_if_oper_status for it, so there are no interfaces to group.",
     "The device does report routing instances on its BGP control-plane series; they are listed under routing_instances. That lane carries the instance name but not which interfaces belong to it."]},
 "groups":null,
 "routing_instances":[{"name":"default","source":"bgp_control_plane"}]}
```

**Is the note true?** Yes, and the reason is a deliberate design rule, not a
break:

- `device_if_oper_status{device="spine1"}` → **0 series**. `count by (__name__) ({device="spine1"})` returns exactly **10 families**: `device_bgp_peer_state` (4), `device_isis_adj_{state,hold_seconds}` (4+4), `device_isis_{area,lsp_count,spf_runs_total}`, `device_mem_percent`, `collector_target_up`, `ALERTS*`. **No `device_if_*` and no `device_cpu_percent` for any device in the fleet.**
- gnmic *is* subscribed (`srl-interfaces` → `/interface[name=*]/statistics|oper-state|admin-state`) and the raw lane proves the data arrives: `gnmi_srl_nokia_interfaces_interface_statistics_{in,out}_octets` exist in VM.
- The canonical lane deletes them on purpose — `deployment/docker/gnmic/gnmic.yaml`, processor `ownership-gate`: `event-delete: value-names: ["^device_if_.*$", "^device_cpu_percent$", "^device_temp_celsius$"]`, under the documented rule *"a (device, family) pair is served by exactly ONE transport … interface/cpu/temp families stay SNMP-owned"*. There is no SNMP profile reaching the SR Linux spines, so nobody serves them.

**Verdict: PASS-with-notes.** The endpoint is correct and honest: it names the
exact missing series, distinguishes "not collected" from "zero interfaces",
resolves the Nokia dialect (`VPRN`) and still surfaces what it *does* know
(`routing_instances` from the BGP control plane, with `source` stamped). The
brief's premise — "interfaces … from gNMI" — is **not true of this deployment**;
see **D-7**. `coverage.vrf_labels=false` with its honest note is exactly the
expected behaviour and was observed.

---

## Scenario 3 — Protocol diagnostics: live collect → analyze → TAC export

**Persona/trigger.** The operator suspects an IS-IS problem on `spine1` and opens
Protocol Diagnostics.

### 3.1 Catalog — is SR Linux a covered dialect?

`GET …/catalog?vendor=nokia%20SR%20Linux` — this is the **exact** string the UI
sends (`platformOf()` in `pages/troubleshoot/protocolDiagModel.ts` joins
`vendor+os+model`; `ProtocolDiagnosticsPanel.tsx:109` passes it verbatim):

```
vendor = "nokia"      vendor_display = "Nokia SR OS"
isis-adjacency-down commands:
  show router isis adjacency
  show router isis interface detail   (×2)
  show port detail
  show router interface
  show router arp
  show router route-table
```

**Reported honestly: NO.** SR Linux is **not** a covered CLI dialect, but the
platform is silently resolved to **Nokia SR OS** — a different operating system
with a different CLI — and its commands are rendered as if they applied. See
**D-2**; this is the run's most consequential finding.

`?device=spine1` is **ignored** (the handler reads only `?vendor=`) and falls back
to the Cisco IOS-XE default — see **D-5**.

### 3.2 Live collect

With `FEATURE_PROTOCOL_DIAG_COLLECT=false` (the state found on the box):

```
POST …/collect {"device_id":"spine1","issue_id":"isis-adjacency-down"}
→ 503 {"error":"protocol-diagnostics collector is not configured on this deployment"}
POST …/collect {"device_id":"no-such-dev", …}          → 404 page not found
```

Honest 503, no fabricated capture. ✔

The flag was then set to `true` and the api recreated. Startup log:

```json
{"component":"protocol-diag","msg":"live collect transport wired (read-only SSH)",
 "flag":"FEATURE_PROTOCOL_DIAG_COLLECT","dedicated_creds":false,"port":22,
 "command_timeout":"30s","max_output":524288,"ruleset":"correlix-protocoldiag-2026-08-27"}
```

`dedicated_creds:false` ⇒ the documented fallback to `CONFIG_BACKUP_SSH_*` engaged.

**The live collect ran. SSH reached the device. Every command failed:**

```json
{"device_id":"spine1","hostname":"spine1","platform":"nokia SR Linux",
 "vendor":"nokia","rendered_vendor":"nokia","redacted":true,
 "ruleset_version":"correlix-protocoldiag-2026-08-27",
 "commands":[
  {"spec_id":"isis-neighbors","command":"show router isis adjacency",
   "output":"","error":"command \"show router isis adjacency\" failed: Process exited with status 1"},
  {"spec_id":"isis-interface","command":"show router isis interface ethernet-1/1.0 detail","output":"","error":"… status 1"},
  … 7 of 7 commands, every one `error`, every one `output:""`]}
```

Timestamps are ~2.3 s apart — real sequential SSH execs, not a stub. Confirmed at
the device:

```
$ ssh admin@172.40.40.11 'show router isis adjacency'
Parsing error: Unknown token 'router'. Options are ['#','/','>','>>','acl','arpnd',
  'interface','lag','network-instance','platform','qos','system','tunnel',
  'tunnel-interface','version','|']
exit=1
```

The transport, the credential custody, the closed command table, the bounded IO,
the per-command error reporting and the redaction flag **all work**. The
**command set is for the wrong OS**.

**One live collect per protocol** (P4-B's remaining checkbox), all against `spine1`:

| Issue | Protocol | Commands | Failed | Bytes captured |
|---|---|---|---|---|
| `isis-adjacency-down` | IS-IS | 7 | **7** | 0 |
| `bgp-session-down` | BGP | 7 | **7** | 0 (`show router bgp summary`, `show router bgp neighbor detail`, `show router route-table`, …) |
| `ospf-neighbor-stuck` | OSPF | 6 | **6** | 0 (`show router ospf neighbor`, `show router ospf interface detail`, `show port detail`, …) |

**20 of 20 commands failed; zero bytes captured across all three protocols.**

### 3.3 Analyze — with real captured output

Pasted the genuine SR Linux adjacency table (4 × `up`) into
`POST …/analyze {issue_id:"isis-adjacency-down"}`:

```json
{"matched":false,"findings":[],
 "unmatched":"no known signature matched — the raw captured output is attached for TAC"}
```

Correct: nothing is down, so no down-signature fires, and no cause is invented.

Then the **same real table with `up` → `down`** (the realistic failure case):

```json
{"matched":true,"findings":[{"signature_id":"isis-adjacency-not-up",
 "verdict":"IS-IS adjacency is not Up","confidence":"medium",
 "cause":"a neighbor is listed but not Up — a level (L1/L2), area (NET), MTU, or authentication mismatch is preventing the adjacency",
 "remediation":"Verify the level, the area/NET, the interface MTU, and authentication match on both ends of the link.",
 "evidence":{"spec_id":"isis-neighbors","command":"show router isis adjacency",
   "line":"| ethernet-1/1.0 | 0100.0000.0011 | L2 | 10.0.1.1 | :: | down | … | 30 |"}}]}
```

The signature fired on a **Nokia SR Linux pipe-table** it was never authored
against, and quoted the exact evidence line. The Cisco-shaped control
(`R2 L2 Gi0/0 10.0.0.2 Init 27 01`) fired the same signature. The analyzer is
dialect-tolerant. ✔

**Breadth check — all 15 issues.** `POST …/analyze` with an empty `outputs` array
for every issue in the catalog (5 BGP + 5 IS-IS + 5 OSPF): **15/15 → HTTP 200,
`matched:false`**, no 5xx and no invented finding anywhere. Untrusted-input
guards were exercised too: an unknown body field is refused
(`400 bad body: json: unknown field "vendor"`), and a `spec_id` outside the
issue's own bundle is refused rather than ignored.

### 3.4 TAC export + redaction

Six secret shapes were appended to the pasted capture. All six masked in
`tac_export`:

| Planted | In export |
|---|---|
| `authentication-key MyS3cretKey!23` | `authentication-key [REDACTED]` |
| `password 7 070C285F4D06` | `password 7 [REDACTED]` |
| `key-string ThisIsAnIsisAuthKey` | `key-string [REDACTED]` |
| `snmp-server community PublicSecret123 RO` | `snmp-server community [REDACTED] RO` |
| `neighbor 10.0.1.1 password bgpNeighborPass99` | `neighbor 10.0.1.1 password [REDACTED]` |
| `username admin secret 5 $1$abcd$efghijklmnop` | `username admin secret 5 [REDACTED]` |

**0 of 6 leaked.** ✔ The export header, however, reads:

```
Device   : spine1 ()
Platform : nokia SR Linux
Vendor   : Nokia SR OS (dialect: Nokia SR OS)
```

— a bundle sent to a vendor TAC that states the wrong operating system, and
attributes real SR Linux output to `$ show router isis adjacency`, a command that
cannot produce it.

**Verdict: PASS-with-notes on the machinery, FAIL on SR Linux coverage.**
Transport, guards, signatures, evidence citation and redaction are all correct
and proven live. The dialect binding sends SR OS commands to an SR Linux box:
7/7 commands failed, and no live collect on the lab spines can ever succeed until
**D-2** is fixed.

---

## Scenario 4 — Investigation surface, API path

**Persona/trigger.** The operator opens Troubleshooting → Investigation for the
symptom *routing adjacency* on `spine1`. Every lane call was issued as the
operator.

| Lane | Call | HTTP | Result |
|---|---|---|---|
| DEM | `GET /api/paths/health` | 200 | `{"count":0,"paths":[]}` → lane `not_connected` |
| What changed | `GET /api/events/feed?class=changes&limit=5` | 200 | 23 `audit_change` items, faceted |
| Device/protocol health | `GET /api/metrics/names` + `query=device_if_oper_status == 0` | 200 | `result:[]`, `seriesFetched:0` |
| Path | `GET /api/probe/paths` | 200 | `[]` |
| Routing | `query=device_bgp_peer_state != 6 or device_ospf_nbr_state != 8 or device_isis_adj_state != 3` | 200 | `result:[]`, `seriesFetched:16` |
| Flows | `GET /api/flows/top?limit=5` | 200 | `rows: 0` (`rows_read` 1084 — CH reached) |
| Events | `GET /api/events/feed?limit=5` | 200 | facets `{audit_change:23, security_exposure:80, security_posture:434}` |

**No 5xx on any lane.** The two metric lanes land on *different, correct* honest
states because `classifyMetricLane` (`investigationModel.ts:279`) uses
`/api/metrics/names` as the authority on what has ever been ingested:

- health — `device_if_oper_status` is **absent from `names`** → `not_connected`, "the collector for it is off or the devices do not expose it". Correct (Scenario 2).
- routing — `device_isis_adj_state` **is** in `names`, `seriesFetched:16`, filter matched nothing → `empty`, *"The metrics are collected and nothing is out of state right now."* Correct.

That distinction — an uncollected family must never read as a healthy one — is
the honesty contract for this surface and it holds live.

### Are there correlation cases for lab devices?

**Yes — six.** `GET /api/correlations?limit=50` as the operator:

```
n = 6   top_hypothesis: sig.ent.security.exposure-story ×6
affected: {"devices":["spine1"]} ×3, {"devices":["spine2"]} ×3
e.g. 71403abf-95a3-53ad-8a0a-9da56a88bd17 · engine 3.1.0+cfg.d92aacb66561 ·
     signal_count 32 · plane_count 1 · verdict_tier "suspected" · grounding "topo"
     evidence_missing: ["sig.ent.security.exposure-story: single modality class
       (security); need ≥2 — every modality has a blind spot"]
```

The same six, and only those six, are returned for
`?as_tenant=t_d3d501aa…` as admin. Attribution is correct.

**Why are they all security-lane, and where is the telemetry?** Answered from
ClickHouse (`corr_signals`, last 24 h, row policy defeated only for this audit
with `SET tenant_scope='__all__'` — note the policy itself *refused* the first
unscoped query with `Unknown setting 'tenant_scope'`, which is §3a.4 working):

| tenant | modality | source | entity | count |
|---|---|---|---|---|
| `t_d3d501aa…` (lab) | security | security | spine2 | 257 |
| `t_d3d501aa…` (lab) | security | security | spine1 | 257 |
| `t_d3d501aa…` (lab) | management_plane | audit | devices / security / auth / api | 26 |
| *(platform)* | management_plane | audit | internal, auth, api, … | 2 400+ |

Fleet-wide the only two `source` values in 24 h are `audit` (2 495) and
`security` (644). So:

1. **The spines DO send syslog and it IS tenant-scoped.** `GET /api/logs/search?q=spine1` → `hits.total = 1943` in index **`netops-syslog-t_d3d501aa08e2395893b378a453b8af67-2026.09.03`** — a per-tenant index, exactly as §3a.4 requires. Iris's own log tool reported 4 703 matching lines in its window.
2. **But no syslog rule has fired for them**, so syslog contributes zero `corr_signals`. The SR Linux lines in the window are `aaa` session open/close and `sr_grpc_server` debug — nothing a rule claims. (The `device_config_change` syslog rule ships SHADOW per tracker 220.)
3. **gNMI contributes nothing to correlation at all on this deployment:** `netops-gnmic-1` runs `subscribe --config /app/conf/gnmic.yaml` — the VictoriaMetrics-only config. The Kafka correlation lane lives in `gnmic-correlation.yaml` and is **not selected** (`GNMIC_CONFIG_FILE` unset).

So the six cases are single-modality security exposure stories, and each one
**says so itself** in `evidence_missing`. That is the correct, honest outcome —
not a gap in attribution.

**Verdict: PASS.** Seven lane calls, zero 5xx, honest lane states with the
"not collected ≠ nothing wrong" distinction demonstrated live, correlation cases
present and correctly tenant-attributed with their own evidence gap declared.

---

## Scenario 5 — Iris co-pilot, three real questions as the lab operator

`COPILOT_API_KEY` is empty, so every answer is `evidence_only: true` with
`provider_note: "Answered from evidence only — no AI provider was available for
the narrative."` — the expected mode, and the strictest one for judging honesty.

### (a) "is spine1 healthy right now" — **FAIL**

```json
{"mode":"unavailable","intent":"capability","modules":[],"skill":null,"chain":null,
 "citations":[],"answer_id":null,
 "text":"I didn't quite catch that. I can: summarize what's going on right now, …"}
```

No skill, no tool, no citation, for a question naming a device the platform holds
live IS-IS, BGP, memory and 1 943 syslog lines for. Boundary mapped:

| Question (context `{"device":"spine1"}`) | mode | skill |
|---|---|---|
| `is spine1 healthy right now` | `unavailable` | — |
| `check spine1 status` | `unavailable` | — |
| `what is the health of spine1` | `product_answer` | — (answered from the **product KB**) |
| `why is spine1 slow` | `troubleshoot_finding` | `osi-bisection` |
| `spine1 is degraded` | `troubleshoot_finding` | `osi-bisection` |
| `investigate spine1` | `troubleshoot_finding` | `osi-bisection` |

Cause: `SelectSkill` scores 0 and `reTroubleshootCue` (`ai/skill_select.go:45`)
contains no health/status/"how is" cue, so the question falls through to the
capability clarification. See **D-3**.

### (b) "isis adjacency down on spine1" — **PASS**

```
mode      troubleshoot_finding      evidence_only true
skill     {"name":"log-confirmation","layer":"logs","version":1}
answer_id aa020304-4427-4132-b4f2-5bdbfe536717
chain [
 {"name":"isis-adjacency","layer":"igp","round":1,"selected":"entry",
  "reason":"matched the igp-layer method isis-adjacency on: isis, isis adjacency, adjacency"},
 {"name":"log-confirmation","layer":"logs","round":2,"selected":"rule",
  "reason":"the adjacency diagnostic ran and no known signature matched, so the
            transition times must be pinned from the device's own words"}]
lookups   [get_device_state, run_protocol_diagnostic, get_topology_context, search_logs, search_logs]
citations state:igp:spine1:0 · diag:isis-adjacency-down:spine1 · topo:spine1 · log:os:0…8   (12)
missing_evidence [
 "platform \"nokia SR Linux\" does not resolve to a known CLI dialect — no read-only
  command is established for it, so its state is UNKNOWN rather than healthy",
 "treat this device's igp state as UNKNOWN, not healthy; ask the operator to run the
  read-only checks below and paste the output",
 "no adjacency or measured path is recorded for this device — say the topology context
  is UNKNOWN here, not that the device is isolated",
 "the seam register is not enabled on this deployment — seam ownership is UNKNOWN here, not absent"]
```

Skill selected with a stated reason, a two-hop chain with the hop reason recorded,
five tool calls, `state:`/`diag:`/`topo:`/`log:` citations, and four honest
missing-evidence lines that each tell the narrator *what not to claim*. No
fabricated fact anywhere in the answer. This is the feature working.

**Two contradictions inside this one answer**, both traced to **D-2**:

- `state:igp:spine1` says *"platform `nokia SR Linux` resolves to no known CLI dialect"* (`showparse.DialectFromPlatform` correctly has **no** `nokia/srlinux` dialect, `showparse.go:338`) — while the run **before** the flag flip cited seven `diagcmd:` suggestions telling the operator to run `show router isis adjacency` / `show port detail` on that same device. One half of Iris says the dialect is unknown; the other half hands out SR OS commands.
- With collect wired, `run_protocol_diagnostic` reported *"no known signature matched"*. In truth **7/7 commands errored and zero bytes were captured** (§3.2). See **D-4**.

### (c) "bgp neighbor down on spine1" — **PASS**, with the sharpest artefact of the run

```
skill  log-confirmation   chain: bgp-session-down (entry, round 1) → log-confirmation (rule, round 2)
lookups [get_device_state, run_protocol_diagnostic, get_topology_context,
         search_logs, recall_investigations, search_logs]
```

The **top log citation Iris returned as evidence about the operator's BGP
problem** is:

```
log:os:0  2026-09-03T04:14:39Z spine1 … |admin|185| Parsing error: Unknown token 'router'.
          Options are ['#','/','>','>>','acl','arpnd','interface','lag','network-instance', …]
```

That is `spine1` logging **Correlix's own diagnostic failing**, shipped back by
syslog and re-served to the operator as evidence about their outage. A closed
loop of self-generated noise, entirely caused by **D-2**.

`recall_investigations` returned nothing, with the right words:
*"no prior CONCLUDED investigation is recorded for this scope — say the history is
EMPTY, not that this has never happened (memory only holds investigations an
operator judged)"* and *"prior investigations are CONTEXT, not current state"*.

### (d) Rate up → memory recall — **FAIL, then PASS after fixing D-1**

**Before (shipped code):**

```
POST /api/ai/feedback {"rating":"up","answer_id":"aa020304-…"}   → 502 Bad Gateway
POST /api/ai/feedback {"rating":"up"}                            → 502 Bad Gateway
POST /api/ai/feedback {"rating":"sideways"}                      → 400 {"error":"rating must be 'up' or 'down'"}
GET  /api/ai/feedback (admin)                                    → 200 {"up":0,"down":0,"by_intent":{}}
```

nginx: `upstream prematurely closed connection while reading response header … POST
/api/ai/feedback`. The api logged **nothing** and never wrote a request line. An
invalid rating returns 400, so the fault is downstream of validation. Root cause
found and reproduced (`panic: assignment to entry in nil map`) — **D-1**, with
**D-10** explaining why it was invisible. Re-asking (b) returned no `memory:`
citation, as expected: nothing had been recorded.

**After (fixes applied, api rebuilt and redeployed — image `16cb7fd83130`):**

```
POST /api/ai/feedback {"rating":"up"}                                    → 204 No Content
POST /api/ai/feedback {"rating":"up","answer_id":"ab3daa8c-…","intent":"capability"}  → 204 No Content
api log: {"component":"ai","msg":"feedback","rating":"up","investigation_remembered":true,
          "sub":"qa-lab-op","tenant":"t_d3d501aa08e2395893b378a453b8af67"}
```

Re-asking *"bgp neighbor down on spine1"* (the `bgp-session-down` skill gathers
memory last, as its loader rule requires) now returns:

```
lookups   [get_device_state, run_protocol_diagnostic, get_topology_context,
           search_logs, recall_investigations, search_logs]
citation  memory:710b7f4e-c8b9-472b-916d-b5772fb72156  (kind "finding")
label     "2026-09-03 on spine1 via isis-adjacency → log-confirmation — concluded: …"

evidence  "2026-09-03 on spine1 via isis-adjacency → log-confirmation — concluded:
           log confirmation — Logs check. Evidence gathered: … (operator confirmed);
           it rested at the time on state:igp:spine1:0, diag:isis-adjacency-down:spine1,
           topo:spine1 (+50 more)."
gaps      "the evidence ids quoted inside a remembered conclusion are HISTORICAL —
           cite the memory row itself, never them"
           "prior investigations are CONTEXT, not current state: verify what the device
           and the engine report NOW before relying on any remembered cause"
```

**`(operator confirmed)` is stamped on the row**, the memory is cited by its own
`memory:<id>` rather than by the historical evidence ids it quotes, and the
"verify current state first" rule travels with it — the whole Phase-B contract.

Cross-tenant: the same question as `qa-fgn-op` returns `citations: []` and
*"no device, peer, prefix or case id was in scope, so no prior investigation could
be recalled — treat the history as UNKNOWN"*. The memory row is tenant-scoped.

**Post-deploy smoke** on the rebuilt image: all nine troubleshooting endpoints
200, `isis/health` still `adjacencies_up: 4`, zero `panic` and zero
`"msg":"server error"` lines in the new container.

### (e) Foreign tenant asks about spine1 — **PASS**

As `qa-fgn-op` (tenant `qa-foreign`), *"isis adjacency down on spine1"*:

```
mode  troubleshoot_finding    skill {"name":"isis-adjacency","layer":"igp"}
text  "isis adjacency — Igp check. No evidence was returned for this scope.
       Gaps: no matching syslog lines in the window; no device in this tenant's
       inventory matches the name in the question — say so; do not assume the
       device exists."
citations []   missing_evidence null
```

The skill still runs (so the refusal is not an error path), and returns **zero**
bytes of lab data. Direct API probes as the same principal:

| Request | Result |
|---|---|
| `GET /api/protocols/isis/{health,adjacencies}?device=spine1` | **404 page not found** |
| `GET /api/devices/spine1/interfaces/by-vrf` | **404 page not found** |
| `POST …/protocol-diagnostics/collect {"device_id":"spine1"}` | **404** (not the 503 the owning tenant gets — no existence oracle) |
| `GET /api/protocols/isis/summary` | 200, `devices: []` |
| `GET /api/correlations?limit=5` | 200, `{"data":[]}` |
| `…?as_tenant=t_d3d501aa…` and `?as_tenant=lab` on the above | **identical** — every escalation ignored, fail-closed |

### (f) Explaining a real lab case — **PASS**

`POST /api/ai/ask {"question":"explain this incident","context":{"correlation_id":"71403abf-…"}}`
as the operator:

```
mode  problem_explanation      intent  problem_explanation
citations  problem:71403abf-… · hypothesis:71403abf:0…3 · evidence-basis:71403abf · affected:71403abf
text "This device carries a known exposure and is showing a network fault at the same
      time — the two are on one node, not yet proven to be one cause. Correlix detected
      an incident on spine1. Correlix suspects this fault domain based on multiple
      supporting signals; final validation is not complete. Expected supporting evidence
      was not found. Recommended owner: Network / Security team, pending confirmation."
```

Every hedge is earned by the case's own `evidence_missing` (single modality class,
needs ≥2) — "suspects", "not yet proven to be one cause", "final validation is not
complete", "pending confirmation". No promoted cause.

Existence-oracle check on the same route:

| Principal / id | Answer |
|---|---|
| lab operator, real id | the explanation above |
| foreign operator, the **real** lab id | `Problem "71403abf-…" isn't available in your scope.` |
| foreign operator, a **fabricated** uuid | `Problem "00000000-1111-…" isn't available in your scope.` |
| foreign operator, `GET /api/correlations/71403abf-…` | `404 {"error":"correlation object not found"}` |

The two refusals differ only by the uuid the caller supplied. No existence signal.

**Scenario 5 verdict: PASS-with-notes** on (b), (c), (e), (f); **PASS after the D-1 fix** on (d); **FAIL** on (a).

---

## Scenario 6 — Iris audit trail: argument NAMES only

32 `{"component":"ai","msg":"tool"}` lines were produced by this run. Every one:

```json
{"allowed":true,"args":["device_id","issue_id","protocol"],"component":"ai","cross":false,
 "duration_ms":16032,"items":1,"level":"info","msg":"tool","reason":"ok","round":1,
 "selected":"entry","skill":"bgp-session-down","sub":"qa-lab-op",
 "tenant":"t_d3d501aa08e2395893b378a453b8af67","tool":"run_protocol_diagnostic"}
```

Distinct `args` sets observed: `[area device_id]`×6 · `[]`×6 · `[device_id]`×6 ·
`[device]`×4 · `[device_id issue_id protocol]`×3 · `[device query window]`×3 ·
`[device window]`×3 · `[query window]`×1.

Scanned all 32 lines for argument **values** — `spine1`, `spine2`, `172.40.40.*`,
`ethernet-1/*`: **0 occurrences.** Identity (`sub`, `tenant`) and control metadata
(`allowed`, `reason`, `round`, `selected`, `skill`, `items`, `duration_ms`) are
present, which is what an audit line is for. The `ask` line likewise carries
`intent`/`mode`/`modules`/`tier` and no question text.

**Verdict: PASS.**

---

## Scenario 7 — Error boundary

```
$ npx vitest run src/App.errorBoundary.test.tsx
 ✓ src/App.errorBoundary.test.tsx (4 tests) 222ms
 Test Files 1 passed (1)   Tests 4 passed (4)
```

The suite pins the honest contract: `role="alert"`, *"Detection Rules could not be
displayed"*, `Try again` + `Reload this page`, the chrome (icon rail, top bar,
`#main-content`) survives, and the rendered text must **not** contain a stack
frame (`/\bat \w+ \(/`) or `componentStack`.

Served bundle (fetched through nginx on `:8000`, over the real `assets/*.js`):

| String | Occurrences in the served bundle |
|---|---|
| `could not be displayed` | 1 |
| `Reload this page` | 1 |
| `Try again` | 1 |

**Verdict: PASS.**

---

## 8. Defects

| # | Sev | Owner / file | Defect |
|---|---|---|---|
| **D-1** | **P0 — fixed in this run** | `src/backend/ai/feedback_store.go` — `NewMemFeedbackStore` (`ai`) | `NewMemFeedbackStore()` returned `&memFeedbackStore{}` with a **nil map**; `Put` then does `m.by[k] = row` → `panic: assignment to entry in nil map`. `STORE_BACKEND=file`, so this is the store the deployment uses. **Every valid `POST /api/ai/feedback` panicked**, tearing down the connection (nginx 502) and taking the whole Iris **Phase-B memory loop** with it — a row is only written when an operator judges an answer, and the judgement never lands. The existing test built `&memFeedbackStore{by: …}` **directly**, so it could never catch the constructor. **Fixed** (constructor initialises the map + a lazy guard in `Put`), regression tests added that go through `NewMemFeedbackStore()` and through the zero value; the panic was reproduced first as a control (`assignment to entry in nil map`). **Verified live** on a rebuilt api (`16cb7fd83130`): `POST /api/ai/feedback` → **204**, `investigation_remembered: true`, and the `memory:` citation with `(operator confirmed)` now appears on the next ask (Scenario 5d). |
| **D-2** | **HIGH** | `src/backend/internal/vendorprofile/profiles/nokia.json` — **owned by another agent, HANDED OFF** | The `srlinux` platform declares `"cli": {"dialect":"nokia","display":"Nokia SR OS"}`. SR Linux gets **SR OS commands and the SR OS name**. Proven live: 7/7 collect commands failed (`Parsing error: Unknown token 'router'`, exit 1); the TAC bundle header says `Vendor: Nokia SR OS` for a `Platform: nokia SR Linux`; Iris cites SR OS commands for a device it simultaneously says has no known dialect; and the device's own parse errors come back through syslog as "evidence". The same profile's `config_capture.platform_dialects` **already forks correctly** (`info from running flat`, rank 45 < 50) and `profile.go:329-332` states the rule — *"issuing SR OS' command at an SR Linux prompt is exactly the"* mistake. The CLI binding simply was not given the same treatment. **Fix (either):** (a) set `srlinux`'s `cli.dialect` to `""` — `VendorFromPlatform` then returns `VendorUnknown`, `DisplayVendor` renders *"unknown vendor"*, `renderVendor` falls back to Cisco **and records it** in `RenderedVendor`, so the operator is told rather than misled; or (b) author a real `srlinux` CLI dialect (`show network-instance <ni> protocols isis adjacency`, `show interface`, …) in `protocoldiag`'s `spec()` table + `commandtable`. (a) is the honest one-line stop-gap and matches `showparse`, which already returns *no dialect* for this platform. Ship (a) now, (b) as the feature. |
| **D-3** | MEDIUM | `src/backend/ai/skill_select.go` — `reTroubleshootCue` (line 45) (`ai`) | *"is spine1 healthy right now"* / *"check spine1 status"* → `mode:"unavailable"`, no skill, no tool, no citation. `reTroubleshootCue` covers complaints (`down`, `slow`, `flapping`, `why is`…) but no health/status/"how is/what is the state of" cue, and no skill's `when_to_use` claims them. Worse, *"what is the health of spine1"* is classified `product_question` and answered from the **product KB** — the operator is told what "health" means in Correlix instead of being told about spine1. A device-named question is the single most likely thing an operator types. Suggest widening the cue (`health(y)?`, `status`, `how is`, `what('?s| is) (the )?(state|status)`) **or** giving the entry method a device-entity trigger — a product decision, so filed rather than patched. |
| **D-4** | MEDIUM | `src/backend/ai_troubleshoot_deps.go` — `aiProtocolDiagnostic`, `rep.Collected = true` (line 300) | After `pdRunCollection` returns, the code sets `rep.Collected = true` and reports `res.Unmatched` **without checking whether any command produced output**. On the lab this turned *"every one of 7 commands errored, 0 bytes captured"* into *"the diagnostic ran and no known signature matched"* — which an operator reads as *"we looked, IS-IS is fine"*. `ai.DiagnosticReport` carries no per-command error field, so the failure cannot even be surfaced. (The HTTP `/collect` response **does** return per-command `error`; only the Iris bridge drops it.) §10 no-silent-failures. **Fix:** if every `col.Commands[i].Output` is empty / every entry has an `Error`, treat it as not-collected — set an honest gap (*"the read-only commands were rejected by the device (N/N failed); no output was captured"*) instead of `Collected=true`, and carry a per-command error onto the report so a partial capture degrades gracefully too. |
| **D-5** | LOW | `src/backend/protocol_diagnostics.go` — `handleProtocolDiagCatalog` (line 188) | `GET …/catalog` reads only `?vendor=`; a `?device=<id>` selector is silently ignored and the response falls back to the Cisco IOS-XE default. The shipped UI does not rely on it (it sends the platform string), but a silently-ignored query parameter that changes which CLI commands an operator is shown is a trap. Either resolve `?device=` through the tenant-scoped inventory (the collect endpoint already does) or reject it with a 400. |
| **D-6** | LOW (config) | `deployment/docker/.env` | `FEATURE_PROTOCOL_DIAG_COLLECT` was **absent** (⇒ `false`), and `PROTOCOL_DIAG_SSH_USER`/`_PASSWORD` were empty, contrary to the brief. It was set to `true` for this run and **left on** (the fallback to `CONFIG_BACKUP_SSH_*` works and P4-B's remaining checkbox asks for exactly this). Remove the line if the lab should return to dormant. |
| **D-7** | LOW (coverage) | `deployment/docker/gnmic/gnmic.yaml` `ownership-gate` | `device_if_*`, `device_cpu_percent`, `device_temp_celsius` are deleted from the canonical lane as SNMP-owned, and no SNMP profile reaches the SR Linux spines — so **no interface or CPU series exists for any lab device**. Consequences: `interfaces/by-vrf` returns 0 rows (Scenario 2), the Investigation *health* lane is permanently `not_connected` (Scenario 4), and P4-D #4 cannot be demonstrated. Not a bug — the ownership rule is deliberate and documented — but the flip it describes (*"prove parity against the raw lane, remove it from the delete list, withdraw it from the SNMP profile in the same change"*) is the blocker for #4 on this lab. Sub-note: the raw lane carries SRL `…/statistics/*` but **no** `oper-state`/`admin-state` series, so parity is not yet provable for the status families. |
| **D-8** | LOW (copy) | `internal/igpmon` | `GET /api/protocols/ospf/summary` — a **fleet** roll-up — returns the per-device note *"no live series collected for **this device**"*. Should read "for these devices" (the other four notes in the same array already do). |
| **D-9** | LOW (copy) | Iris `log-confirmation` skill / next-actions template | With no seam owner resolved, the last next-action renders as *"Escalate to only with the quoted lines and their timestamps attached."* — a dangling empty substitution. Suppress the action, or render *"Escalate with the quoted lines…"* when the owner is unknown. |
| **D-10** | MEDIUM — **fixed in this run** | `src/backend/tls_server.go` — `handshakeErrLog.Write` (lines 56-58) | `handshakeErrLog` is wired to `http.Server.ErrorLog` under TLS and **dropped every line that was not a TLS handshake error**, returning `len(p), nil`. `ErrorLog` is the only place net/http reports a **recovered handler panic** (`http: panic serving …` + stack). This is precisely why D-1 was invisible: a P0 panic in production produced a bare 502, an empty api log and no metric. §10 no-silent-failures. **Fixed:** non-handshake lines are now forwarded as `logError("http","server error",…)`; handshake lines keep their counter and are not double-classified; blank writes emit nothing. Test added. |
| **D-11** | LOW (pre-existing, unrelated) | api container | `{"component":"audit","error":"rename /data/audit.json.tmp /data/audit.json: no such file or directory","msg":"audit trail not persisted; events survive in memory only"}` recurs. The audit trail — including the `sensitive`-tagged protocol-diagnostics capture lines this run generated — is **not persisted**. Reported, not touched (outside this brief's scope). |
| **D-12** | LOW (doc) | `src/backend/protocol_diagnostics.go` — file header comment | The file header documents `POST /api/troubleshoot/protocol-diagnostics/export`. No such route is registered (`main.go:2072-2074`); a live probe returns 404. The TAC bundle is delivered inline as `analyze`'s `tac_export`. Delete the stale paragraph or register the route. |

### Changes made to the tree by this run

| File | Change |
|---|---|
| `src/backend/ai/feedback_store.go` | D-1 fix (constructor + lazy guard) |
| `src/backend/ai/feedback_store_test.go` | 2 regression tests through the exported constructor and the zero value |
| `src/backend/tls_server.go` | D-10 fix (stop swallowing non-handshake ErrorLog output) |
| `src/backend/tls_server_test.go` | 1 test covering both classes + the blank write |
| `deployment/docker/.env` (gitignored) | `FEATURE_PROTOCOL_DIAG_COLLECT=true` — D-6 |

Gate on the changed code: `go build ./...` clean · `go vet ./...` clean ·
`gofmt -l` clean · `staticcheck` clean on both packages · `gosec` clean ·
`govulncheck ./ai/...` → *No vulnerabilities found* · `go test ./` (root, incl.
the new `tls_server_test.go`) **ok** · `go test ./ai/ -run Feedback` **ok**.
`-race` could not be run locally (`-race requires cgo`, no C compiler on this
box — the same CI-only limitation P4-B recorded). **Nothing committed.**

One **pre-existing, unrelated** failure exists in `./ai/`:
`TestDocsCorpusMatchesPortal` — *"embedded corpus has orphan page
`security/vulnerability-management.md` (deleted from the portal) — run
`scripts/sync-docs-corpus.sh`"*. It is caused by the concurrent `docs-portal/**`
work (that tree currently has deleted/modified pages in the working tree) and is
untouched by this run. **Handed off to whoever owns `docs-portal/`:** run
`scripts/sync-docs-corpus.sh` and commit the regenerated corpus, or the `ai`
package stays red.

---

## 9. Cleanup

| Object | Disposition |
|---|---|
| user `qa-lab-op` + its tenant binding | `DELETE /api/users/qa-lab-op` → 204 |
| user `qa-fgn-op` | `DELETE /api/users/qa-fgn-op` → 204 |
| tenant `qa-foreign` (`t_ee34a57aceb56e3fd6f42d66c004e35d`) | `DELETE /api/tenants/<id>?confirm=qa-foreign` → 204 (the name-confirmation guard was exercised: an unconfirmed delete is refused 400) |
| image tag `netops-api:qa-rollback-20260903` | removed after the rebuilt image was verified |
| scratch tokens / captures | outside the repo, discarded |

Verified afterwards by re-reading the API: `GET /api/tenants` → `global` + `lab`
only · `GET /api/users` → `admin` only · `GET /api/bindings` → the platform admin
binding only · `GET /api/devices` → `spine1`, `spine2` unchanged.

**Deliberately left in place:** `FEATURE_PROTOCOL_DIAG_COLLECT=true` in the
gitignored `deployment/docker/.env`, and the api running the rebuilt image
`16cb7fd83130` (the tree as of this run, plus the D-1 / D-10 fixes). The previous
image was `335871f9dbf1`.

Not removable, and recorded rather than hidden: the `corr_signals` and audit rows
this run generated in ClickHouse (they age out with retention), the `qa-fgn-op`
`ai` tool-audit lines in the api log, and the SSH sessions/parse errors this run
caused `spine1` to log. No device configuration was changed — every command
issued to the spines was read-only.

---

## 10. Closure recommendations

| Row | Recommendation |
|---|---|
| **P4-A** — Troubleshooting rebuild | **CLOSE.** Deployed and verified against live data: seven lane calls, zero 5xx, and the honesty contract (`not_connected` ≠ `empty`) demonstrated on real telemetry — the health lane correctly reads *not connected* for an uncollected family while the routing lane reads *empty* for a collected one. The error boundary passes 4/4 and its strings are in the served bundle. |
| **P4-B** — Protocol diagnostics collect→analyze | **DO NOT CLOSE.** The remaining checkbox ("deploy with the flag on and run one live collect per protocol") was executed: transport, credential fallback, closed command table, bounded IO, per-command errors, signature matching and 6/6 redaction all work — but **7/7 commands failed on the only devices in the lab** because of **D-2**. Fix D-2 (the one-line honest form is enough) and re-run one collect per protocol; then close. |
| **P4-C A–A4** — Iris Phase A / chaining / state battery / device-state tools | **CLOSE with D-3 and D-4 filed as follow-ups.** Skill selection with a stated reason, bounded 2-hop chaining with per-hop reasons, five to six tool calls, `state:`/`diag:`/`topo:`/`log:` citations, honest missing-evidence and correct cross-tenant refusal were all observed live. `get_device_state` correctly reports SR Linux as an unknown dialect (`showparse` has no `nokia/srlinux`) rather than guessing — the honest half of D-2. D-3 (health/status phrasings reach no skill) and D-4 (a total collection failure reported as "no signature matched") are real but neither undoes what A–A4 built. |
| **P4-C B** — Iris investigation memory | **CLOSE — but only because D-1 was fixed in this run.** As shipped, the write path was unreachable on any `STORE_BACKEND=file` deployment: `POST /api/ai/feedback` panicked on every valid rating (**D-1**), so no investigation could ever be judged and no `memory:` citation could exist. With the one-line fix deployed the **entire loop was then proven live**: rate up → `204` + `investigation_remembered: true` → next ask returns `memory:710b7f4e-…` labelled `(operator confirmed)`, cited by its own row id, carrying both guardrails ("the quoted evidence ids are HISTORICAL", "prior investigations are CONTEXT, not current state"), and invisible to a foreign tenant. Close **after** the D-1 fix is reviewed and merged — the feature is correct, its only door was locked. |
| **P4-D #4** — interfaces grouped by VRF | **DO NOT CLOSE.** The API is correct and honest (dialect `VPRN` resolved, `coverage.vrf_labels=false` + a note naming the exact missing series, `routing_instances` surfaced from the BGP lane with `source` stamped) but returns **zero interfaces** on the lab, because the gnmic `ownership-gate` deletes `device_if_*` and no SNMP profile reaches the SR Linux spines (**D-7**). The device-detail UI cannot be validated against real data until a transport owns the interface families for these devices. |
| **P4-D #11** — OSPF + IS-IS advanced monitoring | **CLOSE the IS-IS half; keep the OSPF half open.** Open item (a) is now **satisfied**: all four IS-IS depth series are live in VictoriaMetrics from the SR Linux spine — `device_isis_lsp_count`=6, `_spf_runs_total`=10, `_area`=`49.0001`, `_adj_hold_seconds`=30 ×4 — and agree with the device's own `show network-instance default protocols isis adjacency`. IS-IS is **live_validated**, not `lab_validated`. Item (b) stands unchanged: no OSPF-speaking SNMP device exists, and every OSPF field correctly returns `null` + a note naming the MIB object. Item (c) (`telemetry-catalog/`) was not exercised by this run. Fix the D-8 wording while the file is open. |
