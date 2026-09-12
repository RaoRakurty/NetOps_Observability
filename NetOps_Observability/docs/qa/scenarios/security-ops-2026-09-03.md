# Real-world scenario tests — security & ops, lab stack, 2026-09-03

**Run by:** QA agent (live stack, `localhost:8000`) · **Window:** 2026-09-03 03:55–04:35 UTC
**Tenant under test:** `lab` = `t_d3d501aa08e2395893b378a453b8af67` (owns `spine1`, `spine2` — Nokia SR Linux v26.3.2, 7220 IXR-D3L, 172.40.40.11/.12)
**Method:** black-box against the running stack; code read only to root-cause a failure. No product code changed.

Flags actually ON in `deployment/docker/.env` (verified, not assumed):
`FEATURE_SECURITY_LANE`, `FEATURE_CONFIG_BACKUP`, `FEATURE_BMP`, `FEATURE_BGP_ALERTS`, `FEATURE_BGP_LIVE_FEED`.
**`FEATURE_PACKET_CAPTURE` and `FEATURE_PROTOCOL_DIAG_COLLECT` are NOT set** (the task brief listed the latter as on — it is not). See D-07.

Everything created during the run was removed; see [Cleanup](#cleanup).

---

## Verdict summary

| # | Scenario | Verdict |
|---|----------|---------|
| 1 | Rogue local account (threat detection, log lane) | **PASS with a coverage gap** — detection + grounding + correlation all fired end-to-end in 73 s; the exposure-story **list** API is structurally dead (D-01) and the SR Linux phrasing of the same event matches nothing (D-02) |
| 2 | Config drift capture / golden / diff / sealing / redaction | **PASS** — one stale-read wrinkle (D-03) |
| 3 | Packet capture on spine1 | **BLOCKED, honestly** — flag off; and unreachable by design for SR Linux. Refusal is not honest in shape (D-04, D-05) |
| 4 | Compliance rules toggle + saved views + isolation | **PASS** — every isolation assertion held |
| 5 | Advisory with a provisioned feed | **FEED PASS / ASSESSMENT FAIL** — feed loads and hot-reloads correctly; no SR Linux device can ever be assessed (D-06) |
| 6 | Engine-down drill | see §6 |
| 7 | Alert noise review | **FAIL** — ~58 phone pushes/hour, all warning tier, ~20 % lost to ntfy 429 (D-08). A fix is already in flight in the working tree. |

Cross-cutting: `GET /api/security/findings/{id}` 404s for **every** finding (D-09).

---

## 1. Rogue local account on a switch — threat detection over the log lane

**Setup.** No device was touched and no temporary device was needed: `spine1` is already in the
lab registry and already in the vector `device_tenant` enrichment table (proven by the 7 060
genuine SR Linux syslog docs already indexed under `netops-syslog-t_d3d5…-2026.09.03`).
Two RFC5424 lines were injected to the host syslog edge (UDP 514 → `syslog-ng` → `vector-aggregator`
→ `netops.syslog` → `vector-router` → OpenSearch), both with `HOSTNAME = spine1`:

* **Line A — IOS/NX-OS phrasing** (what the threatlane catalog targets):
  `%SEC-5-CONFIG: username backdoor privilege 15 secret 5 $1$Qa9L$LabDrillOnly…`
* **Line B — SR Linux native phrasing for the same real-world event**:
  `User 'admin' committed candidate: set /system aaa authentication user backdoor password $y$j9T$…`

### What fired

| Step | Time (UTC) | Evidence |
|---|---|---|
| Lines sent to UDP 514 | 04:04:39 | — |
| Both indexed, attributed to `lab` | 04:04:56 (**17 s**) | `tenant_id=t_d3d5…`, `tenant_registry=hit`, `tenant_attribution=enriched`, `source_ip=172.18.0.12` |
| `POST /api/security/scan?as_tenant=` | 04:05:23 | `202 {"queued":true,...}` |
| Findings emitted | 04:05:23.613 | scan `…-20260903T040523.613Z` |
| Engine grounded them | 04:05:5x | `corr_evidence_events_total{class="security",outcome="grounded"}` **384 → 514 (+130)**; `outcome="orphan"` unchanged at 130, `invalid` 0 |
| Correlation object created | 04:05:52 | `71403abf-95a3-53ad-8a0a-9da56a88bd17` |

**End-to-end: syslog on the wire → correlated security story in 73 seconds.**

Findings emitted (`GET /api/security/findings?as_tenant=`), both on `resource.uid = spine1`:

```
raw_rule_id = log-new-local-user        control = T1136.001  severity high  status Fail
  standards    = ["MITRE ATT&CK T1136.001"]
  evidence_ref = {locator: "syslog:spine1#log-new-local-user", kind: "log-event",
                  ruleset_version: "correlix-threatlane-2026-08-27"}
raw_rule_id = log-privilege-escalation  control = T1098      severity high  status Fail
```

`GET /api/security/findings/facets` gained `"MITRE ATT&CK T1136.001": 1`, `"MITRE ATT&CK T1098": 1`
and `evidence_class.signal: 2`.

The correlation object is a genuine security story:

```
top_hypothesis  = sig.ent.security.exposure-story      verdict_tier = suspected
affected        = {"devices":["spine1"]}               top_confidence = 1
grounding       = topo    plane_count = 1   signal_count = 66   edge_count = 3
evidence_missing= ["single modality class (security); need ≥2 — every modality has a blind spot"]
nodes           = device:spine1:security_posture / :security_exposure / :security_signal
```

### What did NOT fire

* **`GET /api/security/exposure-stories` returns `[]`** for every window tried (`1h`, `2h`, `24h`,
  `720h`, no `since`) while `GET /api/correlations` shows the story and
  `GET /api/security/exposure-stories/{id}` renders its full edge set. **→ D-01 (High).**
* **Line B produced nothing.** Both findings carry `native_id … :SEC-5-CONFIG`, i.e. both came from
  line A. **→ D-02 (High).**
* The engine's quarantine path was never entered for this injection — correct, because `spine1` is
  registry-known. (It *is* being entered constantly for another source: see D-10.)

### Naming note (not a defect)
The brief expected `evidence_class: "threat"`. The product is internally consistent and the brief
was wrong: rule *family* is `threat`, emitted *evidence class* is `signal`
(`secapi.SecuritySignalKinds` = `security_posture | security_exposure | security_signal`).

---

## 2. Config drift

| Step | Result |
|---|---|
| `POST /api/devices/spine1/config/backup` | `202 {"job_id":"e59c54fea64f26e5","status":"queued"}` — capture completed in ~40 s over the SSH gateway |
| `POST /api/devices/spine1/config/golden` `{"sha":"22fe79d2…"}` | `200 {"golden_sha":"22fe79d2…"}` |
| Re-capture, then `GET …/config/status` | **`state: "in_sync"`**, `golden_sha = last_sha = 22fe79d2…`, `next_scheduled_at 2026-09-04T04:04:07Z` |
| `GET …/config/versions` | `golden: true`, `drift: "in_sync"`, `size_bytes: 59733` |
| `GET …/config/diff?from=A&to=A` | `200 {"added":0,"removed":0,"unified":"","truncated":false}` |
| `GET …/config/diff?from=A&to=<spine2's sha>` | **`404 {"error":"not found"}`** — a foreign version id is not an oracle |
| `GET …/config/diff?from=A&to=deadbeef` | `400 "from and to must be configuration version ids"` |
| tenant-2 `GET /api/devices/spine1/config/versions` | **`404`** |
| tenant-2 `GET /api/config/drift` | `{"items":[],"total":0}` |

**Sealing — verified on disk.** `data/config-backups/t_d3d5…/spine1/22fe79d2….sealed`,
mode `0600` in a `0700` directory, 79 687 bytes, content is `v1:` + base64 ciphertext
(vault AES-256-GCM, AAD `configstore.config:spine1:<sha>`). `grep -c 'interface|admin|network-instance|srl'` = **0** — no plaintext.

**Redaction — verified through the API.** `GET …/config/versions/{sha}` returns 728 lines with
**34 `****` masks**. Every credential-bearing line is masked:

```
set / system aaa authentication linuxadmin-user password ****
set / system snmp access-group SNMPv3-Group security-entry srl-monitor authentication password ****
set / system snmp access-group SNMPv3-Group security-entry srl-monitor privacy password ****
```

The real SSH account password from `.env` does **not** appear anywhere in the response, and no
`$y$`/`$6$` hash survives. The read is audited `sensitive: true, redacted: true`.

**Honest limit.** The **drift-emit** path (`state: drifted` → a `device_config_change` symptom on the
bus) was **not** exercised: producing a second distinct version requires an actual configuration
change on spine1, which is out of scope for a read-only test. Both captures hashed identically
(`22fe79d2…`), so `versions` holds one entry and a two-version diff is not constructible here.
What is proven is capture → seal → golden → re-evaluate → `in_sync`, plus the diff/redaction
contract and its isolation behaviour.

---

## 3. Packet capture on spine1 — honest refusal, dishonest shape

`FEATURE_PACKET_CAPTURE` is **not set**, so `s.pcapAPI` is nil and the pcap subtree is never
registered. Observed:

```
POST /api/devices/spine1/pcap   → 405  "method not allowed"      (plain text)
GET  /api/devices/spine1/pcap   → 404  "404 page not found"      (plain text)
POST /api/devices/nosuchdev/pcap→ 405  "method not allowed"
```

Two problems (D-04, D-05): the responses are bare Go-mux plain text rather than the
`{"error": …}` envelope every other endpoint uses, and the method split (405 vs 404) leaks that the
router is falling through to the generic device handler. **`/api/openapi.json` advertises
`/api/devices/{id}/pcap` with `get` and `post`** regardless of the flag, so the published contract
promises a route that answers 404/405.

Even with the flag on, capture on spine1 is **unreachable by design**: `internal/vendorprofile/profiles/nokia.json`
declares no `pcap_*` keys for either the `sros` or the `srlinux` platform (only `cisco_iosxe`,
`cisco_nxos`, `juniper_junos`, `arista_eos` exist), so `Registry.PcapFamilyForPlatform` misses and
the manager returns `ErrNoPlatform` → `400 "no packet-capture command set is bound for this device's
platform"`. That refusal is correct and is the right answer — the module never guesses a command at
a live device.

Third blocker found while checking: **`data/pcap` on this host is `drwxr-xr-x root:root`.**
`pcap.NewFileBlobStore` does an unconditional `os.Chmod(root, 0700)`, which the non-root api uid
cannot perform on a root-owned directory, so turning the flag on today would fail at boot with
`packet capture could not be started — NO captures will be possible`. **→ D-11.**

Not tested (unreachable): status, audited download, pcap validity, one-per-device, cross-tenant 404.

---

## 4. Compliance rules and saved views

A temporary second tenant `qa-iso-drill` (`t_8a4953577787c469357793b733ad527a`) was created for the
isolation half and deleted afterwards.

### Rule toggle — proven by behaviour, not just by the read-back

| Assertion | Result |
|---|---|
| `PUT /api/security/rules` from the **global/platform view** (no `as_tenant`) | **`400`** `"select a tenant before changing rule state — rule enablement is per-tenant"` |
| `PUT …?as_tenant=lab` `[{"rule_id":"log-new-local-user","enabled":false}]` | `200`, read-back `enabled: false` |
| Same rule read as tenant-2 | **`enabled: true`** — the disable did not leak |
| Rescan at 04:10:27 over the *same* syslog window | newest scan emits **only** `log-privilege-escalation / T1098`; `log-new-local-user / T1136.001` **is gone** |
| Per-scan finding counts | scan `040523` = spine1 34 / spine2 32 (2 signals) → scan `041027` = spine1 **33** / spine2 32 (1 signal) |
| Re-enable | `200`, read-back `enabled: true` |
| Unknown rule id | `400 "unknown rule_id \"no-such-rule\""` |
| `tenant_id` in the body | `400 "json: unknown field \"tenant_id\""` |

### Saved views

| Assertion | Result |
|---|---|
| `POST /api/security/views?as_tenant=lab` `{"name":"QA drill high sev","filters":{"severity":"high"}}` | **`201`**, id `6eab708a-…`, `created_by: admin`; **no `tenant_id` on the wire** |
| `GET …?as_tenant=lab` | the one view |
| `GET …?as_tenant=qa-iso-drill` | **`[]`** |
| `DELETE /api/security/views/{lab id}?as_tenant=qa-iso-drill` | **`404 "saved view not found"`** |
| `DELETE …?as_tenant=lab` | `200 {"deleted": true}` |

### Findings isolation (spot checks)

| Assertion | Result |
|---|---|
| tenant-2 `GET /api/security/findings` | `{"items":[],"total":0}` |
| tenant-2 `GET /api/security/findings/{lab finding id}` | `404 "finding not found"` |
| lab `GET /api/security/findings/{its own finding id}` | **`404` — should be 200. → D-09** |

---

## 5. Advisory with a provisioned feed

`VULN_FEED_PATH` defaults to `/data/vuln/advisories.csv`; `data/vuln` is bind-mounted there and was
empty. The format is a 13-column CSV (`internal/vuln/feed.go`), hot-reloaded on mtime.

A minimal synthetic feed was dropped in (gitignored path, fully revertable):

```csv
vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
nokia,sr_linux,CVE-2026-22222,medium,5.4,,,26.4.0,,,0,2026-06-01,QA DRILL ONLY …
nokia,sros,CVE-2026-33333,high,7.5,,,99.99.99,,,0,2026-06-01,QA DRILL ONLY …
```

**The feed half works.** `GET /api/vulns` immediately reported
`"feed":{"entries":2,"kev_entries":0,"updated_at":"2026-09-03T04:13:32Z"}` — parsed, counted,
hot-reloaded without a restart.

**The assessment half cannot work.** The rescan at 04:13:32 produced the *same* two
`advisory-unassessed` findings (spine1, spine2), and `/api/vulns` names the reason itself:

```json
"unassessed":[{"device_id":"spine1","vendor":"nokia","reason":"OS version not present in sysDescr"},
              {"device_id":"spine2","vendor":"nokia","reason":"OS version not present in sysDescr"}]
"summary":{"devices":2,"assessed":0,"findings":0,"affected":0,"kev":0}
```

Even the deliberately-broad `sros` row (`ver_end_incl 99.99.99`) matched nothing, because
`versionMatches` correctly refuses to match an **empty** device version. **→ D-06.**

**Reverted:** the file was deleted at 04:14:32 and `GET /api/vulns` returned to
`{"vuln_enabled": false}` on the next call. `git status data/` is clean (`data/` is gitignored).

---

## 6. Engine-down drill (ops)

One drill, one page-tier alert. Timeline (all UTC, 2026-09-03):

| t | Event | Evidence |
|---|-------|----------|
| 04:16:26 | `docker compose stop correlation` issued | — |
| 04:16:56 | container stopped | — |
| **04:17:00** | `kafka_consumergroup_members{consumergroup="netops-correlation"} = 0` | **detection latency 4 s** |
| 04:17:00 | `CorrelationConsumerDead` → **pending** (`for: 2m`) | vmalert `/api/v1/alerts` |
| ~04:18 | watchdog cron minute: `watchdog: DOWN -> correlation: not running` **+** `ENGINE_NOT_CONSUMING: correlation consumer group has ZERO members (bus backlog 22) — RCA has stopped; containers will still read healthy. Runbook: docs/runbooks/engine-not-consuming.md` | `data/stack-watchdog.log` |
| 04:19:00 | `CorrelationConsumerDead` → **firing** | vmalert |
| **04:19:40** | api composes the page and **the push FAILS** | `{"alertname":"CorrelationConsumerDead","tier":"page","msg":"platform alert push to host monitoring FAILED","error":"ntfy: status 429"}` |
| 04:19:52 | `docker compose start correlation` | — |
| 04:20:17 | container started | — |
| 04:20:38 | consumer group **re-joined** — live consumer-id on every partition, LAG 0 across `netops.security / syslog / flows / bgp / probes / cloud / …` | `kafka-consumer-groups.sh --describe` |
| **04:21:14** | `kafka_consumergroup_members = 1` again | **57 s to rejoin** |
| 04:21:33 | backlog drained: peak lag 405 → **10** | VictoriaMetrics |
| — | **no `resolved` push was ever sent** | zero `"tier":"resolved"` lines in the api log, `netops_alert_webhook_pushed_total{tier="resolved"} = 0` |
| 04:26:38 | `bash scripts/deploy-qualify.sh` | **INCOMPLETE** (9 PASS / 0 FAIL / 1 required SKIPPED) |

**Detection worked. Delivery did not.**

* `ENGINE_NOT_CONSUMING` appeared on the watchdog's very next cron minute with a live backlog
  figure and a runbook pointer, and re-armed each minute (backlog 22 → 155 → 280). Exactly right.
* Exactly **one** page-tier alert fired — `CorrConsumerNotRunning` and `CorrelationLagGrowing` did
  not (the latter is correctly gated on `members >= 1`). The one-page budget was honoured.
* **The page never reached the phone.** ntfy answered `429` and the deployed build does not retry.
  **→ D-08.**
* **The resolve never reached the phone either** — and not because of a 429: the api never received
  a `status: resolved` alert at all. `tier="resolved"` has **never** been non-zero on this stack.
  **→ D-12.**

`deploy-qualify.sh` result — the recovery itself is clean; the INCOMPLETE is the harness:

```
✓ Q1 correlation consumer joined      kafka_consumergroup_members = 1
✓ Q2 router consumers joined          9/9 groups with a live member
✓ Q3 correlation lag draining         samples [3 0 0]
✓ Q4/Q5 vector-aggregator/router emitting   11 799 / 8 601 events in 5m
✓ Q7 api serving 200 · B1/B2/B4 broker checks PASS
— Q6 no bootstrap-class Kafka errors  SKIPPED: "could not read logs for correlation/vector-router (exit 124)"
RESULT: INCOMPLETE — 1 required check(s) could not be evaluated.
```

Q6 times out (`exit 124`) reading the correlation container's log, which is emitting several INFO
lines per second. On this box the gate can therefore never reach QUALIFIED. **→ D-13.**

**Also noted during the drill** — `docker compose exec correlation python3 … http://127.0.0.1:8080/healthz`
(the recipe in the task brief) is stale: 8080 is `Connection refused`, and 8443 is **HTTPS**
(`RemoteDisconnected` on a plaintext GET). The engine's health/metrics port is 8443/TLS.

---

## 7. Alert noise review

**Window A — 34 min under the api container that ran 03:26:59 → 04:08:04**

| alertname | tier | pushed OK |
|---|---|---|
| DeviceUnreachable | warning | 6 |
| CollectorDown | warning | 6 |
| CollectorAllTargetsUnreachable | warning | 4 |
| CollectorPartialReachability | warning | 3 |
| VectorComponentErrors | warning | 3 |
| CorrDeadLettersRising | warning | 2 |
| CorrEventsDroppedRising | warning | 2 |
| NoSamplesIngested / DiskHeadroomLow / OpenSearchDocumentsRejected / VectorEventsDiscarded / VectorOpenSearchRetryStorm / HostCPULoadHigh / HostDiskLow | warning | 1 each |
| — | **page / resolved** | **0** |

33 delivered + 8 rate-limited in 34 minutes ≈ **58 phone notifications per hour, every one of them
tier `warning`**, at 03:30–04:00 local. 19.5 % were already being lost to `ntfy: status 429`.

**Window B — since the 04:08:04 api restart (~20 min)**

| alertname | tier | outcome |
|---|---|---|
| CollectorDown / CollectorAllTargetsUnreachable / CollectorPartialReachability | warning | 3 each — **all FAILED 429** |
| VectorComponentErrors | warning | 2 — FAILED |
| NoSamplesIngested, DiskHeadroomLow, CorrDeadLettersRising, CorrEventsDroppedRising, HostDiskLow, HostCPULoadHigh | warning | 1 each — FAILED |
| **CorrelationConsumerDead** | **page** | 1 — **FAILED** |

**18 attempts, 18 failures — 100 % of alert delivery is currently down**, and the one page in the
set is the drill's engine-down page. `netops_alert_webhook_push_failures_total{reason="send_error"} = 18`,
`netops_alert_webhook_pushed_total{tier=*} = 0`.

Supporting ratios over the last 8 h: 3 217 alerts received → 2 693 suppressed by cool-down →
153 dispatched → 79 host pushes.

### Digest candidates (chronic, never actionable at 04:00)

Every one of these has been continuously firing for hours or days and re-buzzes the phone on each
cool-down expiry. They are status, not incidents:

| alertname | firing since | why it is a digest, not a page |
|---|---|---|
| `VectorComponentErrors` | **2026-08-27 12:16** (7 days) | a chronic component error rate; nothing changes minute to minute |
| `CorrEventsDroppedRising` | 2026-09-02 22:10 | rate-of-change alert on a stack that has been in this state all night |
| `DiskHeadroomLow` | 2026-09-01 06:58 | duplicates `HostDiskLow`; disk moves at hours-per-percent |
| `CorrDeadLettersRising` | 2026-09-03 00:54 | same class |
| `CollectorDown` / `CollectorAllTargetsUnreachable` / `CollectorPartialReachability` / `DeviceUnreachable` | 2026-09-02 58:30 | **four rules describing one fact** — the lab collectors cannot reach their targets. One page-worthy condition, four buzzes each cool-down. |
| `NoSamplesIngested` | 2026-09-03 02:59 | consequence of the same collector fact |
| `HostCPULoadHigh` | 2026-09-03 03:27 | a 4-core box under a soak |

`AlertingHeartbeat` is correctly never pushed.

**A fix is already in flight**: the working tree carries new, uncommitted
`internal/alertwebhook/digest.go` and `pushbudget.go`, and `hostroute.go` has grown a retry path
(`hostJob.retryable()` = page-only, `hostMaxAttempts`, `retryableErr`) and a `r.budget.take(...)`
page reserve. **None of that is in the deployed image** — the api is running an older SHA
(`BUILD DRIFT` was reported by the watchdog throughout the run). The measurements above are the
"before" picture for that change, and they say the reserve/retry is necessary, not optional:
the *only* page this stack has produced in 8 hours was dropped by the noise.

---

## Defects

Severity: **High** = a shipped surface does not work / a page can be lost · **Medium** = wrong or
misleading behaviour with a workaround · **Low** = cosmetic or documentation.

### D-01 — `GET /api/security/exposure-stories` can never return a row (High · correlation engine + secapi)

The list is joined through a column the engine never populates.

* `secapi/correlations.go:securityExposureStoriesCond` filters
  `ev.signal_id IN (SELECT sig.signal_id FROM netops.corr_signals WHERE sig.kind IN
  ('security_posture','security_exposure','security_signal'))`.
* `src/correlation/engine.py:2889` — `_edge_evidence_row` hardcodes
  **`"signal_id": str(uuid.UUID(int=0))`**. Only `_identity_evidence_row` (app-identity fusion, #81 P5)
  carries a real id, and there are no fused app identities here.
* Measured on the live cluster: **every one of the 61 229 477 rows** in `netops.corr_evidence` has
  `signal_id = 00000000-0000-0000-0000-000000000000`. Running the predicate by hand returns `0`.
* `netops.corr_signals` is *fine* — it holds `security_posture` 378, `security_exposure` 70,
  `security_signal` 2 in the last hour. The break is entirely on the evidence side.

The comment above the function ("HONEST EMPTINESS … the engine-side grounding that lands security
signals in corr_signals is a separate task (T2b)") is now stale and is actively hiding this: the
grounding shipped, and the page still reads empty for a different reason.

Proof it is not "nothing correlated": `GET /api/correlations?as_tenant=lab` returns
`71403abf-95a3-53ad-8a0a-9da56a88bd17`, `top_hypothesis = sig.ent.security.exposure-story`, and
`GET /api/security/exposure-stories/71403abf-…` (the **detail** route, which does not use the
predicate) renders its full edge set. Only the list is dead.

**Fix direction:** either stamp the real `signal_id` on edge evidence rows, or key the predicate on
something the engine actually writes (e.g. the `device:<id>:<kind>` node ids already present on the
object). Whichever is chosen, the stale "honest emptiness" comment must go with it.

### D-02 — the threatlane log catalog has zero SR Linux coverage (High · threatlane)

`internal/threatlane/catalog.go:302` matches `\busername\s+\S+[^\n]*\b(secret|password)\b`, and the
platform→rule bindings exist only in `profiles/cisco.json` and `profiles/arista.json`. Nokia's
profile binds no log rules at all.

Measured: the IOS-phrased line fired **two** rules; the SR Linux-phrased line describing the *same
real event* (`set /system aaa authentication user backdoor password …`) fired **none** — SR Linux
says `user`, never `username`. SR Linux is the only `fidelity: live_validated` platform in
`nokia.json` and is what the lab fabric actually runs, so on the reference deployment every one of
the 8 `log-*` threat rules is dead. A customer running SR Linux gets a threat lane that is
structurally silent while reporting itself enabled.

### D-03 — marking a version golden does not refresh the drift board (Medium · configstore/configdrift)

`POST /api/devices/{id}/config/golden` returns `200 {"golden_sha": …}` and
`GET …/config/versions` immediately shows `golden: true`. But `GET …/config/status` and
`GET /api/config/drift` still reported `golden_sha: null, state: "changed"` — the drift state row is
a materialised snapshot only rewritten when a capture is **evaluated** (`configdrift/evaluator.go`
reads `ev.GoldenSHA` from `configstore/manager.go:501`). It self-heals on the next capture (proven —
the 04:04 capture flipped it to `in_sync`), but `CONFIG_BACKUP_INTERVAL` is 24 h, so between an
operator's "mark golden" click and the next daily capture the drift board says the device has no
baseline and is drifting. Setting golden should re-evaluate that device.

### D-04 — flag-off pcap answers plain text, not the JSON error envelope (Medium · main.go routing)

`POST /api/devices/spine1/pcap` → `405 "method not allowed"`, `GET` → `404 "404 page not found"` —
raw `net/http` strings, no `{"error": …}`. A client cannot tell "feature disabled" from "route
typo", and the 405/404 split leaks that the request fell through to the generic device handler.

### D-05 — OpenAPI advertises pcap regardless of the feature flag (Medium · internal/openapi)

`/api/openapi.json` lists `/api/devices/{id}/pcap` (`get`,`post`), `/pcap/{capture_id}`
(`get`,`delete`) and `/pcap/{capture_id}/download` while `FEATURE_PACKET_CAPTURE` is off and the
routes are unregistered. The published contract promises routes that answer 404/405.

### D-06 — no SR Linux device can ever be advisory-assessed (High · vendorprofile)

`nokia.json` declares `os_parse` for the `sros` product only, with
`os_version_pattern = (?i)\bTiMOS-[A-Z]+-([0-9][0-9A-Za-z.]*)`. An SR Linux box resolves to product
`sros` with an **empty** version, and `vuln.versionMatches` correctly refuses to match an empty
version, so the lane always takes the `advisory-unassessed` branch. Confirmed live: with a valid
2-entry feed loaded (`/api/vulns` → `"entries":2`), `/api/vulns` reports
`assessed: 0` and `reason: "OS version not present in sysDescr"` for both spines — even against a
deliberately unbounded `sros` row. The vendor profile's own note records spine1 as
**SR Linux v26.3.2, live-validated**, so the version *is* known to the project; it just never
reaches the matcher. Needs an `srlinux` entry in `os_parse` with an SR-Linux version pattern.

Secondary: the `advisory-unassessed` **reason** is carried in the finding's `Detail` but is not in
the indexed document (`attrs` holds only category/control/status). Only `/api/vulns` can explain
*why* an asset is unassessed; the security findings surface cannot.

### D-07 — the lab is not running the flags the brief assumed (Low · environment)

`FEATURE_PROTOCOL_DIAG_COLLECT` and `FEATURE_PACKET_CAPTURE` are absent from
`deployment/docker/.env` and therefore off. `deployment/docker/.env:413` also still carries the
stale comment *"FEATURE_CONFIG_BACKUP stays false until the SR Linux/EOS capture dialects land"*
directly above `FEATURE_CONFIG_BACKUP=true`.

### D-08 — host-monitoring pushes are being rate-limited away, page tier included (High · alertwebhook — FIX IN FLIGHT)

`ntfy: status 429` on **18 of 18** attempts since the 04:08 api restart, including the drill's
`CorrelationConsumerDead` **page**. In the preceding 34-minute window, 8 of 41. The deployed build
counts and logs the failure and returns without retrying. The working tree already contains the fix
(page-only retry + a page reserve in the new `pushbudget.go`, plus `digest.go`); it is **not
deployed**. Deploying it, and cutting the warning-tier flood that consumes the quota (see §7 digest
candidates), is what makes a page survivable.

### D-09 — `GET /api/security/findings/{id}` 404s for every finding (High · secapi + indexing)

The list handler returns `id` derived from the OpenSearch `_id`
(`DecodeFinding(h.Source, h.ID)`), but the by-id handler searches for a **source field**:
`secapi/query.go:265 GetBody` → `term { cx_finding_id: id }` (`FieldDocID = "cx_finding_id"`).
The indexed documents do not contain that field — a raw document's `_source` keys are
`attrs, cx_event_id, entity_id, entity_tokens, entity_type, headers, kind, log_index_base,
message_key, native_id, offset, partition, schema_version, severity, source_type,
tenant_attribution, tenant_id, tenant_seg, timestamp, topic, ts`. **No `cx_finding_id`.**
Verified with an id copied verbatim out of the newest scan's list response → `404 "finding not found"`.
Passing `native_id` instead → `400 "invalid finding id"`. Any UI "click a finding for detail" flow
is broken. Fix is either an `ids` query on `_id`, or stamping `cx_finding_id` in the router.

### D-10 — flow exporters 172.40.40.51/.52 are quarantined, continuously (Medium · inventory/ops)

`SECURITY: tenant claim refused — event quarantined, NOT persisted lane=flows
reason=identity_unattributable identity=172.40.40.51 … refused_total=868`, recurring every few
seconds for both addresses. The zero-trust refusal is *correct* — these addresses are in no device
row — but the consequence is that all lab flow telemetry is being discarded, which is also why
`netops-flows-*` indices hold ~130 docs/day. Either register the exporters as devices in the `lab`
tenant or stop them.

### D-11 — `data/pcap` is root-owned; enabling packet capture would fail at boot (Medium · installer/ops)

`drwxr-xr-x root root`. `pcap.NewFileBlobStore` performs an unconditional `os.Chmod(root, 0700)`,
which the non-root api uid cannot do on a root-owned directory, so `buildPacketCapture` would fail
with `packet capture could not be started — NO captures will be possible`. Compare
`data/config-backups`, correctly `rao:rao 0700`.

### D-12 — the `resolved` leg has never fired (High · vmalert notifier config)

`netops_alert_webhook_pushed_total{tier="resolved"}` is **0** across the whole 8 h of
VictoriaMetrics history, and the api log contains no line mentioning `resolved` at all —
`CorrelationConsumerDead` cleared out of vmalert's alert list without the api ever receiving a
`status: resolved` payload. The receiver code handles it correctly
(`alertwebhook.go:635` → `DispatchResolve` + `pushHost(..., "resolved")`), so the gap is upstream at
vmalert's `-notifier.url` delivery. Operationally this means **every page leaves a stuck alert on
the phone forever** — there is no all-clear. This is the other half of D-08 and should ship with it.

### D-13 — `deploy-qualify.sh` Q6 times out on a busy stack (Medium · scripts)

`Q6 no bootstrap-class Kafka errors — SKIPPED: could not read logs for correlation/vector-router
(exit 124)`. The correlation container logs several INFO lines per second (one per ClickHouse
insert), so the log read hits its timeout. Because a required SKIP downgrades the whole run to
`INCOMPLETE`, the gate can never reach QUALIFIED on this box. Bound the read (`--since`, `--tail`,
or grep server-side) instead of reading the whole stream.

### D-14 — tracker 225 root-caused: the snapshot repository is missing files, not disk-bound (Medium · storage ops)

Read as admin via the client cert. Repo `netops-fs`, 14 snapshots, the last three all `PARTIAL` with
a worsening ratio: `2026-08-31` 48/62 shards failed · `09-01` 32/48 · `09-02` 28/46. Every failure is
the same class:

```
NoSuchFileException[/usr/share/opensearch/snapshots/indices/<uuid>/0/index-<gen>]
```

i.e. repository metadata files are **gone from the repo**, not shards refused by a watermark — the
disk-pressure hypothesis in tracker row 225 is wrong. The failing indices are largely ones long
since deleted from the cluster (`netops-syslog-t_burst*-2026.08.17`, `netops-*-untagged-2026.08.20/21/25/26`),
so the repo directory was pruned out from under OpenSearch. Remedy: `POST /_snapshot/netops-fs/_cleanup`
+ repository verify, or delete and recreate the repository and take a fresh full snapshot; then add
the shard-failure `reason` to the watchdog line as row 225 already asks.

### D-15 — the watchdog log carries no timestamps (Medium · scripts, §16)

`data/stack-watchdog.log` is 13 MB of unstamped lines. During this drill the `ENGINE_NOT_CONSUMING`
detection minute had to be inferred from an external clock. A production watchdog log that cannot
date its own findings cannot be used in a post-incident timeline. (Separately, the path in the task
brief — `scripts/stack-watchdog.log` — is a **stale orphan** last written 2026-08-22; cron writes to
`data/stack-watchdog.log`. The orphan should be deleted so nobody reads it as current.)

**FIXED 2026-09-03.** `stack-watchdog.sh` now emits every diagnostic through
`log()`/`logerr()`, which stamp `%Y-%m-%dT%H:%M:%S%z` on **each** line — including every
continuation line of the multi-line `DOWN ->` summary. The stale path is corrected in
`README.md` (the documented cron now writes `data/stack-watchdog.log`) and in
`scripts/support-bundle.sh`, whose candidate list preferred the orphan over the live log; the
orphan file itself is untracked and still needs deleting on the dev host
(`rm NetOps_Observability/scripts/stack-watchdog.log`, ~24 MB). Guarded by
`tests/test_watchdog_transitions.py::test_every_diagnostic_line_is_timestamped_on_a_healthy_run`,
`::test_every_line_of_the_multiline_down_summary_is_timestamped` and
`::test_no_bare_echo_writes_a_diagnostic_line`.

### D-16 — `docker inspect` exposes the vmalert basic-auth secret (Medium · deployment)

`netops-vmalert-1`'s `Config.Cmd` carries `-datasource.url`, `-remoteWrite.url` and `-notifier.url`
with inline `user:password@host` credentials, so any account in the `docker` group can read them
without touching `.env`. §8 says no hardcoded credentials; container argv is as readable as a file.
Move them to `-datasource.basicAuth.passwordFile` / the `notifier.config` file form backed by a
mounted secret. (Values deliberately not reproduced here.)

### Non-defects checked and cleared

* **Redis is not back.** `netops-redis-1` runs `valkey/valkey:8-alpine`; the compose service keeps the
  name `redis` only so `REDIS_HOST` consumers are untouched (documented at
  `docker-compose.yml:87-94`). No licensing regression. The root `CLAUDE.md` line "Redis … fully
  removed" reads as a contradiction to anyone checking `docker ps`; a five-word note would fix it.
* **The watchdog's `CLICKHOUSE_DATA_STALE: … nothing is being correlated` is not true** — the engine
  was writing `netops.findings` rows continuously throughout (observed live). Whatever that check
  reads is not "correlation is producing"; worth a look, but it did not mislead this run.
* Injected syslog left `message` as `5001 - - %SEC-5-CONFIG: …` — the RFC5424 PROCID/MSGID prefix is
  not stripped by the parser. Cosmetic; it did not affect matching.

---

## Closure recommendations

### P3 Security CTEM

| Capability | Recommendation |
|---|---|
| **Threat detection (log lane)** | **Do not close.** The mechanism is proven end-to-end on real infrastructure — 73 s from wire to correlated story, correct MITRE tagging, correct tenant attribution, grounded by the engine, and a rule toggle that provably silences it. But D-02 means the reference platform has no coverage, and D-01 means the surface built to display the result is empty. Close after D-01 and D-02. |
| **Config drift** | **Close the capture/seal/golden/diff/redaction half** — capture → seal (`v1:` AES-GCM, 0600) → golden → re-evaluate → `in_sync` all verified on a live SR Linux switch, with 34 masked secrets in the API read and clean 404/400 boundaries. **Leave the drift-emit half open**: it needs a real configuration change on a device, which no test here can manufacture. Fix D-03 with it. |
| **Packet capture** | **Cannot be closed. Not exercisable on this lab at all** — flag off, no Nokia pcap family, root-owned blob dir. Needs a Cisco/Arista/Juniper device (or an SR Linux `capture` block) before it can be attested. Fix D-04, D-05, D-11 meanwhile — they are cheap and independent of a device. |
| **Rules & saved views** | **Close.** Every assertion held, including behavioural proof that a disabled rule stops emitting on the next scan and re-enabling restores it, plus refusal from the global view (400) and full second-tenant isolation on views (empty list, 404 delete). |
| **Advisory** | **Do not close.** The feed contract works (parse, count, hot-reload, clean revert). Assessment is structurally impossible for the only devices on the lab (D-06). Close after an `srlinux` `os_parse` entry lands and a rescan produces an assessed CVE finding. |

### Ops — engine-down and alert delivery

**Detection: close. Delivery: do not close.**

Detection is genuinely good — 4 s to observe the dead consumer group, a 2-minute `for` that fired
exactly one page, a watchdog that named `ENGINE_NOT_CONSUMING` with a live backlog count and a
runbook link on its next cron minute, a 57 s rejoin and a lag drain from 405 to 10.

Delivery is fully broken: **18 of 18 pushes lost to `429`, including the page**, and the `resolved`
tier has never fired even once. Close only after the in-flight `digest.go` / `pushbudget.go` work is
**deployed** and re-drilled, and D-12 is fixed. Re-run this drill as the acceptance test — the pass
condition is one page **delivered** and one resolve **delivered**.

### Tracker rows

* **Row 217 — security lane live attestation.** The blocking owner action is **done**: tenant `lab`
  exists and owns both spines, and the lane is emitting. Attested here: 32 findings/device/scan,
  128+ docs in `netops-secfindings-t_d3d5…`, `/api/security/posture` reporting
  `coverage {assessed 2 / total 2 / unassessed 0}` and `funnel {scope 2, discover 128, prioritize 56}`,
  and the engine grounding them as the 4th evidence class (`corr_evidence_events_total{class="security",
  outcome="grounded"}` +130 in one scan, 0 invalid). The predicted verdicts landed:
  `exposure-http/-snmp/-ssh` (AC-4/AC-17) plus the hardening set.
  **Rewrite the row rather than delete it** — the remaining work is no longer the owner action, it is
  the `#/security` funnel being unviewable because of D-01.
* **Row 223 — Ubiquiti SNMPv3 template argument slip.** Not exercised (no Ubiquiti device on the lab,
  and the fix is a one-line profile change plus its golden). **No change; still awaiting the deliberate correction.**
* **Row 225 — PARTIAL OpenSearch snapshot.** **Root-caused, see D-14.** Not a watermark problem: the
  repository is missing its own metadata files, three days running, with a worsening shard-failure
  ratio. Update the row with the `NoSuchFileException` evidence and the cleanup/recreate remedy.

---

## Cleanup

Everything created for this run was removed and verified:

| Object | State |
|---|---|
| Saved view `6eab708a-…` ("QA drill high sev") | deleted, `200 {"deleted":true}` |
| Rule `log-new-local-user` disabled for `lab` | **re-enabled**, read-back `enabled: true` |
| Temporary tenant `qa-iso-drill` (`t_8a49535…`) | deleted (see below) |
| `data/vuln/advisories.csv` | deleted; `/api/vulns` → `{"vuln_enabled": false}`; path is gitignored |
| `correlation` container | restarted; consumer group re-joined, lag drained, `deploy-qualify` 9/9 required PASS |
| Golden baseline on `spine1` | **left set deliberately** — it is a real, correct baseline for a real device and removing it would leave the drift board worse than it was found. Flag if it should be cleared. |
| 2 injected syslog docs + the findings derived from them | see below |

Post-cleanup verification (all as of 2026-09-03 04:33 UTC):

```
_delete_by_query netops-syslog-*      message:"backdoor"                        → deleted 2, failures []
_delete_by_query netops-secfindings-* attrs.raw_rule_id in {log-new-local-user,
                                       log-privilege-escalation}                → deleted 5, failures []
GET /api/security/findings/facets?as_tenant=lab  → evidence_class {exposure 70, posture 378}
                                                    MITRE framework keys: none
GET /api/security/rules?as_tenant=lab            → disabled rules: none
GET /api/security/views?as_tenant=lab            → []
GET /api/vulns                                   → {"vuln_enabled": false}
GET /api/tenants                                 → global, lab   (qa-iso-drill gone)
git status docs/ data/                           → only this file is new from this run
```

(5 findings rather than 3 because the lane's own 15-minute pass re-detected the injected line once
before the syslog documents were removed. All five were mine; none remain.)

**One residue, deliberately left:** correlation object `71403abf-95a3-53ad-8a0a-9da56a88bd17` in
ClickHouse. It is an aggregate over 66 signals of which the injection contributed 2 — the security
exposure-story would have formed from the tenant's genuine posture/exposure signals regardless. An
`ALTER TABLE … DELETE` across `corr_current` / `corr_objects` / `corr_edges` / `corr_evidence` to
remove it is more invasive than the residue is worth, and it is not visible on the security page
anyway (D-01). Flagging rather than acting.

**Not mine:** the tenant `qa-foreign` (`t_a6d18170ba2571d616d6560374fec78f`, 64 findings) and every
other modified file under `docs/` predate or run alongside this session.
