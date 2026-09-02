# UI copy audit — NOC-operator voice, whole site

**Date:** 2026-09-02 · **Tracker item:** frontend wave #1.1 / #2
(“Remove verbose developer-speak copy across the site — NOC-operator voice”).

The first copy pass (`305c800c`) stripped instructional chrome from **operator
surfaces** — Devices, Correlations, Events, Alerts, Incidents, Findings,
AppObservability. It scoped itself explicitly, and the tracker's open item was
“confirm *entire-site* coverage.” This is that sweep: **every** `.ts`/`.tsx` under
`src/frontend/src` (314 non-test files), not only the operator boards.

**Result: 219 string replacements across 100 source files**, plus a mechanical guard
(`src/copyVoice.test.ts`) so the removed phrasing cannot come back quietly.

---

## 1. The standard applied

An operator watching a network reads a screen to answer one question: *what is
happening, and what do I do?* Copy fails that when it:

1. **explains the UI** instead of the network (“click a row to…”, “Tip:”, “N shown”);
2. **shows an internal identifier** where a name belongs (`fw_logs`, `device_bgp_peer_state`, `talks_to`);
3. **shows a stack trace** wearing a label (`500 Internal Server Error: {"error":"clickhouse: dial tcp …"}`);
4. **ships a placeholder** (“coming soon”, “Phase 2 stub”, `mock-nms`, “Fixture”);
5. **uses our vocabulary, not theirs** (“poller”, “ring buffer”, “backend”, “RE2”, store names);
6. **says nothing** where it could say why (“No data”, “n/a”, “—”).

### Deliberately preserved

- **Seam vocabulary** — “seam”, “seam-owned”, ISP/WAN ownership language. Untouched.
- **RCA honesty phrasing** — “possibly because of X”, the five honest coverage
  states, “Absence of telemetry is shown as absence — not as zero traffic.”
  Untouched: these are the product's argument, not filler.
- **Genuinely technical audiences.** Administration → API access, the GraphQL
  explorer, developer tokens, PromQL/expression fields, IAM action names in
  connector hints. An admin wiring `rds:DescribeDBInstances` needs the exact
  string. These were flagged LOW and left, with two exceptions where the word was
  ours rather than the vendor's (see §2.5).
- **PromQL metric names inside queries.** `count(device_bgp_peer_state == 6)` is
  code that happens to live in a string. Only the metric name *inside a sentence*
  was wrong, and only that was fixed.

---

## 2. Replacements applied

219 string replacements in total (the count is *occurrences*, so one
find-and-replace of a pattern that appeared 43 times counts 43). Grouped by
defect; “→” is the shipped replacement. The tables below are complete —
every distinct copy change is listed.

### 2.1 Instructional chrome (38 occurrences)

The affordance is the affordance; words describing it spend reading budget on nothing.

| File | Was | Now |
|---|---|---|
| `components/BottomDrawer.tsx`, `components/Inspector.tsx` | `Drag to resize` | `Resize` |
| `components/DataTable.tsx` | `Drag or use ←/→ to resize` | `Resize column` (the key hint stays in `aria-label`) |
| `components/board/panels.tsx` | `Click to enlarge` | `Enlarge` |
| `components/rca/RcaWorkspace.tsx` | `**Tip:** Click any marker to see why it was counted as evidence.` | `Each marker carries the reason it counted as evidence.` |
| `tabs/admin.tsx` (×9) | `Click to configure` / `Click to set up` | `Not configured` / `Not set up` |
| `tabs/admin.tsx` | `click to cycle` · `click a cell on a custom role to set its access` | `Change access level` · `each cell on a custom role sets its access` |
| `tabs/admin.tsx` | `Hidden from the global view — click to make visible` | `Hidden from the global view` |
| `tabs/Correlations.tsx` (×5) | `— click to clear the status filter` / `— click to show only these` | dropped; the chip is visibly interactive |
| `features/.../TopologyCanvas.tsx` | `…observed-since; click a row to focus it on the map).` | `Device inventory beside the map — status, management IP, first observed.` |
| `features/.../NetworkPathView.tsx` | `measurements — click a hop for the full metric list.` | `measurements.` |
| `features/.../EvidencePopover.tsx` | `+N more · click to open` | `+N more` |
| `features/topology/workflows/*.tsx` (×4) | `… Select a device to light up its neighbours.` | `The physical fabric, device by device.` (and the three siblings) |
| `pages/InterfacePerformance.tsx` | `Select a device to scope to the flows it exports.` | dropped |
| `pages/bgp/AsPathGraphPanel.tsx` | `Hover any AS for its …` | `Each AS carries its …` |
| `pages/appobs/shell.tsx` | `Click to remove this X filter` | `Remove this X filter` |
| `tabs/AdminSsoIdp.tsx` | `Use the arrows to reorder.` | dropped |
| `tabs/MetricsExplorer.tsx` | `+N more — refine the filter` | `+N more — narrow your search` |
| `tabs/Logs.tsx` | `Select all loaded` | `Select all rows in view` |
| `tabs/SnmpProfiles.tsx` | `Select a profile.` | `No profile selected.` |
| `features/.../TopologyCanvas.tsx` | `too large to expand on the canvas — use the overview or search.` | `too large to expand here.` |

### 2.2 Developer error text reaching the screen (≈70 occurrences, ~58 call sites)

**The largest defect in the audit.** `services/api.ts` throws
``new Error(`${status} ${statusText}: ${body}`)``, and ~60 render sites did
`setErr(e instanceof Error ? e.message : String(e))`. What an operator actually
read was:

```
500 Internal Server Error: {"error":"clickhouse: dial tcp 172.18.0.9:9000: connect: connection refused"}
```

That is unactionable, and it discloses internal hostnames, ports and component
names in the product UI.

**Fix: `src/lib/errors.ts` → `operatorError(e, fallback)`** (16 unit tests). It is
deliberately conservative — it *keeps* what is useful and drops only the shape:

- a message that already reads as a sentence is **passed through**, normalized
  (`"a capture is already running on this device"` → `"A capture is already running on this device."`).
  The backend's own operator wording is better than a substitute, and discarding
  it would be its own dishonesty;
- the HTTP envelope is unwrapped, and a JSON body carrying a plain sentence
  becomes the message;
- anything that is code talking to code — a Go wrap chain, `pq:`/`sql:` prefixes,
  a stack frame, an IP:port, a JSON or HTML body, a JS runtime error — is dropped
  for the caller's own sentence about the failed action.

Applied at ~58 sites across `tabs/{Alerts,Rules,Findings,ProcessorsAdmin,MaintenanceWindows,Correlations,AuditLog,StackHealth,SnmpProfiles,Collectors,SensitiveDataAccess}`,
`pages/{SavedDashboards,DeviceGeomap,PortsWorkbench,BgpOps,AppObservability,DataProtection,DeviceTerminal}`,
`pages/security/*` (6), `pages/telemetry/*`, `pages/troubleshoot/*`, `pages/device/VrfInterfaces.tsx`.

Also removed the bare lowercase failure strings that were their fallbacks:
`"failed to load audit log"`, `"failed to load stack health"`, `"failed to load profiles"`,
`"failed to add metric"`, `"failed to create profile"`, `"invalid OID JSON"`,
`"expected a JSON array of metrics (or {metrics:[…]})"`, `"export failed"`, `"lookup failed"`,
`· Error: {err}` (×2), `Expression error: {err}`.

**One important non-change.** In `pages/telemetry/TelemetryCoverage.tsx` the caught
message is a **control signal** — `isForbidden(err)` reads the 403 out of it to
show the “platform-admin only” card, because *a legitimate 403 is an answer, not a
failure* (§3a). Mapping at the catch site destroyed that. The raw message stays in
state there and `operatorError` runs at the single render boundary (`ErrLine`).
The lesson generalizes: **map at the render boundary whenever the error is also a
control signal.**

### 2.3 Internal identifiers shown as labels (16)

| File | Was | Now |
|---|---|---|
| `pages/DeviceNeighbors.tsx` | `No BGP peers in telemetry (device_bgp_peer_state) for this device.` | `No BGP peers have been seen for this device.` |
| `pages/DeviceNeighbors.tsx` | `…(device_ospf_nbr_state)…` | `No OSPF neighbours have been seen for this device.` |
| `tabs/Logs.tsx` | signal label `fw_logs` | `Firewall logs` |
| `tabs/ProcessorsAdmin.tsx` | `PCI · stamped on cx_sensitive` | `PCI` |
| `pages/appobs/AppDetail.tsx` | `talks_to / depends_on / backed_by edges from cloud_flow + traces (P3D/P3E)` | `Dependencies observed in cloud flows and traces.` |
| `pages/appobs/ServiceMap.tsx` | `…/api/cloud/service-map takes only window_hours` | `…drawn for the whole tenant over the selected time window.` |
| `pages/appobs/ServiceMap.tsx` | legend `talks_to · width = observed bytes` | `talks to · width = observed bytes` |
| `pages/appobs/ServiceMap.tsx` | `…and talks_to dependencies appear here…` | `…and dependencies appear here…` |
| `pages/AppObservability.tsx` | `Traffic dependencies (talks_to / egresses_via) and RCA edges…` | `Traffic dependencies and RCA edges…` |
| `pages/appobs/GovernanceSettings.tsx` | `add a tag key, e.g. cost_center` | `add a tag, e.g. cost centre` |
| `pages/NmsIntegrations.tsx` | credentials rendered as `Object.keys(creds).join(", ")` → `api_key, org` | the field **labels**: `Dashboard API key, Organization ID` |
| `pages/NmsIntegrations.tsx` | `used in poll paths (/organizations/{org}/…)` | `Identifies your organisation with the vendor.` |
| `tabs/admin.tsx` | contact-point options rendered as `email` / `slack` / `webhook` | `Email` / `Slack` / `Webhook` |
| `pages/SecurityOverview.tsx` | `Verdict suspected · engine e-2026.09` | `Verdict suspected` |

### 2.4 Placeholder and stub text (13)

| File | Was | Now |
|---|---|---|
| `components/IconRail.tsx` | `The support portal is coming soon.` | `The support portal is not open yet.` |
| `pages/AppObservability.tsx` | `Coming soon: network impact (service→connection correlation)` | `Network impact is not connected on this deployment` |
| `pages/appobs/readiness.ts` | `Coming soon` | `Not collected here` |
| `tabs/admin.tsx` | `Tenant-specific roles are coming soon.` | `…are not available yet.` |
| `tabs/Opsis.tsx` | slash-command badge `soon` | `not yet` |
| `features/.../TopologySideDrawer.tsx` | `(Phase 2 stub — resolution backend lands later)` | `— not available yet` |
| `features/.../TopologyCanvas.tsx` | `…a bundled sample fabric is shown so the renderer can be evaluated.` | `…a sample fabric is shown instead.` |
| `features/.../TopologyCanvas.tsx` | `This workflow mode is not backed by live data yet — a bundled sample is shown.` | `No live data for this view yet — a sample is shown.` |
| `features/.../GeoTopologyMap.tsx` | `No SoT-placed sites found` | `No sites have coordinates yet` |
| `pages/NmsIntegrations.tsx` | `(or http://mock-nms:8091 for the bundled stand-in)` | dropped |
| `pages/telemetry/TelemetryCoverage.tsx` | `title="Fixture"` | `title="Sample event"` |
| `pages/telemetry/fixtures.ts` | `mining not yet run` | `analysis has not run yet` |
| `lib/fidelity.ts` | tier label `code`, “Written in code, no capture behind it yet” | `unverified`, “Defined in the product, not yet confirmed against a device” |

### 2.5 Our vocabulary, not the operator's (≈67 occurrences)

**Store and engine names.** An operator does not run our database.
`ClickHouse` / `VictoriaMetrics` / `OpenSearch` in `pages/DataSources.tsx` → the
data itself (“flows”, “SNMP metrics”, “syslog”, “traps”); `sub: "OpenSearch"` in
`components/CommandPalette.tsx` and `components/TopBar.tsx` → `Log search`;
`nav.tsx` platform tab `OpenSearch` → `Search Dashboards`;
`Search (Lucene)` → `Search`; `Execution history requires the Postgres backend.`
→ `Run history is not available on this deployment.`;
`RE2 syntax · validated on save` → `Pattern is checked when you save`;
`Regex (RE2)` → `Pattern`; `Custom regex` → `Custom pattern`.

*Kept:* `tabs/SearchDashboards.tsx` (“OpenSearch Dashboards” is the embedded
tool's real product name) and `pages/DataProtection.tsx` (restoring an OpenSearch
snapshot is the actionable fact on an administrator's backup page). Both are
recorded as documented exemptions in the guard.

**Collection language.** We collect telemetry; we do not “poll”.
`Polling… / Poll now` → `Collecting… / Collect now`; `Pause/Resume polling` →
`Pause/Resume collection`; `the poller needs eks:ListClusters…` → `the collector
needs …` (×3, IAM actions kept — they are the actionable part);
`the poller uses it instead of the global default` → `the collector uses it`;
`polling every 10 seconds` → `Refreshed every 10 seconds`;
`SNMP/gNMI collectors are not polling this fleet` → `…are not collecting from
this fleet`; `BGP/OSPF/IS-IS polling is not enabled` → `…collection is not
enabled`; `the seam lanes are built and polling` → `built and collecting`
(*seam* preserved); `polling stopped. Reload the list` → `Refresh the list`.

**Implementation words.** `Server-side ring buffer: constant size, oldest
overwritten.` → `Keeps the most recent updates; older ones roll off.`;
`PAUSED · poller cap / POLLING / IDLE` → `Paused — at capacity / Receiving /
Idle`; `Loading basemap…` → `Loading map…`; `Loading trust setup from the
connector API…` → `Loading trust setup…`; `Permissions are defined by the
capability pack from the API.` → `…set by the provider's capability pack.`;
`The server returned no adjacency/summary/health payload.` → `No adjacency/
summary/health data came back.`; `Cloud attachment type (from backend
connectivity data)` → `Cloud attachment type`; `Flow/Events backend unavailable`
→ `Flow/Event data unavailable`; `The inventory backend did not answer.` →
`Inventory did not answer.`; `Debug / lab — excluded` → `Lab / test source —
excluded`; `Debug View` → `Evidence detail`; `Reasoning:` → `Why:`;
`generic controller — REST / webhook` → `— HTTP integration`;
`WEBHOOK` → `PUSH`; `webhook only` → `push only`;
`Dry run … the pipeline is not touched` → `Test run … live processing is
untouched`; `cursor pagination appends rows, never re-orders them` → `more rows
are added as you scroll; the order never changes`; `This page is truncated at N
events` → `Showing the first N events`; `Matches the device label (regex).
Empty = the whole fleet.` → `Optional. Leave blank to cover the whole fleet.`;
`WAN device name pattern (regex)` → `Filter WAN devices by name`;
`<option>enum</option>` → `Named states`; `Signal kinds with no causal-layer
mapping` → `Evidence types not yet mapped to a causal layer`;
`This span could not be classified` → `This segment…`;
`Raw signal stream` → `Live event stream`; `Signal stream` → `Event stream`;
`Syslog (raw signal)` → `Syslog message`; `grouped, not raw alerts` → `grouped,
not individual alerts`; `Raw signals (if any) have not formed a correlated
group.` → `Individual alerts have not yet grouped into an incident.`;
`Correlation engine unreachable.` → `Correlation is not answering right now.`;
`Cloud connectors need the platform database backend — this deployment runs the
in-memory store.` → `Cloud connectors are not available on this deployment.`;
`Service assignment needs the platform database backend…` → `…is not enabled on
this deployment.`; `Set FEATURE_COPILOT=true in deployment/docker/.env and
restart the API.` → `An administrator can enable it in the platform
configuration.`; `Set via environment; clear it from .env` → `Set by your
deployment configuration; clear it there`; `never shown again, never returned by
the API` → `and is never displayed again`; `the profile stores them write-only`
→ `stores them but can never display them again`;
`username (blank = yourself)` → `Username — leave blank for yourself`;
`internal/debug-only monitoring` → `internal-only monitoring`.

### 2.6 Empty and unknown states (15)

`No data` → `Nothing arriving` (`DataSources`), `Nothing collected yet`
(`Devices`, `panels`), `Nothing collected in this window.` (`board/panels`,
`FrontPage`), `Nothing collected` (the RCA evidence pill in `rcaCase.ts`);
`No data received` → `Nothing has arrived yet`;
`n/a` → `Not rated` (`VulnerabilityManagement`) / `Not assessed`
(`security/parts`); `NO certificate` → `No certificate presented`;
`Validator fatal` / `Validator warn` → `Critical problems` / `Warnings`;
`No logs in range.` → `No log entries in this window.`;
`Nothing to display for this view` → `Nothing to show for this view yet`;
`admin/oper/security/auth mode … "unknown"` → `not reported` (`Wireless`, ×3);
a `—` trend tooltip → `not measured` (`ReliabilityScorecard`, matching the same
page's other formatter);
`Unknown fidelity tier` → `Fidelity not recorded`;
`Select at least one resource` → `Select at least one resource.`

*Kept:* “No data arriving” (`appobs/Ingestion`) — that is about the **feed**, and
it is the honest, specific statement.

---

## 3. The guard

**`src/copyVoice.test.ts`** — 23 tests. It scans every shipped `.ts`/`.tsx`
(excluding tests, `mock/`, `test/`, `rcaPreview.tsx`) for 15 denylist rules built
from the phrases removed above, and fails naming `file:line — rule: span · what
to write instead`.

Design points that decide whether a guard like this survives:

- **It reads copy, not code.** Comments are blanked first (positions preserved,
  so line numbers stay true) and only string literals and JSX text nodes are
  matched — via `src/lib/copyScan.ts`, now shared with the pre-existing
  `components/rca/vocabulary.test.ts` (the “Signals” guard), so both mean the
  same thing by “what a person can read.”
- **`proseOnly` rules.** `device_bgp_peer_state` inside `count(… == 6)` is a
  query; inside “No BGP peers in telemetry (…) for this device” it is a defect.
  The `wire-name-in-prose` rule fires only when the span reads as a sentence
  (≥3 ordinary words, no expression punctuation or function call). Without this
  the guard would fail on ~20 legitimate PromQL strings and be switched off.
- **Teeth.** 20 cases assert every rule still fires on the exact copy it removed,
  so a typo in a regex cannot turn the guard into a silent no-op — plus 12
  anti-false-positive cases (identifiers, field access, comments, PromQL, API
  parameter keys, “No data arriving”).
- **Exemptions carry reasons.** Each `allow` entry names why the phrase is
  legitimate there. An unexplained exemption list is how a guard rots.

**Bug found and fixed while building it:** `stripComments` did not reset string
mode at a newline, so a single apostrophe in JSX text (`isn't`) put the scanner
into string mode for the rest of the file — after which `//` was no longer
recognized and every later comment was scanned as copy. A `'`/`"` string cannot
span a newline in JavaScript, so resetting there is exact. This also strengthens
the existing “Signals” guard, which had the same blind spot.

---

## 4. Tests updated intentionally

18 test files pinned copy this pass changed. Each was updated to the new wording
(never loosened to make it pass), and the three that pinned a *shape* rather than
a string were rewritten to assert the new contract:

| Test | Was pinned | Now |
|---|---|---|
| `pages/telemetry/TelemetryCoverage.test.tsx` | `503 Service Unavailable: miner down` | `Miner down.` — the envelope is stripped at the render boundary |
| `pages/telemetry/TelemetryCoverage.test.tsx` | `alerts:write required`, `parser stats unavailable` | sentence-cased equivalents |
| `pages/troubleshoot/InvestigationLanes.test.tsx` | “renders its failure **verbatim**, prefixed by the lane” | “renders its failure **as operator copy**, prefixed by the lane” — the lane prefix is kept because it says *which* lane failed |
| `components/rca/RcaWorkspace.test.tsx` | `Debug View`, fidelity `code` | `Evidence detail`, `unverified` |
| `components/rca/{rcaCase,rcaExport}.test.ts` | pill `No data` | `Nothing collected` |
| `pages/CommandCenter.test.tsx` | resize title `/←\/→/` | `/Resize column/` |
| `pages/security/SecurityOverview.test.tsx` | snapshot | regenerated (2 intended lines) |
| `pages/{CloudLogs}.test.tsx`, `tabs/TransportSecurity.test.tsx`, `pages/bgp/panels.test.tsx`, `pages/appobs/{shell,Connections,assign,attribution,connectorWizard,ProviderIncidents}.test.*` | the old strings | the new ones |

---

## 5. Audited and deliberately left

The sweep found ~235 distinct candidates; the ones below were judged legitimate and left. The remainder were judged
legitimate, and are recorded here so the next pass does not re-litigate them:

| Kept | Why |
|---|---|
| PromQL / expression fields (`avg by (device) (device_cpu_percent) > 90`, `rate(device_if_in_octets[5m]) * 8`) | Expert input fields. The example IS the documentation. |
| IAM action names (`rds:DescribeDBInstances`, `container.clusters.list`) | The actionable part of the hint — an admin pastes them into a policy. |
| Administration → API access, GraphQL explorer, developer tokens, OAuth `client_credentials` | Explicitly technical audience (kept as LOW-confidence findings). |
| `pages/DataProtection.tsx` OpenSearch snapshots | You restore an OpenSearch snapshot, not “a search”. |
| `tabs/SearchDashboards.tsx` iframe title | The embedded tool's real product name. |
| `features/.../UnresolvedNode.tsx` raw id as label | That IS the unresolved node — the id is the only thing known about it. |
| `TopologySideDrawer` “Discovered as \<rawId\>” | Labelled, monospaced, and the raw value is the point. |
| Loading-string inconsistency (9 phrasings) | Real, but cosmetic and cross-cutting; a separate pass, noted below. |

**Known follow-ups (not done here):**

1. **Loading strings** — at least 9 phrasings (`Loading…`, `Loading ticket
   status…`, `Loading the cloud network…`, `Loading enterprise overview…`,
   `Loading parser coverage…`, …). Each is individually fine; together they read
   inconsistent. Worth one convention, and it touches ~20 files.
2. **`—` as a value** appears in ~40 cells with no shared meaning. “Not
   reported” / “Not measured” / “Not assessed” were applied where the reason was
   knowable; a general convention for the rest is a design decision, not a
   find-and-replace.
3. **`ProtocolDiagnosticsPanel`** still falls back to `device_id` where a display
   name is unavailable (`hostname || device_id`). The fix is a display-name
   resolver, not a copy edit.
