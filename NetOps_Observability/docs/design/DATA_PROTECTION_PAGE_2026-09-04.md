# Data Protection console — design of record (2026-09-04)

The Correlix backup and recovery surface, rebuilt from a settings card into an
operations console. This document records what the page is, what it took from
each product studied, the contract it renders, and the contract gaps the backend
still has to close.

Implementation: `src/frontend/src/pages/DataProtection.tsx`,
`src/frontend/src/pages/dataProtection.model.ts`, the `.dp-*` block in
`src/frontend/src/styles.css`.

---

## 1. What changed

The old page answered "is a backup running": a remote destination form, a
schedule checkbox, and a status card carrying the age of the newest snapshot.
It refused to expose restore at all, on the grounds that restore is destructive
and belongs in a runbook.

That leaves the operator with the easy half. The question a backup surface has
to answer is "can I get the data back, from what point in time, for which
engine, and has anyone ever proved it". The console answers that, and it exposes
restore behind the same guard rails the enterprise products use: a wizard whose
default target is a renamed copy beside the live data, with the in-place
overwrite as a separate, labelled, type-to-confirm step.

| | Before | Now |
|---|---|---|
| Verdict | Three coloured pills (repository, remote, schedule) | One posture — Protected / At risk / Unprotected — with the reason, plus recovery-point objective per engine, time since the last **proven** restorable copy, next run, repository headroom |
| Coverage | Search tier and "full backup" only | One row per engine (search, system bundle, flows, application state, metrics, secrets and TLS material, device configurations) with schedule, last attempt, last success, last verified restore, size, retention, destination class, immutable and encrypted badges |
| Recovery points | Not shown | Table of every restorable copy: state, start, duration, index count, size, verification badge, verbatim failure text |
| Restore | Not available ("runbook-only") | Wizard: scope → destination (renamed by default) → in-place confirmation step → review; async progress; audit line on completion |
| Verify | A drill result if a report file happened to be mounted | "Verify now" per copy and "Run restore drill" on the newest, both recorded in the trail |
| Delete / take | Not available | Take one now; delete with a type-the-name confirmation |
| Policy | Cron and retention fields | Same fields, with the consequence of disabling written beside the switch; turning it off asks for a reason first and the off state then names who, when and why; externally-owned jobs named as external |
| Activity | None | Audit trail of every backup, restore, verify and policy change, with the drill history split out |
| Location | A card inside Administration → Settings | Administration → Platform → Data Protection (`#/admin/data-protection`), platform-only |

---

## 2. What each product contributed

Information architecture only. None of the branding, none of the vocabulary
that belongs to those vendors, and nothing that implies a capability Correlix
does not have.

### Veeam Backup & Replication
- **The job/session split.** Veeam separates "what is configured to run" from
  "what actually ran". The console does the same: the coverage matrix is
  configuration plus its last outcome; the recovery-point table is sessions.
- **SLA / RPO compliance as a first-class header number.** Adopted as
  *recovery-point objective achieved against target, per engine*, in the header
  rather than buried in a report. Veeam's version is a percentage over a window;
  ours is the plainer "achieved 1h 00m against a 1d 00h objective", because a
  single-instance platform has few enough engines to show them all.
- **Rejected:** Veeam's job-centric navigation. Correlix has one protection
  policy per engine, not a job catalogue, so a job list would be a table of one.

### Rubrik / Cohesity
- **Policy-centric, not job-centric.** The Policies section is the thing you
  change; the coverage matrix is what those policies produce. This is why
  disabling the recovery-point policy renders its consequence ("no new restore
  points will be created") next to the switch rather than as a toast.
- **"Last snapshot / next snapshot" as a paired fact.** Adopted verbatim in the
  header (last proven restorable copy · next scheduled run) and per engine.
- **Immutability badges.** Adopted as the `immutable` / `encrypted` pair beside
  the destination class, because "the copy exists" and "the copy cannot be
  altered by whoever got into the host" are different claims.
- **SLA domains.** Adopted only in spirit: the destination classes
  (local / remote / offsite) each carry what they actually protect against
  rather than a tier name that means nothing outside the vendor.
- **Rejected:** the recovery-points *timeline* ribbon. With a daily policy the
  ribbon is a row of evenly spaced identical ticks — a chart carrying one bit of
  information. The sortable table with an explicit duration column says more per
  pixel. It is worth revisiting if sub-hourly or continuous protection ships.

### Elastic Cloud snapshot management
- **Repository health as its own object, with distinct failure states.**
  Adopted directly: unregistered, unreachable and damaged are three different
  first actions, so they are three different remedies, not one "repository
  problem".
- **The snapshot list columns** — state, start/end, duration, indices, size —
  adopted almost as-is; failures are shown with the reason text verbatim
  rather than as a count.
- **The restore wizard's rename step.** Adopted, in the shape the platform's own
  restore takes: a name PREFIX (`restored-` by default) rather than Elastic's
  regex pair, because the server's `rename_prefix` is what the operation
  actually accepts and offering a pattern the backend would ignore is its own
  small lie. Extended: the wizard previews the resulting names, and refuses to
  advance on an empty or illegal prefix, because that would put the restored
  data back on the live names — an overwrite wearing a rename's clothes.
- **The retention policy editor** (count and max age) — kept from the existing
  page, which already mirrored the engine's own vocabulary.

### NetBackup / Commvault
- **The audit trail of restores.** Adopted as the Activity section: who ran
  what, against what, and what it returned — including denials.
- **Drill history as a separate list.** Adopted, because "we take backups" and
  "we have restored one" are different assurances and an operator should not
  have to filter a combined log to tell them apart.
- **Type-to-confirm on destructive actions.** Adopted for both the in-place
  restore (type `RESTORE IN PLACE`) and the delete (type the copy's own name).

---

## 3. Rules the page enforces

**Honest empty states.** Every value that can be absent arrives as `null` with a
`*_reason`, goes through `measured()` in the model, and renders as
`not measured — <reason>`. There is no code path that turns an absent number
into a `0`, a dash or a green tick. `measured()` deliberately treats a real `0`
as measured: zero bytes free is a fact and an emergency, "not measured" is
neither. This is pinned by `dataProtection.model.test.ts` and by assertions in
`DataProtection.test.tsx` that the fabricated value is *absent* from the DOM
(`queryByText("0% free")`, `queryByText("0 B")`).

**Measured means measured** (added 2026-09-06, tracker 204). The
"Bytes on disk (measured)" section renders `GET /api/system/storage/measured`,
and every number in it was read back from the store that OWNS the bytes by the
query named beside it — OpenSearch `_cat/indices` store.size per index (per
tenant, because the index name carries the tenant segment; the shared `untagged`
lane is its own row and is deliberately not folded into anybody's total),
ClickHouse `system.parts.bytes_on_disk` per table and partition (per tenant,
because every netops table is partitioned by `tenant_id` first) with
`data_uncompressed_bytes` beside it so the compression ratio shown is MEASURED
rather than the constant the sizing model assumes, VictoriaMetrics' own
`vm_data_size_bytes`, `pg_database_size()`, and a walk of the api's data
directory. Nothing on this section is a rate multiplied by an assumed
bytes-per-row; the derived model lives in `scripts/resource_planner.py` and is
labelled an estimate there.

The section obeys the same three-state rule as the rest of the page, and adds
two of its own. `total_measured_bytes` is labelled a **lower bound** whenever any
store is unmeasured, because summing what you could measure and calling it the
footprint is the same lie in a smaller font. And a store that cannot be measured
per TENANT (VictoriaMetrics, the app database, the api file store, Kafka — none
is partitioned by tenant on disk) returns a scoped caller a `null` with that
reason rather than a pro-rata share: a division is not a measurement. Kafka is
the standing example of a store that cannot be measured at all — the api ships
no Kafka client, kafka-exporter publishes lag rather than log-dir bytes, and the
api container does not mount the broker volume.

**Absence is styled as absence.** `.dp-unmeasured` is muted and italic, never
red. "Nobody measured this" is a different fact from "this is broken", and
colouring them alike trains an operator to ignore both.

**Vocabulary is the operator's.** Rows are named for the data they hold
(Metrics history, Flows & correlation history, Application state), not for the
product that stores it. The storage-engine names are denied by
`src/copyVoice.test.ts`; the page holds the one standing exemption for the
snapshot engine, because you restore a snapshot, not "a search".

**A stopped policy is never mistaken for an accident.** Turning the
recovery-point policy off asks for a reason before it writes, and sends it as
the `reason` the server records with the intent. A policy found off later then
reads "Turned off by root on 2026-09-03T09:12:00Z: the repository volume is
being replaced" — and one with no recorded reason says exactly that, because "we
do not know why this is off" is the fact that matters.

**Every panel fails on its own.** Five independent reads, five independent
failures, each rendered as an operator sentence through `lib/errors.ts`. A dead
activity feed never blanks the restore points, and a dead restore-point list
leaves the posture readable.

**Platform-admin gating in the UI, enforced on the server.** The role is read
from the session exactly as the other platform pages read it
(`useAuth().user.platform_admin`). A tenant admin sees the posture read-only and
is told why the controls are absent, instead of being shown buttons that 403.

**Accessibility.** Five `role="region"` landmarks with stable `data-section`
ids; the wizard and both confirmations are `role="dialog"` with Escape and Tab
containment (the shared `Modal`); every typed control carries a label; the
recovery-point table is the shared keyboard-navigable `DataTable`. The header's
stat grid and the section frames reserve their boxes, so a slow panel does not
push a button out from under the cursor.

**Performance.** The recovery-point table is the windowed `DataTable`; the audit
trail and drill history use the row-cap + "Show all" convention. Budget
`data-protection` in `perf/budgets.json` measures the page with **500 recovery
points, 7 engines and a 200-operation trail**: 1,083 DOM nodes against a 1,300
ceiling, so a de-virtualized regression fails immediately. Tests also render the
page at 0, 1 and 500 restore points.

---

## 4. Contract

The page is built against `src/backend/system_backup_contract.go` and the
"Data Protection" tag in `src/backend/internal/openapi/openapi.go`. Every call
site in `src/frontend/src/services/api.ts` carries a
`// contract: openapi.go <route>` marker, so a rename on the server is a
one-line change here.

| Route | What the page does with it |
|---|---|
| `GET /api/system/backup/coverage` | `BackupCoverageView` — the coverage matrix, and (with the repository below) everything the header verdict is derived from |
| `GET /api/system/backup/snapshots/list` | `SnapshotListView` — the repository object plus the restore points. `?sizes=1` is opt-in behind a "Measure sizes" control, because it costs one repository call per restore point |
| `POST /api/system/backup/snapshots/create` | Take one now → 202 `Operation` |
| `POST /api/system/backup/snapshots/delete` | `{snapshot, confirm}`, confirm = the restore point's own name |
| `POST /api/system/backup/snapshots/restore` | `{snapshot, indices?, mode, rename_prefix?, confirm?}`; `mode: "renamed"` is the wizard's default, `in_place` requires the typed name |
| `POST /api/system/backup/snapshots/verify` | The drill. Per row it names the snapshot; the section's "Run restore drill" omits it, which probes the newest good copy |
| `GET /api/system/backup/operations` | `OperationListView` — the audit trail, and the drill history is its `snapshot_verify` slice |
| `GET /api/system/backup/operations/{id}` | The poll target for every 202 above |

Unchanged and still used: `GET|PUT /api/system/backup` (the bundle destination
and schedule) and `GET|PUT /api/system/backup/snapshots` (the recovery-point
policy).

### Derived in the frontend, not asked of the server

Three things the page shows are computed in `dataProtection.model.ts` rather
than added to the API, because the arithmetic is presentation and hiding it
behind a server field would make it unauditable:

- **The headline posture** (`posture()`). The worst true statement wins, and the
  reason names the specific condition: a broken repository, then the first
  uncovered engine, then the first unmeasurable one, then an engine that has
  never succeeded, then "recent copies, no proved restore". Only a covered,
  recently-successful, proved platform reads Protected. An unreadable coverage
  table is `unknown`, never Protected — the absence of bad news is not good news.
- **The repository's state** (`repositoryState()`), from the two facts the
  server carries separately (`registered`, `verified`) plus whether the list read
  at all: `ok`, `unregistered`, `damaged`, `unverified`, `unreachable`. Each has
  its own remedy, because each has a different first action.
- **The last proven restorable copy** (`lastProvenRestore()`), the newest
  `last_verified.result === "pass"` across engines. A failed drill is not a proof
  and does not count.

### What the backend must still provide

1. **`rpo_target_hours` per engine.** The contract publishes the ACHIEVED
   recovery point (`rpo_hours`) but no objective. The header therefore renders
   "last good copy 10h 30m old · objective not set" instead of assuming a
   default and reporting it as met. The field is already read by the frontend
   type (`EngineCoverage.rpo_target_hours`), so wiring it is one server field.
2. **Repository disk headroom.** `SnapshotRepositoryView` carries no capacity,
   so the header stat renders "not measured — the platform does not report the
   repository volume's capacity". Two nullable fields plus a detail
   (`disk_free_bytes`, `disk_total_bytes`, `disk_detail`) would close it.
3. **A per-engine reason for an absent `schedule`, `last_attempt` or
   `retention`.** Those are nil pointers with no sibling detail today, so the
   page falls back to the engine's `detail` and then to a generic sentence. A
   `*_detail` per field would let the row say exactly why, like the others do.
4. **Keep `covered_reason` populated for every verdict, including `yes`.** The
   matrix prints it under the badge; a blank one there is the only way this page
   can show a verdict an operator cannot check.
5. **Server-side re-validation of both confirmations.** The typed strings are a
   UI guard against an accidental click. The server must refuse an in-place
   restore or a delete whose `confirm` does not equal the snapshot name — which
   the contract already states, and which the isolation/route tests should pin.
6. **Keep `managed_by` honest.** The page warns when something other than the
   GUI owns the enabled flag, because a switch that can be silently overwritten
   is worse than no switch. If ownership ever moves, this field is how the page
   finds out.
7. **An operations ring large enough to outlive one incident.** The page prints
   `capacity` verbatim ("the platform keeps the newest N operations") so the
   operator knows what they cannot see; if N is small, the drill history is
   effectively unreadable after a busy day.

## 5. Tests

- `src/frontend/src/pages/dataProtection.model.test.ts` — 45 tests over the pure
  rules: `measured` (including that a real `0` and a real `false` stay measured),
  formatting, the engine vocabulary, the four coverage verdicts, the five
  repository states and their remedies, every branch of the posture derivation,
  the last-proven-restore scan, the recovery-point verdict, the three-way
  restorability verdict, the restore prefix rules, type-to-confirm, the
  operations vocabulary and the drill's document-count evidence.
- `src/frontend/src/pages/DataProtection.test.tsx` — 92 tests over the rendered
  console: every header state and every unmeasured header value, the matrix
  including not-applicable, unknown, never-succeeded and external rows, restore
  points at 0/1/500, the opt-in size measurement, take/verify/delete and both
  restore paths with their confirmations, async progress and settled operations,
  admin gating, the policy consequence copy, activity and drills including a
  drill whose counts did not match, every honest state with its remedy and
  documentation link, the landmarks and labels, and copy-denylist and vocabulary
  guards aimed at this page's own sources.
- `perf/render.perf.tsx` — the `data-protection` budget scenario.
