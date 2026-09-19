<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Installer failure modes and self-healing — FMEA (2026-09-15)

**Status:** RESEARCH / PROPOSED (owner review). No code was changed to produce this document.
**Owner ask (2026-09-15):** "dig into this installation more granularly and think of all the possible
issues that might occur and build all kinds of self healing techniques."
**Scope:** every stage of a fresh install and a re-run, from `correlix-setup` (GUI) and
`install-correlix.sh` down through `install.py`, compose, qualification and uninstall.
**Out of scope:** product runtime after a qualified install (covered by `docs/runbooks/engine-liveness-matrix.md`).

## 0. How to read this

**Code of record is HEAD `74f7be09`.** Every `file:line` citation refers to that commit. While this
was being written, another engineer's fix for item 1 was landing **uncommitted** in the same tree
(`deployment/docker/docker-compose.yml` +38, `scripts/install.py` +324, new `tests/test_install_converge.py`).
It is described as **IN FLIGHT** below and was **not reviewed** here. Line numbers in the live tree
already differ from HEAD.

Abbreviations: `IPY` = `scripts/install.py` · `ICS` = `scripts/install-correlix.sh` · `PH` =
`scripts/prepare-host.sh` · `M` = `scripts/installer-gui/main.go` · `U` = `scripts/installer-gui/ui.html`
· `DC` = `deployment/docker/docker-compose.yml` · `TLS` = `deployment/docker/compose.tls.yml` · `CI` =
`.github/workflows/fresh-install-integrity.yml` (repo root).

**Scales (for a 4-core / 16 GB VM like 10.70.245.123):**

| | Likelihood (L) | Impact (I) |
|---|---|---|
| 5 | observed in the last 10 days, or happens on every install | install fails, or secrets/data lost; expert recovery needed |
| 4 | expected within a handful of installs on a slow-disk VM | install fails but a re-run or runbook recovers it, **or** "success" over a broken product |
| 3 | plausible per upgrade, re-run or operator choice | degraded product, security hygiene breach, or a long delay |
| 2 | needs an unlucky coincidence | diagnosability / operator confusion |
| 1 | rare | negligible |

**Risk = L × I.** "Self-heals today" is judged against HEAD, never against the in-flight change.
**UNVERIFIED** marks anything this research could not prove from code, logs or a read-only probe.

**Repo rules every proposal respects:** never swallow an error (scripts/CLAUDE.md §16.1). Every wait
is bounded, with backoff and jitter (§9, §16.3). Every step is idempotent. No secret reaches a log
(§8, §16.5). Nothing destructive happens without naming its target first (§16.3). A self-healing
action that cannot heal must **fail loudly and name the remedy**. It must never "continue and hope".

---

## 1. Evidence base

### 1.1 The live failure on 10.70.245.123 (read-only survey, 2026-09-15 03:40–03:45 UTC)

Bundle `2026.09.15-ge8ebc980` was installed through the GUI with the TLS default and the add-ons log-search-ui,
self-monitoring and sso. Run log: `~/rc1-bundle/correlix-install-20260915-025100.log`.
Timing file: `data/install-timing.json`.

| Stage | Seconds | Note |
|---|---:|---|
| preflight + verify + extract | (not timed) | all PASS, 80 GB free |
| bundle (core images) | 382.0 | 1.1 GB zst |
| tls-env / data-dirs | 9.4 / 10.8 | chown through the helper container (non-root) |
| addon-pack ×3 | 122.0 + 119.4 + 92.9 | image loads are **716 s = 55 % of the run** |
| bootstrap-appstate | 30.8 | first-boot socket window survived (the new readiness rule worked) |
| up-a (phase A) | 213.3 | 25 containers created and started at once |
| mint | 90.9 | |
| up-b (phase B) | 235.1 **FAIL** | `dependency failed to start: container netops-postgres-1 is unhealthy` ×3 |
| **total** | **1306.8** | failed 03:13:02Z |

The postgres log (phase-B container, started 03:11:00) shows the mechanism end to end:

- 03:11:07 `database system was interrupted; last known up at 03:03:57`. The phase-A container
  had been stopped uncleanly. It ran with Docker's 10 s default (`StopTimeout=<nil>`; `DC:74-106` has no
  `stop_grace_period`).
- 03:11:17 → 03:12:47 `syncing data directory (fsync), elapsed time: 10…100 s`. The data dir is
  **66 MB / 1 754 files**, so each file cost about 60 ms to fsync. That is a sick disk, not a big database.
- 03:12:54 `automatic recovery in progress` → redo took 0.08 s → 03:12:58 end-of-recovery checkpoint.
  Clients were still refused at 03:13:28. Ready at about +145 s.
- The healthcheck `pg_isready`, interval 10 s, retries 5, **no start_period** (`DC:99-103`), went
  unhealthy at about 50 s. Every later `compose up` pass failed in seconds against the sticky
  `unhealthy` status. `compose_up` gives up after 3 passes and two fixed 30 s sleeps (`IPY:2449-2461`).
  **The installer quit about 25 s before postgres would have answered.**

Collateral state still visible 30 min later:

- `netops-keycloak-1`: `RestartCount=106`, "Up 17 seconds". Its log says `FATAL: database "keycloak" does not exist`.
  Keycloak started in phase A (`DC:171-206`, depends only on postgres healthy). `bootstrap_keycloak_db`
  runs only after phase B (`IPY:3628-3630`). The failed run never got there. A JVM restarting about every 22 s on
  4 cores adds CPU and IO load during exactly the window that is already starved.
- `netops-api-1`, `netops-correlation-1`, `netops-nginx-1`: state `created`, never started.
- Host pressure with the partial stack up: **IO PSI some avg300 = 36.5 %, full avg300 = 22.5 %**,
  vmstat `wa` 15–35 %, CPU PSI some 12 %, memory PSI ≈ 0. Disk `vda` virtio, 100 GB, 26 % used.
- Docker 29.1.3 with the **containerd snapshotter** (`driver-type io.containerd.snapshotter.v1`), Compose 2.40.3,
  daemon.json `live-restore` + 20m×3 log caps, `vm.max_map_count=262144`, NTP synced, cgroup v2.
- `gui.log`: `03:28:03 correlix-setup: shutting down (install result never acknowledged)`. The wizard
  **stopped itself 15 min after the failure** (`M:94`, `M:876`). The owner's browser was left with nothing to reconnect to.
- The install log's line order is scrambled. `Loaded image: …` lines appear **before** the
  `=== loading image bundle ===` header they belong to, because install.py's stdout is block-buffered through
  `tee` (`ICS:827` runs `python3` without `-u`; only CI sets `PYTHONUNBUFFERED`, `CI:136-139`).
- Docker auto-created bind-mount sources as `root:root`: `data/cloud-logs`, `data/syslog-ng`,
  `data/vector-aggregator`. None of them is in `ensure_data_dirs`' owner map (`IPY:1844-1901`).
- The compose project is `netops` with `working_dir=/home/rao/rc1-bundle/NetOps_Observability/deployment/docker`
  (pinned by `name: netops`, `DC:27`).

### 1.2 Prior incidents this FMEA generalises

| Date | Incident | Class | Source |
|---|---|---|---|
| 2026-09-06/07 | 12 installer defects on .123; helper image by digest offline; vmauth missing from archive; Docker claimed `data/tls/services` as root; `uninstall --purge` could not delete; orphan volumes | "a step needs something Docker has not put on the host yet, offline" | `docs/audit/FRESH_INSTALL_ACCEPTANCE_2026-09-06.md` §4 |
| 2026-09-14 | `pg_isready` answers the entrypoint's temporary server; three first-boot PG states; regex missed psql ≥14 wording | readiness judged by the wrong signal | memory `rc1-run-2026-09-13`; `IPY:2838-3037` |
| 2026-09-14 | Restarting `correlix-setup` killed the in-flight install; the browser showed a frozen bar | child-process lifecycle | memory `rc1-run-2026-09-13` |
| 2026-09-14 | `prepare-host.sh --firewall` locked the operator out of :8800 and never opened 443 | self-inflicted lock-out | TRACKER 320; `PH:227-240` |
| 2026-09-15 | Leading `-` in a minted secret crash-looped OpenSearch Dashboards on ~1 in 64 installs | per-install randomness | `IPY:316-332`, `IPY:850-868` |
| 2026-09-05 | OpenSearch flood-stage block + recreate → 60 s crash loop | disk watermark × recreate | memory `opensearch-flood-stage-crash-loop` |
| 2026-09-02 | Stale single-file bind mount of `apply-acls.sh`; ungranted topic made the consumer auth-dead for 3 h, all green | stale mount / "healthy proves nothing" | memory `deploy-acl-and-stale-mount-lesson` |
| 2026-09-06 | Deleting dangling images removed image objects under running containers | destructive cleanup on a live host | same memory note |
| 2026-08-27 | Shrinking Kafka retention in a disk crisis lost 6.3 M events | wrong disk lever | memory `soak-retention-cap-lesson` |

### 1.3 Why CI does not catch these

The only real boot test (`CI:100-196`) runs `sudo -E python3 scripts/install.py --tls=yes`:

- **as root**
- **online** (builds images, no bundle load)
- **unbuffered**
- on a **fast-SSD** GitHub runner
- **once**: never re-run, never interrupted
- **never through the GUI or `install-correlix.sh`**

Its crash-loop assertion samples `State` once (`CI:171-179`), and a JVM that restarts every 20 s reads
`running`. Every row marked L≥4 below lives in a path CI never takes. The acceptance report said the
same about the 2026-09-06 defects (§4 of that report).

---

## 2. Top 15 by risk (L × I)

| # | Failure mode | L | I | Risk | Self-heals at HEAD? | Proposed self-healing (one line) | Lands in |
|---|---|---|---|---|---|---|---|
| 1 | Stateful store stopped uncleanly at the phase A→B recreate → crash recovery outlives a fixed health gate → `depends_on: service_healthy` fails fast. Keycloak crash-loops on a missing DB meanwhile. | 5 | 5 | 25 | No | Clean stop before recreate, `stop_grace_period`, `start_period`, `syncfs`, Keycloak DB before first start, and a convergence loop that waits on a dependency's **recovery signature** instead of counting passes (**IN FLIGHT**) | `DC` postgres/kafka/opensearch/clickhouse; `IPY` `compose_up`, `stop_stores_cleanly`, `bootstrap_keycloak_db`, `main` |
| 2 | The install dies with the wizard (restart, crash, Ctrl-C, ssh drop). The wizard auto-stops 15 min after an unacknowledged failure. A restarted wizard cannot re-attach, and the page freezes if no `result` marker arrives. | 4 | 5 | 20 | No | Run the install as a detached, journaled job (`systemd-run --collect`, or setsid + pidfile). The wizard re-attaches from the journal and log. It never auto-stops while an install is running or a failure is unacknowledged. The page gets an `onerror` handler and an inactivity watchdog. | `M` `execRunner.start`, `finishInstall`/`armShutdown`, `apiState`; `U` stream handling; `ICS` `cmd_install` |
| 3 | Slow or contended disk (observed IO PSI full 22 %, fsync about 60 ms/file) makes every fixed budget too short: 10 s stop, healthchecks without `start_period`, the 300 s mint wait, the 3-pass compose retry. Nothing measures the disk. | 4 | 4 | 16 | No | A preflight **host-speed probe** (bounded O_DSYNC write-latency sample on the Docker root and `data/`) writes `data/.host-profile.json`. Every budget scales from it, and a very slow disk warns or refuses with the number. | `ICS` `preflight()`; new `scripts/host_profile.py`; `IPY` budget helpers (`_pg_ready_budget_s`, converge budget, `wait_for_minted_certs`) |
| 4 | No stage journal or resume. A re-run (the documented remedy, `ICS:514`) reloads 12 min of images, repeats the phase A→B recreate risk, and never repairs a truncated archive join (`ICS:393-397`) or a partial source extract (`ICS:413-416`). | 4 | 4 | 16 | Partly (steps are mostly idempotent) | `data/.install-journal.json` records per-stage done + input fingerprints. `load_bundle` skips archives whose MANIFEST refs are already present. Join and extract go to `.partial` and are renamed atomically. The TLS phase is skipped when already converged. | `IPY` `main`, `load_bundle`, `load_addon_packs`; `ICS` `verify_bundle` |
| 5 | "Success" over a crash-looping service. `wait_healthy` (`ICS:444-466`) and the CI assert sample `State`, not `RestartCount`. api, keycloak, nginx, grafana and OSD have no healthcheck at all. | 4 | 4 | 16 | No | A stability gate on the **RestartCount delta + StartedAt** over the window. Log-signature classification of any looper, with a targeted remediation (e.g. keycloak "database does not exist" → `--bootstrap-sso` → recreate keycloak). Healthchecks for the services that lack them. | `ICS` `wait_healthy`; `DC` api/keycloak/nginx healthchecks; `CI:171-179` |
| 6 | The admin password is written into the tee'd install log (`ICS:496` via `ICS:809`, default umask), the GUI log ring and SSE replay, and `/api/state` (`M:931`). It survives `uninstall --purge`. | 5 | 3 | 15 | No | Never print it (point at `.env` or the GUI's trusted channel). `umask 077` before creating the log. A redaction filter on child output in the wizard. Purge removes logs. A test proves the log is clean. | `ICS` `print_success`, `cmd_install`; `M` `perLine`, `apiState` |
| 7 | Install or upgrade from a **new bundle folder** over an existing install. `name: netops` (`DC:27`) makes the new folder adopt the old containers. The busy UI port is reported as a foreign process (`ICS:314`). No `upgrade` command, no pre-upgrade backup. A blanket `docker image prune -f` runs after install (`ICS:839`). ACLs are applied through a single-file mount that may be stale (`TLS:623`, `IPY:2563`). | 3 | 5 | 15 | No | Detect an existing install by compose labels and refuse, naming its folder. An explicit `upgrade` subcommand: version check, disk-gated backup, stop stores cleanly, image tag handoff, bootstraps, qualify, rollback on failure. Pipe the ACL script via stdin. Replace prune with named removal of previous-version tags no container references. | `ICS` `preflight()`, new `cmd_upgrade`; `IPY` `apply_kafka_acls` |
| 8 | Firewall lock-out: `--firewall` omits 8800, 443 and the compose-published 514/162/11019; it opens 1162 while compose publishes 162 (`PH:231-236`, `ICS:173-175`). | 3 | 4 | 12 | No (TRACKER 320) | Derive the port set from compose + TLS choice (one source). Insert rules before `ufw enable`. Keep 8800 open while the wizard runs and remove it on stop. Self-probe the management IP after enabling, and roll back with a named message if the wizard port stops answering. | `PH` §13; `M` Prepare handler |
| 9 | OpenSearch bootstrap: `apply-ism.sh:42` waits forever (`until curl -sf … sleep 5`). Under TLS a 401 loops endlessly while the TLS healthcheck treats 401 as healthy (`TLS:276-285`). A failed template apply is only a warning (`IPY:2744-2749`), so indices get dynamic mappings. A flood-stage block makes the recreated node crash-loop. | 3 | 4 | 12 | No | Bound the loop and classify the response (refused / 401 / 403 / 5xx). Template failure becomes a retried, then **degraded** install result shown in the GUI. A post-boot probe for `read_only_allow_delete` releases blocks once disk is under the high watermark. | `deployment/docker/opensearch/apply-ism.sh`; `IPY` `bootstrap_opensearch`, `_result_ok` |
| 10 | Disk budget ignores the containerd image store (compressed blobs + unpacked snapshots: 1.9 GB of zst became 11.8 GB of images). Preflight checks only the Docker root with the wrong message (<20 GB fails, "needs 40 GB", `ICS:303-309`). Nothing checks `data/`'s filesystem, the post-install projection against the OpenSearch 85/90/95 % watermarks, or ENOSPC during `docker load` (`IPY:2476-2480`). | 3 | 4 | 12 | No | MANIFEST carries unpacked sizes. Preflight requires "missing images × unpacked + data budget + margin" on each filesystem and projects post-install use < 80 %. `docker load` stderr is classified (`no space left on device` → named failure listing what uses the disk, never an automatic prune). | `ICS` `preflight()`; `scripts/make-installer.sh` MANIFEST; `IPY` `load_bundle` |
| 11 | Everything starts at once on 4 cores. The planner itself warned "CPU allocations (30.0) exceed cores x 1.5 (6.0)" and "sum of reservations exceeds allocatable". Phase A and phase B each create and start ~25 containers together, so first-boot timers of every service compete. | 4 | 3 | 12 | No | **Tiered bring-up**: stores → wait on each store's own readiness → engines → UI/ingress → add-ons after core qualify. The same order in phase B. Add-ons (OSD, grafana, keycloak) are deferred on hosts the planner flags as over-committed. | `IPY` `main`, `compose_up(services=…)`; `scripts/resource_planner.py` (flag) |
| 12 | No install lock. GUI + CLI, two browser tabs on two wizard processes, or a cron `update.sh` can run at once and race on `.env` surgery and compose (`M:413-422` is in-memory only). | 2 | 5 | 10 | No | `flock` on `deployment/docker/.install.lock`, held by `ICS` and re-checked by `IPY`. The holder writes pid, command and start time. A second invocation refuses and names the holder. A stale lock whose pid is dead is taken over with a log line. | `ICS` `cmd_install`/`cmd_uninstall`/`enable`; `IPY` `main` |
| 13 | Interrupted or ENOSPC `.env` mutation leaves a truncated `.env`. Eight mutation sites use a non-atomic `write_text`/append (`IPY:845, 865, 2126, 2223, 2260, 2298, 2322, 2325, 3237`). A re-run then **keeps** the damaged file (`IPY:760-869`), and the missing keys are not all migrations (e.g. `DB_PASSWORD`). | 2 | 5 | 10 | No | Route every `.env` write through `_write_private` (atomic, 0600). Snapshot `.env.bak.<run-id>` before a run's first mutation. On re-run, validate completeness (every `generate_secrets()` key + every `:?` key in compose). If incomplete and a snapshot matches, restore it; otherwise refuse, naming the keys. | `IPY` `splice_env_values`, `activate_tls_compose_file`, `augment_profiles_for_tls`, `write_offline_override`, `write_env`, `bootstrap_grafana`; new `validate_env_complete` |
| 14 | The install log cannot be trusted for diagnosis. Python stdout is block-buffered through tee (observed out-of-order lines), there are no per-line timestamps, and buffered lines are lost on SIGKILL (the GUI-restart class). | 5 | 2 | 10 | No | `PYTHONUNBUFFERED=1 python3 -u`. A timestamp prefix in the tee filter. Markers stay flushed. | `ICS:827`, `ICS:809` |
| 15 | Host prerequisites not checked: rootless Docker (ports 443/514/162 fail late), a Compose too old for `!override` (`TLS:66-68`), storage driver and snapshotter, inodes, the daemon's nofile limit, proxy/TLS interception (online path), AppArmor/SELinux relabel needs. No `doctor` command gathers them. | 2 | 4 | 8 | No | Extend preflight with named remedies. Add `install-correlix.sh doctor`: a read-only, bounded, redacted report of every check in this document plus the log-signature classifier run over current container logs. | `ICS` `preflight()`, new `cmd_doctor`; shared signature table `scripts/install_signatures.py` |

Just below the cut line (risk 8): Postgres readiness in the drills (TRACKER 321), a fixed 300 s mint budget,
the root-owned auto-created bind sources class, per-consumer secret shape validation, and the GUI token burn
(TRACKER 315). They are in §3 with the rest.

---

## 3. Stage-by-stage FMEA

Each row lists: failure mode · L/I · how it is **detected today** · whether it **self-heals today** ·
the **proposed** technique · the **regression test** that would prove it.

### 3.1 Entry: GUI wizard (`correlix-setup`)

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| G1 | Wizard restarted, crashed or stopped → child install killed or orphaned. No `Setpgid`/`Setsid`/`Pdeathsig` (`M:171`), no signal handling, shutdown does not wait for the child (`M:2008-2015`). | 4/5 | Only by a human (memory 2026-09-14) | No | The install runs as `systemd-run --user --unit=correlix-install-<ts> --collect` where available, else `setsid` with its stdout already going to the log file (not a pipe owned by the wizard). The pid lands in `data/.install-state.json` (journal §4.1). | Go test: start a real child through `execRunner`, kill the parent's pipe reader → the child keeps writing to its log file and finishes. Test that the state file names the pid. |
| G2 | A restarted wizard cannot tell an install is running or has failed. State is in memory only (`M:122-144`); a new token and phase `idle` (`M:257`, `M:1971`). | 4/4 | No | No | On boot, read the journal. If the pid is alive → phase `installing` and re-tail the log from the start. If dead without `done` → phase `interrupted` with the last stage and a "Resume" button (runs the same config; the journal skips completed stages). | Go test with a fixture journal: alive pid → `installing`, dead pid → `interrupted`, done → `installed`. |
| G3 | Auto-stop 15 min after an unacknowledged result, including a **failure** (`M:94`, `M:876`). Observed 03:28:03 on .123. | 5/3 | `gui.log` line only | No | Never auto-stop on `PhaseError`. Keep serving until acknowledged; idle session expiry already bounds exposure (`M:92`). On `installed`, keep the 15 min. Print "re-open with `install-correlix.sh gui`" into the install log on exit. | `TestShutdownScheduling` extension: an error result arms no shutdown; success arms 15 min. |
| G4 | The page stays on the progress bar when the child dies without a `result` marker. The page ignores `phase` events and has no `onerror` (`U:1045-1055`, `U:1108-1112`). | 3/4 | No | No | The server synthesizes a `result: fail` event on any non-zero exit (it already sets the phase, `M:866-875`). The page listens for `phase=error`, adds `EventSource.onerror` with reconnect + `/api/state` poll, and shows "no output for N min" from a server-side inactivity clock. | UI contract test: a child killed by signal → the SSE stream carries a `result` with `status=fail`. JS test for the `onerror` path. |
| G5 | No inactivity or overall timeout on check/prepare/install (`M:412-453`). A hung docker call hangs the wizard forever. | 2/4 | No | No | An inactivity watchdog: no stdout for `max(10 min, profile-scaled)` → phase `stalled` with the last line and the `doctor` suggestion. **Never kill the install automatically** (a slow `docker load` is legal); offer "stop install" which sends SIGTERM to the process group, then SIGKILL after grace. | Fake runner that goes silent → `stalled` after the injected clock passes; nothing killed without the explicit action. |
| G6 | Retry reports a stale failure. `st.result`/`st.stages` are never cleared between runs (`M:423-424`, `M:864`). The UI promises "Retry continues from where it stopped" (`U:1104`) but re-runs from the start. | 3/3 | No | No | Clear result and stages at `runPhase` start. Make the promise true through the journal (§4.1), or change the wording until it is. | `TestIdempotencyKeySemantics` extension: fail → retry exits 0 with no marker → `installed`. |
| G7 | `/api/done` schedules a shutdown during a running install (`M:1008-1011`). | 1/5 | No | No | Refuse `done` unless the phase is `installed`/`error`, with a 409 that names the phase. | Handler test. |
| G8 | Setup token burned by any bare GET, e.g. a link preview (TRACKER 315, `M:1709-1719`). | 3/3 | No | Restart wizard | Exchange only on POST from the landing page; a GET renders a "Continue" button. | Test: prior GET → a later POST exchange succeeds. |
| G9 | SSE slow consumer silently drops events (`M:319`). | 2/2 | No | Page reload replays | Count drops; send a `gap` event so the page refetches `/api/state`. | Unit test on the ring with a blocked subscriber. |
| G10 | Wizard port 8800 busy → `log.Fatalf` (`M:2041-2044`); the port is not probed in facts (`M:1507`). | 2/3 | Fatal line | No | `ICS cmd_gui` probes 8800 first and offers the next free port, printing both. | Bash test with a listener on 8800. |

### 3.2 Entry: `install-correlix.sh` (preflight, bundle, add-ons)

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| S1 | No lock: concurrent installs (§2 #12). | 2/5 | No | No | flock, §4.2 | Two invocations against a held lock: the second exits 3 naming the pid. |
| S2 | Admin password in the log (§2 #6). | 5/3 | No | No | §2 #6 | Stubbed success run; `grep -c "$ADMIN_INITIAL_PASSWORD" log` = 0; log mode 0600. |
| S3 | stdout buffering, no timestamps (§2 #14). | 5/2 | Visible disorder in the .123 log | No | `python3 -u`, ts filter | Contract test: `ICS` invokes `python3 -u` or exports `PYTHONUNBUFFERED=1`. |
| S4 | Disk check on the Docker root only, with mismatched text (<20 GB fails, message says 40; RAM <6 GB fails, message says 8) (`ICS:295-309`). | 3/3 | Partly | No | One threshold table shared by text and test; add `data/` fs + projection (§2 #10). | Table-driven preflight test with fake `df`/meminfo. |
| S5 | Port checks skipped whenever `.env` exists (`ICS:314`, `ICS:327`) — true for a half-installed box that **never started**. | 3/3 | No | No | Skip only ports held by **this project's** containers (`docker ps --filter label=com.docker.compose.project=netops` + `working_dir` = this folder); check the rest. | Fake `ss` + fake `docker ps`: `.env` present, no containers, port busy → FAIL. |
| S6 | 443 and 8800 never checked; ingest list says 162/udp while prepare opens 1162 (`ICS:173-175`, `PH:236`). | 3/3 | No | No | Derive from compose `ports:` + TLS choice (§2 #8). | Test that the preflight list equals the compose-derived set. |
| S7 | Existing install in **another** folder (`name: netops`, `DC:27`) → a busy UI port is misreported as a foreign process, or `--ui-port` makes the new folder recreate the old containers. | 3/5 | Indirect (port FAIL) | No | Refuse with the existing `working_dir` and the two ways forward (`upgrade` from that folder, or uninstall it). | Fake `docker inspect` labels with another `working_dir` → a named refusal. |
| S8 | The `vm.max_map_count` auto-fix is unreachable because the `prepare-host --check` gate fails first (`ICS:270-279` then `ICS:332-346`). | 2/2 | FAIL line | No (dead code) | Either remove the dead branch or order the auto-fix before the gate for items it can fix without sudo. | Test the order. |
| S9 | Split-archive join interrupted → a truncated joined file is never rebuilt; the checksum failure reads "re-download" (`ICS:393-403`). | 2/4 | Misleading FAIL | No | Join into `<file>.partial`, verify its sha against SHA256SUMS, rename. On mismatch with parts present, rebuild once before telling the operator to re-download. | Truncated joined file + good parts → rebuilt and verified. |
| S10 | `sha256sum -c --ignore-missing … >/dev/null 2>&1` names no failing file; a missing SHA256SUMS skips verification silently (`ICS:398-405`). | 2/4 | Partly | No | Keep the output (the failing member); a missing SHA256SUMS in bundle mode is a FAIL unless `CORRELIX_ALLOW_UNVERIFIED=1`. | Corrupted member → FAIL naming it; SUMS absent → FAIL. |
| S11 | Partial source extraction is never repaired (`ICS:413-416`); a newer tarball in the same folder is never extracted. | 2/4 | No | No | Extract to `NetOps_Observability.partial/`, write `.extracted-from=<tarball sha>`, rename. Re-extract when the marker is missing; refuse when the sha differs, pointing at `upgrade`. | Kill mid-extract (fake tar exit 1) → re-run completes; different sha → a named refusal. |
| S12 | `enable <addon>` loads the pack with no checksum or signature (`ICS:1062-1070`). | 2/4 | No | No | Call `verify_bundle` for the pack member. | Corrupted pack → FAIL. |
| S13 | `docker image prune -f … || true` after every install (`ICS:839`). On the containerd image store, whether prune can remove image objects under running containers is **UNVERIFIED**; the 2026-09-06 lab incident did exactly that with `docker rmi` of dangling ids. | 2/5 | No | No | Replace with a named removal of previous-version tags (from the old MANIFEST) that no container references (`docker ps -aq | xargs docker inspect -f '{{.Image}}'` set difference). Report counts; no `|| true`. | Fake docker: an image referenced by a container is never removed. |
| S14 | `wait_healthy` samples State/Health; misses crash loops and services without healthchecks (`ICS:444-466`). | 4/4 | No | No | §2 #5 | Fake `docker inspect` RestartCount 3 → 9 inside the window → FAIL naming the service + signature. |

### 3.3 Entry: `prepare-host.sh`

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| P1 | Firewall lock-out (TRACKER 320). | 3/4 | No | No | §2 #8 | Fake `ufw` records rules; assert 22, 8800 (temporary), 443 or 8000 per scheme, every compose device port. |
| P2 | Unprivileged `--check` never audits the docker-group item (TRACKER 316, `PH:90`, `PH:180-184`). | 4/3 | No | No | `TARGET_USER=${SUDO_USER:-$(id -un)}`. | Both paths print the item. |
| P3 | NTP and unattended-upgrades "fixes" always print FIXED (`… || true; fixd`, `PH:123-126`, `PH:222-224`). §16.1 violation. | 2/3 | No | No | Re-check after the fix; print FIX FAILED with stderr. | Fake `systemctl` failure → not FIXED. |
| P4 | `daemon.json` merge replaces an operator's `log-opts` wholesale (`PH:151-153`) and restarts dockerd **under a running stack**. | 2/4 | No | No | Merge keys; refuse the restart when Correlix containers run unless `--restart-docker`; `live-restore` already set keeps containers alive (verify). | Fixture daemon.json with custom `log-opts` keeps them. |
| P5 | Non-apt hosts always fail the gate even with `CORRELIX_SKIP_OS_CHECK=1` (`PH:86-89`). | 1/3 | FAIL | No | Audit-only checks run without apt; only fixes need apt. | Test with apt absent in `--check`. |

### 3.4 `install.py` — prereq, scaffold, env, sizing

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| E1 | Truncated or partial `.env` after a kill or ENOSPC (§2 #13). | 2/5 | No | No | Atomic writes + completeness validation + snapshot restore. | Monkeypatch `write` to raise ENOSPC mid-surgery → `.env` byte-identical; truncated fixture → restored from snapshot or refused naming the keys. |
| E2 | A generated secret that a consumer's parser rejects (the leading `-` class, fixed at `IPY:316-332`). Residual: `generate_password` alphabet `!@#%^&*-_=+` (`IPY:303`) is used for `CLICKHOUSE_PASSWORD`, `REDIS_PASSWORD` and the four `INGEST_TOKEN_*` (`IPY:683`, `IPY:729`, `IPY:743-746`). Any consumer that is a shell, a URL or an option parser is a latent failure; memory 2026-09-05 records `set -a; . .env` forking on `&`. | 2/4 | Per incident | Partly (`IPY:857-868` heals one key) | A per-consumer **secret shape contract**: each key declares its consumers (url-userinfo, cli-arg, shell-unquoted, xml, yaml); the generator picks the alphabet that is safe for all of them; a re-run heals any value violating its contract where secret_rotation classes it FREE. | Property test: 10 000 minted values per key through each declared consumer parser (urllib, compose interpolation, `shlex`, the OSD option parser rule). |
| E3 | `.env` drift on re-run: an operator removed `sso` from profiles but the keycloak DB bootstrap or add-on load still keys off stale args (`IPY:3632` uses `args.profiles` for grafana while `IPY:3626-3628` uses `.env`). | 2/3 | No | No | One `effective_profiles()` read from `.env` everywhere. | Test: `.env` without self-monitoring + default args → no grafana bootstrap. |
| E4 | Sizing over-commit proceeds silently (demo relaxed mode; observed warnings). | 4/3 | warn lines | No | Emit a machine flag `overcommitted=true` in `resource-plan.json`; `main` switches to tiered bring-up (§2 #11) and defers add-ons. | Planner test: 4 cores / 16 GB → flag set; `main` order test. |
| E5 | `check_docker` accepts any Compose v2; `!override` (`TLS:66-68`) needs a newer Compose (minimum version **UNVERIFIED**, believed ≥ 2.24). | 2/4 | Late compose parse error | No | Parse the version and require the minimum; name the upgrade. | Fake `docker compose version` 2.20 → FAIL. |

### 3.5 `install.py` — image bundle and add-on packs

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| B1 | Re-run reloads every archive (716 s on .123) — no presence check (`IPY:2464-2483`). | 4/3 | No | n/a | Skip when every MANIFEST ref for that archive resolves locally (`docker image inspect <tag>`) **and** the archive sha equals the journal's recorded sha. | Fake inspect all-present → no `zstd` spawned; one missing → load. |
| B2 | Disk full mid-load; containerd keeps compressed + unpacked (§2 #10). | 3/4 | Generic "docker load from bundle failed" (`IPY:2480`) | No | Pre-check against the unpacked size; classify `no space left on device` on stderr (captured, not inherited). | Fake `docker load` with ENOSPC stderr → named failure listing `docker system df` (never an auto-prune). |
| B3 | `docker load` wedged (daemon hang) → install hangs; no timeout (`IPY:2476-2477`). | 2/4 | No | No | Inactivity-bounded (no progress on stdout for N min, profile-scaled), not a wall-clock kill. | Fake load that sleeps silently → bounded failure. |
| B4 | Partial load after a reboot or kill — are the images that were already "Loaded" usable, and is a half-imported image left dangling? **UNVERIFIED** for the containerd store. | 2/3 | No | Unknown | Journal marks the stage incomplete; B1's per-ref check makes the next run load only what is missing; `doctor` lists untagged content from the interrupted load for **operator** removal. | Integration (rig): kill `docker load` at 50 %, re-run, assert every MANIFEST ref inspects. |
| B5 | The chown helper image is not on the host yet (DEFECT-1 class). Fixed by ordering (`IPY:3536-3546`) and ref resolution (`IPY:1709-1728`). Residual: a future helper consumer called before `load_bundle`. | 1/5 | `test_bundle_load_precedes_the_chown_dependent_steps` | Yes (for known callers) | Keep. Generalise: a single `require_local_image(ref)` helper that fails loudly before any `docker run` and names the pack. | Existing test + a lint test that every `docker run` in `IPY` goes through the helper. |
| B6 | Digest-pinned image missing from the offline override: `gotenberg-tls-init` stays digest-pinned in `TLS:784`, which `write_offline_override` never sees (it scans only `docker-compose.yml`, `IPY:2096-2112`). Offline `pdf` profile would try to pull. | 2/4 | No | No | Scan every file in the `COMPOSE_FILE` chain; a test ties MANIFEST ↔ all digest pins. | Test: every `image: …@sha256` in DC+TLS has an override on offline installs. |

### 3.6 `install.py` — TLS env, data dirs, app-state role

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| D1 | Docker auto-creates a bind-mount source as root before `ensure_data_dirs` knows it (DEFECT-6 class). Observed root-owned `data/cloud-logs`, `data/syslog-ng`, `data/vector-aggregator` on .123 — harmless today (those services run as root), fatal for the next non-root one. | 2/4 | `tls_service_mount_dirs` covers only `tls/services/*` (`IPY:1805-1828`) | Partly | Derive **every** `../../data/<x>` bind source from the whole `COMPOSE_FILE` chain; pre-create each with the owner declared by a compose `x-correlix-owner` extension (or a table checked against compose by test). | Test: every data bind source in DC+TLS appears in the owner map. |
| D2 | Re-install over a data tree owned by service uids → the non-root installer cannot traverse (`IPY:1911-1928` fails with a manual `sudo chown`). | 3/3 | Named FAIL | No | Same helper-container repair `chown_tree` already uses (`IPY:1731-1752`), bounded, for `mkdir` too. | Fixture: parent 0700 owned by another uid → helper path used. |
| D3 | Postgres first-boot three states (fixed, `IPY:2939-3037`). Residual: the drills and the rotation path still gate on `pg_isready` (TRACKER 321). | 2/4 | CI boot test | Yes (install) / No (drills) | Share the readiness rule as a small shell helper for the drills. | TRACKER 321 test. |
| D4 | App-state role provisioning budget 180 s fixed (`IPY:2910`), env-tunable only by a knob the operator must know (`IPY:3163-3167`). | 2/4 | Named FAIL with the knob | Partly | Budget from the host profile (§4.3). | Profile "slow" → budget ≥ 600 s. |

### 3.7 `install.py` — phase A, mint, phase B (the two-phase TLS boot)

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| T1 | **Item 1.** Unclean store stop at recreate → recovery → fast-failing health gate. | 5/5 | Compose error line; `compose_up` 3 fixed passes (`IPY:2449-2461`) | No | **IN FLIGHT:** `stop_grace_period: 120s` on postgres/kafka/opensearch/clickhouse; `recovery_init_sync_method=syncfs`; postgres `start_period: 300s`; `stop_stores_cleanly()` before phase B with SIGKILL (exit 137) reporting; `compose_up` convergence loop with `_UP_BLOCKER`, `_PROGRESS_SIGNATURES` (recovery wording), `_UP_FATAL_SIGNATURES` (port allocated, no such image, ENOSPC), crash-loop detection (restarts ≥ 3), 900 s budget, redacted log tails. **Residual gaps to check in review:** (a) `stop_grace_period` is only honoured if the signal reaches the postmaster — the TLS wrapper `exec`s (`deployment/docker/postgres/tls-entrypoint.sh:75`), good; keep a test that every TLS wrapper `exec`s; (b) kafka, clickhouse and opensearch have their own unclean-stop recovery wording that `_PROGRESS_SIGNATURES` does not list yet (Kafka "Recovering unflushed segment", ClickHouse "Loading data parts", OpenSearch "recovering"); (c) the budget should come from the host profile, not a constant; (d) confirm the post-stop verification reads postgres' `database system is shut down` line, not just the exit code. | IN FLIGHT tests in `tests/test_install_converge.py` (`test_a_recovering_dependency_is_waited_for_not_failed`, `test_phase_b_stops_the_stores_before_recreating_them`, …). **Add:** a CI chaos leg that `docker kill -s KILL netops-postgres-1` between phase A and B on the real two-phase boot and asserts exit 0. |
| T2 | Keycloak (profile sso) starts in phase A before its DB exists → crash loop, CPU burn (`DC:171-206`, `IPY:3628-3630`). | 5/3 | Warning only when the late bootstrap fails (`IPY:2787-2813`) | Only if the install reaches the end | **IN FLIGHT:** `bootstrap_keycloak_db(start_postgres=True)` before the first start. Residual: make a failure to create it **fatal** when `sso` is active (today it warns), because "success" with a looping Keycloak is §2 #5. | IN FLIGHT `test_keycloak_database_is_created_before_the_first_start`. |
| T3 | Mint budget fixed at 300 s (`IPY:2331`); mint took 91 s on .123 with the stores still starting; a slower disk or a looping dependency of the api (postgres, redis, secrets-seal healthy — `DC:2288-2292`, `TLS:93-95`) runs it out. Failure names sentinels but not **why** the api has not minted. | 2/4 | Missing-sentinel list (`IPY:2348-2353`) | No | Budget from the host profile; while waiting, poll the api container state + its blockers and print them ("api is `created`: waiting on postgres (recovering)"); stop early with the blocker's signature if the api's dependency is crash-looping. | Fake ops: api `created` + postgres unhealthy → message names postgres. |
| T4 | Phase-B recreate of a store hit by OpenSearch flood stage → 60 s crash loop (memory 2026-09-05). | 2/4 | No | No | Before phase B: if any filesystem ≥ 88 %, refuse the recreate and name the disk consumers; after boot, the block-release probe (§2 #9). | Fake `df` 92 % → refusal before recreate. |
| T5 | Phase B changes `DATABASE_URL` to verify-full (`IPY:3185-3219`) before postgres is actually serving TLS; a failed phase B leaves `.env` in the TLS form, and a re-run's phase A normalises it back (`IPY:2229-2262`). Works today — a re-run converges — but only because two surgeries undo each other. | 2/3 | n/a | Yes (by accident) | Record the TLS phase in the journal (`tls_phase=a|b|done`) so the re-run knows which half it is in and skips A when certs + chain are already present. | Journal test: failed B → re-run does not re-enter A. |
| T6 | Keycloak under TLS: pg_hba is `hostssl` only (`tls-entrypoint.sh:63`) and `KC_DB_URL` carries no `sslmode` (`DC:198`). pgjdbc's default `sslmode=prefer` should negotiate TLS — **UNVERIFIED**. | 2/4 | No | Unknown | Verify on the rig; if it fails, set `?sslmode=require` in `TLS` for keycloak. | Boot test with `sso` under TLS asserting keycloak healthy. |
| T7 | `apply_kafka_acls` runs the **mounted** `/acls/apply-acls.sh` (`IPY:2532`, `IPY:2563`; `TLS:623` single-file mount). On an upgrade where kafka is not recreated, the container runs the old matrix (memory 2026-09-02). | 3/5 | Bus-liveness gate catches the correlation group only (`IPY:2596-2631`) | Partly (bounded retry 900 s) | Pipe the repo script: `docker compose exec -T kafka sh -s < deployment/docker/kafka/apply-acls.sh`; extend `verify_bus_consumers` to every consumer group the release declares (`netops-router-*` too). | Test asserting the command pipes stdin; fake describe with a router group missing → FAIL. |

### 3.8 `install.py` — post-boot bootstraps

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| O1 | `apply-ism.sh:42` unbounded wait; TLS 401 loop (§2 #9). | 3/4 | No | No | Bound + classify; exit 78 with the class. | Fake curl 401 ×N → exit non-zero after the bound. |
| O2 | Index templates not applied → only `warn` (`IPY:2744-2749`), install reports ok. | 3/4 | warn line | No | Retry within budget; still failing → install result `degraded` (new marker status) with the exact re-run command; GUI shows it as amber, not green. | Test: script exit 1 → `_result` status `degraded`. |
| O3 | `bootstrap_grafana` installs a plugin from the internet with an `--insecure` fallback (`IPY:3264-3272`) — on an offline install this always fails and then warns; on an intercepted network it silently downgrades verification. | 3/3 | warn | No | Ship the plugin in the self-monitoring pack; no network fetch on bundle installs; never auto-fallback to `--insecure` (make it an explicit operator flag). | Offline test: no `grafana cli plugins install` invoked. |
| O4 | `bootstrap_grafana` recreates grafana with `check=False` and prints ok regardless (`IPY:3281-3283`). §16.1. | 2/2 | No | No | Check the return code and name the failure. | Fake compose exit 1 → warn with stderr. |
| O5 | Profile gating reads `args.profiles` for grafana (`IPY:3632`) but `.env` for keycloak (`IPY:3626-3628`). | 2/3 | No | No | E3. | E3. |

### 3.9 Interruption, resume and re-run

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| R1 | Ctrl-C / SIGTERM → `KeyboardInterrupt` → `fail("interrupted")` with no cleanup (`IPY:3685-3687`); SIGTERM/SIGHUP are not handled at all (Python default = die, no stage-fail marker, no timing file). ssh drop kills a foreground `ICS` run. | 3/4 | No | No | Handle SIGTERM/SIGHUP like SIGINT: close the open stage as `interrupted`, write the journal, flush, exit 130/143. `ICS` prints "safe to resume: `install-correlix.sh install --resume`". Recommend `tmux`/`systemd-run` in the printed command for ssh installs. | Test: send SIGTERM to a subprocess running a stub stage → journal says `interrupted`, marker emitted. |
| R2 | Reboot mid-install: `restart: unless-stopped` (`DC:39`) brings back whatever phase was running; if the reboot hit phase B, some containers are TLS-configured and some are not. | 2/4 | No | Re-run converges (not proven) | Journal-driven resume re-enters the recorded TLS phase; `doctor` shows mixed phase (containers whose config hash ≠ current chain). | Rig test (owner-gated hardware): reboot during up-b, re-run, qualify. |
| R3 | Re-run after failure repeats the whole run including the destabilising recreate (§2 #4). | 4/4 | No | Partly | Journal (§4.1). | Journal tests. |
| R4 | Re-run after the operator changed the TLS answer (yes → no) on a started install: compose chain still includes `compose.tls.yml`; `resolve_tls_choice` returns false but nothing removes the variant. **UNVERIFIED** what happens (likely stays TLS silently). | 2/3 | No | Unknown | Detect the mismatch from `COMPOSE_FILE` and refuse a downgrade with an explanation (downgrade is a migration, not a flag flip). | Test: `.env` chain has tls + `--tls=no` → refusal. |

### 3.10 Upgrade over an existing install

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| U1 | No `upgrade` subcommand (`ICS:132-134`); the bundle path has no pre-upgrade backup; `update.sh` pulls/builds and cannot work offline (`scripts/update.sh:333-336`). | 3/5 | No | No | `cmd_upgrade`: version from MANIFEST vs `data/.correlix-version`; refuse downgrade; disk gate; `scripts/backup.sh` (exists, used by `update.sh:315-327`); `stop_stores_cleanly`; load new images; run install.py (journal marks bootstraps as required again); `docs/runbooks/upgrade-bootstraps.md` §2 list; `deploy-qualify.sh`; on failure re-tag previous images + restore `.env` snapshot + start. | Integration on the rig: upgrade N-1 → N with a forced failure at qualify → stack back on N-1, data intact. |
| U2 | New bundle folder adopts the old project (§2 #7, S7). | 3/5 | Indirect | No | S7. | S7. |
| U3 | Consumer topic set changed → ACLs must be re-applied (memory 2026-09-02). install.py re-applies every run (good) but via the possibly stale mount (T7). | 3/5 | Correlation group only | Partly | T7. | T7. |
| U4 | Valkey cannot load a Redis 7.4 RDB (`DC:108-114`) — upgrade from a pre-Valkey install needs `data/redis/dump.rdb` removed. | 1/3 | Runtime crash loop | No | Upgrade pre-step detects an RDB version header it cannot read and moves it aside with a log line (the store is a cache — confirm before automating). | Fixture RDB header → moved aside. |
| U5 | `.env` migrations append new secrets for new keys (`IPY:763-849`) — correct — but never validate that the stores that already consumed older keys still agree (e.g. an operator-edited `DB_PASSWORD`). | 2/4 | No | No | Post-migration credential probe per store (the rotation module's verify functions) before `compose up`; refuse with the store named. | Fake runner auth failure → refusal. |

### 3.11 Uninstall and leftovers

| ID | Failure mode | L/I | Detected today | Self-heals? | Proposed | Regression test |
|---|---|---|---|---|---|---|
| X1 | Symlink `/usr/local/bin/install-correlix` left dangling (TRACKER 317); surfaced as the only FIX on the next bundle's readiness screen. | 4/2 | Next install's prepare check | No | Remove or re-point on purge; name it. | TRACKER 317 test. |
| X2 | Watchdog cron + `/etc/correlix/*` + logrotate left behind (never called by uninstall; `scripts/install-watchdog.sh:106-126`). A leftover watchdog pages the owner's phone about a stack that was deliberately removed. | 3/3 | No | No | `cmd_uninstall` calls `install-watchdog.sh --uninstall` when the cron file exists (needs sudo — ask, or print the exact command and exit non-zero on `--purge` if not done). | Fake cron file → purge removes or names it. |
| X3 | Install logs containing the admin password survive purge (S2). | 5/3 | No | No | Purge removes `correlix-install-*.log` (after S2 there is nothing secret in new ones). | Purge test. |
| X4 | `/etc/sysctl.d/99-correlix.conf`, daemon.json edits, UFW rules, `correlix` user remain. | 4/1 | No | No | `uninstall --purge-host` (explicit, separate) reverts prepare-host changes it can prove it made (backup of daemon.json taken at prepare time). | Fixture test with recorded backups. |
| X5 | `docker rmi … || true` per MANIFEST image (`ICS:985-991`) hides failures (§16.1). | 3/2 | No | No | Count and name images not removed and why. | Fake rmi failure → named. |
| X6 | Purge fails in `purge_data_dir` → `.env` kept (correct), but images are not yet removed and the operator sees `die` text only. | 2/2 | Named | Partly | Fine as is; add the journal state `uninstall-incomplete` so `doctor`/next install explain it. | — |

### 3.12 Host-level conditions (cross-cutting)

| ID | Condition | L/I | Detected today | Proposed detection / healing |
|---|---|---|---|---|
| H1 | Slow fsync / IO contention (observed) | 4/4 | No | Host-speed probe (§4.3); budgets scale; tiered bring-up. |
| H2 | Low RAM / OOM kills during first boot | 2/4 | RAM ≥6 GB gate (`ICS:295`) | `doctor` + stability gate read `State.OOMKilled` and `dmesg`-free cgroup `memory.events` (`oom_kill`) per container; classify "OOMKilled" and name the planner knob. |
| H3 | CPU contention (planner over-commit, observed) | 4/3 | warn | Tiered bring-up; defer add-ons. |
| H4 | Clock skew → SVID `notBefore` in the future | 1/4 | `PH:123` NTP check | Mint stage compares host time with an SVID's `notBefore`; skew > 60 s → named failure. |
| H5 | `vm.max_map_count` | 1/4 | Gate + auto-fix (`ICS:332-346`) | Keep (fix S8 order). |
| H6 | ulimit nofile of dockerd / containers | 1/3 | OpenSearch/ClickHouse set their own (`DC:745-746`, `DC:1302`) | `doctor` reads `/proc/$(pidof dockerd)/limits` (root-only → report UNKNOWN when unprivileged, never guess). |
| H7 | Inodes exhausted | 1/4 | No | Preflight `df -i` on Docker root and `data/` fs; fail < 5 % free. |
| H8 | SELinux enforcing (non-Ubuntu) / AppArmor denials on bind mounts | 1/4 | OS gate limits to Ubuntu/Debian (`ICS:248-256`) | `doctor` reports `aa-status` summary where readable; classifier signature `permission denied` on a bind mount with correct uid → "LSM denial suspected". |
| H9 | Rootless Docker → privileged ports 443/514/162 fail | 1/4 | No | Preflight reads `docker info -f '{{.SecurityOptions}}'` for `rootless`; FAIL with remedy (ports ≥1024 via `.env`). |
| H10 | Storage driver / snapshotter (containerd store doubles image disk) | 3/3 | No | Preflight reads `DriverStatus`; disk budget multiplier. |
| H11 | cgroup v1 host (resource limits semantics differ) | 1/2 | No | Preflight reads `docker info -f '{{.CgroupVersion}}'`; WARN. |
| H12 | Proxy / TLS interception on the online path (memory `versa-tls-interception`) | 2/3 | No (online path only) | Online installs probe the registry with the system CA bundle and classify `x509: certificate signed by unknown authority` → name the interception, never auto-`--insecure`. |
| H13 | DNS broken inside containers (online build) | 2/3 | No | Online preflight runs a bounded `docker run --rm --network netops-probe <local image> getent hosts <registry>`; offline skips. |
| H14 | Docker daemon restarted mid-install (package upgrade via unattended-upgrades) | 2/4 | No | Every docker call classifies `Cannot connect to the Docker daemon` → bounded wait for `docker info` (backoff + jitter, 120 s) then resume the step once. prepare-host could pin a `Unattended-Upgrade::Package-Blacklist` for docker during install (**proposal, owner call**). |

---

## 4. Self-healing building blocks (proposed architecture)

These are the shared mechanisms the rows above lean on. Each is small, testable without Docker
(injected runner, clock and filesystem, the same pattern as `ComposeRunner`, `IPY:1457-1487`),
and loud when it cannot heal.

### 4.1 Install journal (resumable stages)

- File: `data/.install-journal.json`. Written atomically (`_write_private` pattern, `IPY:644-664`),
  mode 0600, **no secrets** (fingerprints are sha256 of inputs, never values).
- Record per stage: `id`, `status` (`running|done|failed|interrupted`), `started_utc`, `ended_utc`,
  `inputs` (bundle sha, MANIFEST sha, `.env` key-set hash, compose chain hash, TLS phase), `pid`.
- Rules:
  1. A stage is skipped on re-run only if `done` **and** its input fingerprint is unchanged **and** its
     cheap post-condition still holds (e.g. `bundle`: every MANIFEST ref inspects; `mint`: sentinels exist;
     `kafka-acls`: never skipped — it is cheap and the store can be wiped).
  2. Destructive or state-changing stages (`up-b`) always re-verify their post-condition instead of trusting the journal.
  3. The journal is advisory: a missing or corrupt journal means "run everything", never "refuse".
- Consumers: `install.py main`, the wizard's re-attach (G2), `doctor`, `deploy-qualify.sh` (can floor windows on
  `up-b.ended_utc` the way Q6 already floors on the ACL marker, `IPY:2634-2669`).
- The existing `data/install-timing.json` (`IPY:271-294`) is the natural seed — extend it rather than add a third file.

### 4.2 Single-writer lock

- `flock -n 9` on `deployment/docker/.install.lock` in `ICS` for `install|uninstall|enable|disable|reset-demo-data|upgrade`.
- `install.py` re-acquires (Python `fcntl.flock`) so a direct `python3 scripts/install.py` is also covered.
- The holder writes `pid`, `argv[0..1]`, `started_utc` into the lock file; a refusal prints them.
- A stale lock (holder pid dead) is taken over with a `warn` line. flock releases on process death anyway, so this is only
  about the diagnostic contents.

### 4.3 Host profile → budgets

- `scripts/host_profile.py` (stdlib only): bounded O_DSYNC write latency (e.g. 64 × 8 KiB writes, 5 s cap) on the Docker
  root's filesystem and on `data/`'s, CPU count, MemTotal, IO/CPU PSI avg60 where readable, snapshotter type.
- Writes `data/.host-profile.json` with a class: `fast | normal | slow | very-slow`.
- Every budget in the installer becomes `base × factor(class)` with an explicit env override kept (the
  `CORRELIX_PG_READY_TIMEOUT` pattern, `IPY:2906-2930`): PG readiness, compose converge, mint, ACL apply, stop grace
  (via `.env` → compose `stop_grace_period: ${STORE_STOP_GRACE:-120s}`), healthcheck `start_period`.
- `very-slow` (e.g. p99 fsync > 200 ms or IO PSI full avg60 > 20 %): preflight WARNs in plain words ("this disk is about N×
  slower than recommended; the install will take longer and first boots are at risk") and switches on tiered bring-up;
  it refuses only with an operator override absent if the probe measures the disk as unusable (threshold to calibrate on
  the rig — **proposal**).
- On .123 the measured symptom (≈60 ms per file fsync, IO PSI full avg300 22.5 %) would classify `very-slow`.

### 4.4 Log-signature classifier (one table, many callers)

- `scripts/install_signatures.py`: `(service, regex) → class, remedy, action`. Classes:
  `recovering` (wait), `starting` (wait), `fatal-config` (stop, name key), `port-conflict`, `disk-full`,
  `image-missing`, `auth-denied` (ACL/credential), `db-missing` (targeted bootstrap), `flood-stage`,
  `oom-killed`, `lsm-denied`, `daemon-down`.
- The in-flight `_UP_FATAL_SIGNATURES` / `_PROGRESS_SIGNATURES` / `_UP_BLOCKER` in `compose_up` are the seed; move them to the
  shared module so `wait_healthy` (bash calls `python3 -m install_signatures classify <service>`), `doctor`, the wizard's
  failure panel and `deploy-qualify.sh` classify identically.
- Actions are **whitelisted and idempotent**: `wait` (bounded), `bootstrap:<name>` (e.g. keycloak DB, Kafka ACLs, OS
  templates), `recreate:<service>` (once per run, journaled), `fail`. No action deletes data or images.
- Output of any log excerpt passes the in-flight `_SECRETISH` redaction (`passw|secret|token|apikey|…`).
- Tests: every signature has a recorded real log fixture (the .123 postgres log in §1.1 is fixture #1; keycloak
  `database "keycloak" does not exist`; OSD `must have a value`; Kafka `TopicAuthorizationFailedError`; OpenSearch
  `ClusterBlockException … read_only_allow_delete`; `port is already allocated`; `no space left on device`).

### 4.5 Tiered bring-up

- Tier 0 stores: postgres, clickhouse, kafka, opensearch, redis(valkey), victoria, secrets-seal.
- Tier 1 bootstraps that need stores only: app-state role, keycloak DB, kafka-init, opensearch-security-init.
- Tier 2 engines: api, correlation, vector-aggregator, vector-router, syslog-ng, goflow2, gnmic, prober, vmalert, vmauth.
- Tier 3 ingress/UI: frontend, nginx.
- Tier 4 add-ons: opensearch-dashboards, grafana/cadvisor/node-exporter/kafka-exporter, keycloak.
- `compose_up(services=[…])` per tier with `--no-deps` off (compose still enforces `depends_on`), waiting on each tier's
  own readiness through the classifier before the next. On `fast`/`normal` hosts the tiers can collapse to today's single
  `up -d` for speed; on `slow`/`very-slow` or planner `overcommitted` they stay separate.
- Phase B uses the same tiers after `stop_stores_cleanly` (IN FLIGHT).
- The thresholds that pick the mode are uncalibrated, so `CORRELIX_BRINGUP_MODE=auto|tiered|single` (default `auto`)
  settles it for a host they read wrong — the support lever, no patched installer. `tiered`/`single` outrank both the
  host class and the planner, and the reason the installer prints then names the variable instead of the host. A value
  that is none of the three stops the install rather than being ignored.

### 4.6 `doctor` (read-only, bounded, redacted)

- `install-correlix.sh doctor [--json]`: host profile, preflight checks (all of §3.12), journal + lock state, compose
  project ownership (S7), every container's state + `RestartCount` + `OOMKilled` + health + classifier verdict on its last
  200 log lines, disk vs watermarks, ACL marker age, `.env` completeness (key names only), wizard state.
- Exit 0 healthy · 1 actionable problems · 2 could not assess (e.g. docker unreachable).
- The wizard's failure panel runs it and shows the verdicts; the support bundle includes its JSON.
- Never mutates anything; never prints a secret value (tested by a fixture `.env` with sentinel secrets).

### 4.7 Stability gate (success means stable, not sampled)

- Window W (profile-scaled, default 60 s): record `RestartCount` and `StartedAt` for every non-one-shot container at t0 and
  t0+W; any increase, or any `StartedAt` inside the window, or health `unhealthy` at the end → not stable.
- One-shots (`*-init`, `gotenberg-tls-init`) must be `exited 0` — today nothing waits for them (`DC` has no
  `service_completed_successfully` except `TLS:821-823`).
- Replaces the sampling in `ICS:444-466` and `CI:171-179`.

---

## 5. Regression-test plan

| Layer | What it proves | Where |
|---|---|---|
| Unit (no docker) | Classifier table vs recorded real logs; journal skip/resume rules; lock refusal; atomic `.env` under injected ENOSPC; completeness validator; host-profile classification with an injected timer; tiered order; stability gate with fake inspect data; secret shape contract property test | `tests/test_install_*.py` (pytest, same style as `tests/test_install_data_dirs.py`) |
| Go unit | Detached child survives wizard exit; re-attach from journal; no auto-stop on error; result synthesis on signal death; inactivity `stalled`; token exchange only on POST | `scripts/installer-gui/*_test.go` |
| Bash | preflight tables, `verify_bundle` partial join/extract, `wait_healthy` restart delta, purge leftovers, firewall rule set with fake `ufw` | `tests/` shell harness already used by `test_install_uninstall.py` |
| CI real boot (extend `CI:100-196`) | (1) **non-root** run through `install-correlix.sh` with a locally built bundle (the customer path); (2) **chaos**: SIGKILL postgres between phase A and B; (3) **re-run** of the same install (second run must skip `bundle` and exit 0 fast); (4) **throttled disk**: `docker run --device-write-bps` is not available for the daemon itself — use a loop-mounted, `dm-delay`-backed `data/` on the runner (**feasibility UNVERIFIED on GitHub runners**; fallback: the rig); (5) stability gate instead of the one-shot state sample | `.github/workflows/fresh-install-integrity.yml` |
| Rig (owner-gated hardware, per memory `single-box-ttur-goal`) | Reboot mid-phase-B; upgrade N-1→N with forced rollback; GUI restart during `docker load`; the .123-class slow disk | acceptance runbook `docs/runbooks/first-customer-acceptance.md` gets a "failure drills" section |

A fix for any row is complete only with its test red on HEAD and green after (the "tests that lied" lesson,
memory `remediation-run-2026-09-12`).

---

## 6. Suggested sequencing (bounded contexts, one per change — CLAUDE.md §7)

1. **Merge item 1 (IN FLIGHT)** + its CI chaos leg (T1) + make keycloak DB creation fatal under `sso` (T2 residual).
2. **Diagnosability first, it is cheap:** `python3 -u` + timestamps (S3), no password in logs (S2/X3), stability gate (§4.7) in `wait_healthy` and CI.
3. **Wizard lifecycle** (G1–G4, G6, G7): detached job + re-attach + no auto-stop on error. This is the owner-visible one.
4. **Lock + atomic `.env` + completeness validator** (S1, E1).
5. **Journal + bundle skip + atomic join/extract** (§4.1, B1, S9, S11).
6. **Host profile + budgets + tiered bring-up** (§4.3, §4.5) — calibrate thresholds on .123 read-only data + the rig.
7. **Classifier module + `doctor`** (§4.4, §4.6), absorbing the in-flight signature tables.
8. **Firewall + port single source** (P1/S6, TRACKER 320) and **existing-install detection + `upgrade`** (S7, U1, T7, S13).
9. Long tail from §3 as tracker rows.

---

## 7. Open questions for the owner

1. **Refuse or warn on a very slow disk?** On .123 the disk measured ≈60 ms per fsync under load. Refusing protects the
   first impression; warning keeps evaluation hosts usable. Proposal: warn + tiered bring-up, refuse only below an
   "unusable" floor calibrated on the rig.
2. **systemd-run vs setsid** for the detached install: systemd gives cgroup-level stop and a journal, but a `--user`
   unit needs lingering for an ssh-launched wizard. Proposal: system unit via the sudo step the wizard already has
   (Prepare), setsid fallback.
3. **Degraded result status:** should an install whose optional bootstraps failed (OpenSearch templates, grafana plugin)
   report amber "installed with problems" in the GUI? Proposal: yes; today it reports green.
4. **Uninstall reverting host changes** (`--purge-host`): acceptable scope, or leave host hardening in place by design?
5. **unattended-upgrades restarting dockerd during an install** (H14): pin during install, or only detect and wait?

---

## 8. What was verified, and how

- **Code:** read at HEAD `74f7be09` — `IPY` 1–960, 1457–1506, 1668–3687 in full; `ICS` preflight, `verify_bundle`,
  `wait_healthy`, `print_success`, `cmd_install`, uninstall/purge; `PH` privilege, firewall, alias; `M` process
  start, `finishInstall`, constants; `DC` postgres/keycloak/api/correlation/anchors via `git show HEAD:`; `TLS` as on disk
  (unmodified). Wider inventories of `M`/`U`, `ICS`/`PH`/`update.sh`/`install-watchdog.sh`/`deploy-qualify.sh` and all
  compose services were produced by three read-only sub-inventories; their load-bearing citations used in §2 were
  re-read directly.
- **Lab (10.70.245.123), read-only only:** `docker ps/inspect/logs/info/system df`, `vmstat`, `/proc/pressure/*`, `lsblk`,
  `sysctl`, the install log, `gui.log`, `data/install-timing.json`, `ls` of `data/`, `.env` **key names only** (no values
  printed). Nothing was restarted, stopped, written, pruned or re-run.
- **UNVERIFIED items** (flagged in place): containerd-store behaviour of an interrupted `docker load` (B4) and of
  `docker image prune` under running containers (S13); Keycloak JDBC under `hostssl` (T6); minimum Compose version for
  `!override` (E5); TLS-answer downgrade behaviour (R4); dm-delay feasibility on GitHub runners (§5); the phase-A postgres
  container's exact exit code (container removed — the unclean stop is proven by the recovery log, the SIGKILL-at-10 s is
  inferred from the absent `stop_grace_period`).
