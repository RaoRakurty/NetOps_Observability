<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Fresh-install acceptance — 2026-09-06/07

> The acceptance tracker row 265 was written around: **a fresh install of the
> shipped download folder on a server the owner provides, driven the way a
> customer drives it.** This is that run, on the host the owner designated.
>
> Nothing in this document is a secret. The one-time setup token, the sudo
> password and the generated administrator password were all used during the
> run and are deliberately absent. The setup certificate fingerprints printed
> below are public by design — they exist to be compared in a browser warning.

| | |
|---|---|
| **Host** | `10.70.245.123` (`netops`), owner-designated |
| **Bundle** | `correlix-2026.09.06-g9967eaf5` (`dist/`, git `9967eaf5`, built 2026-09-06T20:31:22Z) |
| **Path driven** | **Graphical** (the `correlix-setup` wizard over HTTPS), driven headlessly with Playwright/chromium from the dev box |
| **Result** | **PASS on the fifth attempt** — a fully healthy, TLS/mTLS, PostgreSQL-backed stack, verified by the wizard, by `deploy-qualify.sh` (9 passed / 0 failed) and by hand. It took five attempts because the shipped installer had **four blocking defects**; all are fixed and each fix was proven by re-running the step that failed. **The 2026-09-06 bundle must be rebuilt before it ships** (DEFECT‑3). |
| **Sign-in URL** | **`https://10.70.245.123/`** — administrator `admin`, password in `deployment/docker/.env` as `ADMIN_INITIAL_PASSWORD`. Self-signed certificate, so the browser warns once. (Not `:8000` — see DEFECT‑7.) |
| **Left running** | yes, deliberately: 20 containers, core only, self-monitoring enabled then disabled again |

---

## 0. Step 0 — cleaning the host (owner instruction, 2026-09-07)

The host was **not** bare: it carried a running Correlix install from
2026-07-21 plus leftovers from 2026-07-04. Per the owner's instruction the host
was cleaned the way a customer would be told to, starting with the product's own
supported uninstall.

**What was there**

| Item | Detail |
|---|---|
| Running stack | compose project `netops`, 16 running + 2 exited containers, up 17 min |
| Install dir | `/home/rao/correlix-2026.07.21-g236c9a2b` — 2.6 GB (bundle + extracted tree + `data/`) |
| Older leftover | `/home/rao/correlix-2026.07.04-g8d36d26` — 12 MB (`NetOps_Observability/data` only) |
| Images | 17 images, 6.355 GB (95 % reclaimable) |
| Volumes | 10 local volumes (5 in use) |
| Network | `netops_netops` |
| Service account | `correlix` (system user, home `/opt/correlix`, docker group) |
| Logs | `~/correlix-install.log`, `~/install-g8d36d26.log`, `~/setup-gui.log` |

**What was removed**

1. `./install-correlix.sh uninstall --purge` from the old install directory —
   removed all 18 containers, all 17 images and the `netops_netops` network.
   **It exited 1** and left 6.3 MB of data behind — see DEFECT‑3.
2. The residue the uninstall could not remove, with sudo: both bundle
   directories, the three stray install logs.
3. `docker volume prune -f` — the 10 anonymous volumes `compose down`
   (no `-v`) had orphaned. See DEFECT‑4.
4. `userdel -r correlix` — the service account and `/opt/correlix`, so
   `prepare-host.sh` would be genuinely exercised.

**Nothing else was touched.** Docker itself, its `daemon.json`, the
`/etc/sysctl.d/99-correlix.conf` kernel settings and `unattended-upgrades` were
left in place per the owner's instruction (no OS packages, no Docker). Those
four therefore report PASS in §3 from the *previous* preparation rather than
from this run; the service account and the PATH alias were genuinely re-created.

**Post-clean state:** 0 containers, 0 images, 0 volumes, no Correlix directory,
no service account, 84 GB free.

---

## 1. Host survey (read-only, before anything was changed)

| Fact | Value | Against the documented requirement |
|---|---|---|
| OS | Ubuntu 22.04.5 LTS (jammy), kernel 5.15.0-186 | ✅ Ubuntu 22.04+ |
| Arch | x86_64 | ✅ |
| CPU | 4 cores | ✅ meets the *production* recommendation |
| RAM | 15.6 GiB | ⚠️ just under the 16 GiB production recommendation; well over the 8 GB evaluation minimum |
| Disk | 97 GB volume, 84 GB free after the clean | ⚠️ just under the 100 GB production recommendation; well over the 40 GB minimum |
| Docker | 29.1.3 (Ubuntu `docker.io` build, not docker-ce) | ✅ |
| Compose | v2.40.3 plugin | ✅ Compose v2 |
| Management IP | `10.70.245.123` on `enp1s0` (the only non-virtual IPv4; `docker0` correctly filtered out) | ✅ |

The two ⚠️ rows are exactly how the product reports them — as advisory
`≥ 16 GiB recommended` / `≥ 100 GB recommended` marks, not as blockers. That is
the right call for this host.

---

## 2. Steps and timings

| # | Step | How | Outcome | Duration |
|---|---|---|---|---|
| 0 | Survey + clean | ssh, then `uninstall --purge` + residue removal | done; 2 defects found (DEFECT‑11, ‑12) | ~4 min |
| 1 | Ship the folder | `rsync -a` of the whole 2.1 GB `dist/correlix-2026.09.06-g9967eaf5/` | 366 files transferred | **50 s** (~43 MB/s) |
| 2 | Verify integrity | `sha256sum -c SHA256SUMS` on the host | **365/365 OK, exit 0** | **28 s** |
| 3 | Host readiness audit | `./prepare-host.sh --check` (read-only) | 6 PASS, 2 FIX (exit 1) — correctly named the service account and the PATH alias I had removed | 1 s |
| 4 | Prepare the host | `sudo ./prepare-host.sh` | 7 PASS, 2 FIXED, exit 0 — "Host is ready for Correlix." | **4 s** |
| 5 | Start the wizard | `./install-correlix.sh gui` | bound `10.70.245.123:8800` over **HTTPS**, printed the URL, the SHA-256 certificate fingerprint and a one-time token | 6 s |
| 6 | Wizard walk ×5 | Playwright/chromium, `ignoreHTTPSErrors` | identical every time: core only (all add-ons unticked), discovery off, sizing auto, admin `admin`, PostgreSQL, full mTLS | ~20 s per walk |
| 7 | Install (run 1) | wizard **Install** | ❌ **FAILED at 42 %** — DEFECT‑1 (TLS stage: ingress key ownership) | 42 s to failure |
| 8 | Install (run 2, D‑1 fixed) | wizard **Install** | ❌ **FAILED at 67 %** — DEFECT‑2 (Postgres first boot). D‑1's stage now passes: *"ownership repaired to 101:101 via helper container"*, and so do the data dirs | 8 min (7.4 min of it `docker load`) |
| 9 | Install (run 3, D‑1+2 fixed) | wizard **Install** | ❌ **FAILED at 75 %** — DEFECT‑3 (`vmauth` image absent from the bundle). D‑2's stage now passes: *"✓ provisioning the Postgres app-state role"* | 5 min |
| 10 | Install (run 4, D‑1+2+3 addressed) | wizard **Install** | ❌ **FAILED at 83 %** — DEFECT‑6 (`data/tls/services` claimed by Docker as root). D‑3's blocker is gone: the whole stack came up, 22 containers, `netops-vmauth-1` started, 48 Postgres migrations applied | 13 min |
| 11 | Install (run 5, all five fixed) | wizard **Install** | ✅ **COMPLETE** — Done screen: *all services healthy (held stable through a re-check) · ingress answered end to end · administrator login verified* | **16 min 39 s** |
| 12 | Validate | see §5 | see §5 | ~6 min |
| 13 | Add-on `enable self-monitoring` → `disable` | `./install-correlix.sh` | see §5 | 3 min 55 s to enable |

Each failure was diagnosed, fixed at the source, and the **same wizard step
re-run** to prove the fix — which is why there are five runs rather than one.
Every one of the five failures was in the installer, not the host: the host
itself passed every prerequisite check on the very first attempt.

---

## 3. The prerequisite check, as the customer meets it

The owner asked to prove the prerequisite check is the **first** thing a
customer meets on both paths, and to list every check with its outcome. It is,
on both paths, and it is more thorough than expected — with exactly one real gap, now closed
(DEFECT‑4).

**A naming correction worth recording:** `scripts/preflight-install.py` is
**not** the host prerequisite checker. It is a *static* compose ↔ `install.py`
drift gate that runs in CI without Docker (does a fresh `install.py` provision
every env var, bind-mount and data dir the compose stack requires). The host
prerequisite check lives in two places that share one source of truth:

* `preflight()` in `install-correlix.sh` — the **hard gate** on both paths.
  Nothing is mutated until it passes; the GUI runs it as install stage 1.
* `prepare-host.sh --check` — the prerequisite inventory, called *by*
  `preflight()`, and rendered directly on the wizard's Readiness screen.

### What actually ran on this host, and what it said

Screenshot: `shots3/01-readiness.png` (the Readiness screen renders all of it
before the customer can press anything).

| # | Check | Where | Result on 10.70.245.123 |
|---|---|---|---|
| 1 | CPU architecture is x86_64 | `preflight()` / Readiness | ✅ x86_64 |
| 2 | OS is Ubuntu ≥ 22.04 / Debian ≥ 12 | `preflight()` / Readiness | ✅ Ubuntu 22.04.5 LTS — "supported" |
| 3 | CPU count ≥ 2 (4 recommended) | `preflight()` / Readiness | ✅ 4 cores |
| 4 | RAM ≥ 8 GB (16 recommended) | `preflight()` / Readiness | ✳️ 15.6 GiB — "≥ 16 GiB recommended" |
| 5 | Docker root disk ≥ 20 GB (40/100 recommended) | `preflight()` / Readiness | ✳️ 77–82 GB free — "≥ 100 GB recommended" |
| 6 | `python3` present | `preflight()` | ✅ |
| 7 | Docker engine installed | `preflight()` / Readiness | ✅ Docker 29.1.3 |
| 8 | Docker **daemon reachable** by this user | `preflight()` / Readiness | ✅ "daemon healthy" |
| 9 | Compose **v2** plugin | `preflight()` / Readiness | ✅ 2.40.3 |
| 10 | `zstd` present (bundle installs) | `preflight()` | ✅ |
| 11 | Dashboard port free | `preflight()` / Readiness | ✅ "Port 8000 free" |
| 12 | `vm.max_map_count` ≥ 262144 (OpenSearch) | `preflight()` (self-heals via sudo, else names the exact fix) | ✅ already 262144 |
| 13 | docker + compose v2 working | `prepare-host --check` | ✅ |
| 14 | `zstd`, `python3`, `curl` | `prepare-host --check` | ✅ |
| 15 | Clock NTP-synchronized | `prepare-host --check` / Readiness | ✅ |
| 16 | `daemon.json` baseline (live-restore, log caps, no-new-privileges) | `prepare-host --check` | ✅ |
| 17 | Service account `correlix` | `prepare-host --check` | FIX → **FIXED** by `prepare-host.sh` |
| 18 | Invoking user in the `docker` group | `prepare-host --check` | ✅ |
| 19 | Kernel settings (max_map_count, overcommit, swappiness, UDP rmem, net hardening) | `prepare-host --check` | ✅ |
| 20 | `unattended-upgrades` installed | `prepare-host --check` | ✅ |
| 21 | `install-correlix` alias on PATH | `prepare-host --check` | FIX → **FIXED** by `prepare-host.sh` |
| 22 | Bundle integrity (`SHA256SUMS`, signature when present) | `verify_bundle` before anything is loaded | ✅ "bundle integrity verified" |
| 23 | Scaffold — 44 required paths ship | `install.py` | ✅ |
| 24 | **Device-facing ports free** (514, 5514, 2055, 4739, 6343, 162, 11019) | **added by this acceptance** — DEFECT‑4 | ✅ all free on this host |

Row 24 is the one prerequisite the stack genuinely needs that nothing checked.
It is now checked; see DEFECT‑4.

**On a host without Docker:** the audit reports
`FIX Docker Engine + Compose v2 not working (will install docker-ce from
Docker's official repo)` and `preflight()` refuses to install — it never
proceeds to a confusing later failure. `sudo ./prepare-host.sh` then installs
docker-ce from Docker's official GPG-verified apt repo. That is the documented
customer sequence and the README says so. It could not be exercised as an
*install* on this host because the owner's instruction was to leave Docker
alone; the refusal path and the FIX wording were read and verified in source.

---

## 4. Defects

Twelve, of which **four were hard blockers that made a default fresh install
impossible**. Nine are fixed here; three are filed. Not one of them was a
problem with the host — the host passed every prerequisite check on its first
attempt. They were all in the installer, and every one of them is only
reachable on a *fresh, air-gapped, non-root, TLS-default* install: exactly the
combination no CI leg exercises and every customer does.

| # | Severity | What | Status |
|---|---|---|---|
| 1 | CRITICAL | non-root chown helper unusable offline (digest ref + load ordering) — killed every TLS install at 42 % | FIXED |
| 2 | CRITICAL | Postgres first-boot race — `pg_isready` answers on the entrypoint's temporary server | FIXED |
| 3 | HIGH | `vmauth` — started by every default TLS install — is not in the base archive | BUILD FIXED · **bundle must be rebuilt** |
| 4 | MEDIUM | only the dashboard port was pre-checked; the eight device-facing ports were not | FIXED |
| 5 | MEDIUM | the wizard offered a NetBox add-on that guarantees a failed install | FIXED |
| 6 | CRITICAL | Docker claims `data/tls/services` as root → the API can never mint SVIDs | FIXED |
| 7 | MEDIUM | the sign-in URL is wrong in Settings, Review **and** on the Done screen | FIXED (messaging half) |
| 8 | MEDIUM | the shipped `preflight-install.py` exits 1 on every installed appliance | FIXED |
| 9 | HIGH | `disable self-monitoring` leaves `kafka-exporter` running and reports success | FIXED |
| 10 | MEDIUM | `deploy-qualify.sh` fails by construction when run right after an install | FILED |
| 11 | HIGH | `uninstall --purge` cannot delete the data it says it deletes | FILED |
| 12 | LOW | `uninstall` leaves orphaned anonymous volumes | FILED |

**The pattern worth naming.** Defects 1, 3 and 6 are one family: *a step that
needs something Docker has not put on the host yet, on a machine with no
internet*. The codebase already knew this class — `write_offline_override()`
encodes it for compose, `cmd_uninstall()` for `docker rmi`, and the `seal`
entry in `BASE_PROFILES` was added for exactly it. Each time the fix was
applied to the instance and not the class, so the next new service
(`vmauth`) walked straight back into all three. The tests added here tie the
lists together — `BASE_PROFILES` to `TLS_EXTRA_PROFILES`, the helper ref to
what is actually local, the SVID dirs to what compose mounts — so the class is
closed rather than the instance.


### DEFECT‑1 — CRITICAL — a fresh air-gapped install fails 100 % of the time with the default TLS posture · **FIXED**

**Symptom.** Install run 1 died at 42 %, at the *first* stage that touches the
host, with:

```
cannot set ownership of …/nginx/certs/privkey.pem to 101:101.
  direct chown failed: [Errno 1] Operation not permitted
  docker helper fallback failed: Unable to find image
    'postgres:16-alpine@sha256:16bc17…' locally
docker: failed to resolve reference "docker.io/library/postgres@sha256:16bc17…":
  … tls: failed to verify certificate: x509: certificate signed by unknown authority
```

**Root cause — two compounding bugs.**

1. `install.py`'s `_docker_chown()` helper (the only way a **non-root**
   installer — the documented, recommended way to install — can chown a file to
   a service uid) referenced the helper image **by digest**.
   `docker load` restores an image by **tag**; a registry digest is pull-time
   metadata the archive never carries. This is the same lesson the codebase
   already encodes twice — in `write_offline_override()` for compose, and in
   `cmd_uninstall()` for `docker rmi` — but not here. So docker reached for
   `registry-1.docker.io`, which an air-gapped appliance must never do and
   which fails outright with no egress.
2. Worse, the ordering made it unwinnable: `load_bundle()` ran *after*
   `ensure_ingress_cert()` and `ensure_data_dirs()`, so at that moment **no
   image existed on the host at all**. The fallback had nothing to run.

Both `ensure_ingress_cert()` (uid 101 ingress key) and `ensure_data_dirs()`
(per-service uids) depend on that fallback, so every non-root install with the
**default** TLS posture died here. The comment above the helper —
*"on any install that reaches 'up' this image is on the host anyway"* — was
simply not true at the point it was called.

**Fix** (`scripts/install.py`):
* `_chown_helper_ref()` resolves the helper against what is actually on the
  host — digest-pinned when local (online install), the docker-load'ed **tag**
  when only that is (offline bundle), digest otherwise so an online host still
  pulls a pinned image rather than a floating tag.
* `load_bundle()` moved ahead of the first step that can need the helper.

**Proof of fix.** Run 2, same wizard, same host, the stage that failed now
reports:

```
[info] nginx ingress TLS key (privkey.pem): ownership repaired to 101:101 via
       helper container (direct chown unavailable: [Errno 1] Operation not permitted…)
@CX@ {"id":"tls-env", … "status":"ok","elapsed_s":9.777}
```

**Tests** (`tests/test_install_data_dirs.py`): helper-ref preference on a
digest-local host, on a docker-load'ed host and on a host with neither; that
the two refs name the same image; the end-to-end offline chown shape; and a
source-order assertion that `load_bundle` precedes both chown-dependent steps.

---

### DEFECT‑2 — CRITICAL — Postgres first-boot race fails the install · **FIXED**

**Symptom.** Install run 2 died at 67 %:

```
the app-state role could not be provisioned: provisioning failed: psql: error:
connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed:
FATAL:  the database system is shutting down.
```

**Root cause.** `bootstrap_app_state_role()` starts `postgres` alone, waits for
`pg_isready`, then runs the provisioning `psql`. But the official postgres
entrypoint's **first boot** is: `initdb` → start a **temporary** server on the
unix socket to run its init scripts → **shut that down** → start the real
server. `pg_isready` answers "ready" against the *temporary* server, so the
probe returns immediately and the very next `psql` lands in the shutdown
window. A readiness probe cannot distinguish the two servers; only the fresh
install hits it (a re-run finds an initialised data dir and never restarts),
which is exactly why it survived to a customer-facing acceptance.

**Fix** (`scripts/install.py`): `_provision_app_state_role_with_retry()` —
a bounded retry (180 s, exponential backoff capped at 10 s) over a
`_PG_TRANSIENT` classifier covering *shutting down · starting up · not yet
accepting connections · connection refused · server closed the connection*.
A **non**-transient failure (bad password, syntax error) is surfaced
immediately — three minutes of retries would only delay the message the
operator needs. §9's "retry with backoff", applied where it was missing.

**Tests** (`tests/test_install_data_dirs.py`): each transient string is
retried and succeeds; a real authentication failure is *not* retried; the loop
is bounded and terminates; a first-attempt success never sleeps.

---

### DEFECT‑3 — HIGH — the base archive is missing an image every default install starts · **BUILD FIXED, BUNDLE MUST BE REBUILT**

**Symptom.** Install run 3 died at 75 %, during bring-up:

```
Error response from daemon: failed to resolve reference
  "docker.io/victoriametrics/vmauth:v1.101.0": … tls: failed to verify certificate
[warn ] start pass 1 incomplete (slow first-boot health) — waiting 30s and retrying…
docker compose up did not converge after 3 attempts (last exit 1)
```

**Root cause.** TLS/mTLS is the **default** posture, and `install.py`'s
`TLS_EXTRA_PROFILES = ("seal", "security", "vmauth")` switches all three
profiles on for every default install. But `make-installer.sh` cut the base
image set with

```bash
BASE_PROFILES=(--profile embedded-bus --profile prober --profile seal)
```

`security`'s only image (`netops-opensearch:2.16.0-slim`) is already in the
archive for another reason, so it went unnoticed — but `vmauth`'s
(`victoriametrics/vmauth:v1.101.0`) is unique to that profile and therefore
**never entered the bundle**. `MANIFEST` confirms it: `victoria-metrics` and
`vmalert` are listed, `vmauth` is not.

This is precisely the class the `seal` profile was added to that array for.
`tests/test_install_addon_packs.py::test_the_sealing_sidecar_is_declared_not_inherited`
even records the earlier instance in its own docstring —
*"A CI runner has no .env, so the bundle it cut had no sealing sidecar image
and its --tls install could not start."* The fix was applied to the instance,
not the class; two more profiles were added to `TLS_EXTRA_PROFILES` afterwards
and nothing tied the two lists together.

**Fix** (`scripts/make-installer.sh`): `BASE_PROFILES` now names `security` and
`vmauth` as well.

**This one cannot be fully proven by a re-run**, because the shipped
`correlix-2026.09.06-g9967eaf5` archive was cut before the fix. To finish the
acceptance, the single missing image was `docker save`d from the build host and
loaded on the target — putting the host in exactly the state a bundle built
**with** this fix produces — and the install re-run from there (run 4). The
build change is what ships; **the 2026-09-06 bundle must be rebuilt before it
goes to a customer.** (`tests/test_download_folder.py::test_bundle_is_not_stale_against_head`
independently reports that bundle as lagging HEAD, so a rebuild was due anyway.)

**Tests** (`tests/test_download_folder.py`):
`test_base_profiles_cover_a_default_tls_install` ties `BASE_PROFILES` to
`install.py`'s `TLS_EXTRA_PROFILES` so the two lists can never drift again, and
`test_addon_profiles_are_never_also_base_profiles` guards the other direction
(a profile that is both "always shipped" and "optional pack" makes the pack
resolve to no images).

---

### DEFECT‑4 — MEDIUM — only the dashboard port was checked; the eight device-facing ports were not · **FIXED**

`docker-compose.yml` publishes ten host ports; `preflight()` checked exactly
one of them (`BASE_PORT`, 8000). A busy device-facing port — a host `rsyslog`
on 514, an `snmptrapd` on 162, another collector on 2055 — therefore surfaced
*ten minutes into the install* as docker's
`Bind for 0.0.0.0:514 failed: port is already allocated`: precisely the
"fails later with a confusing error" the owner asked to eliminate.

**Fix** (`scripts/install-correlix.sh`): a `STACK_INGEST_PORTS` registry and
`check_ingest_ports()`, called from `preflight()` on **fresh installs only**
(a running Correlix's own listeners are not a conflict). It reads the kernel's
listening table via `ss` — UDP cannot be probed by connecting, and five of the
eight ports are UDP — folds every local address down to `proto:port`, and stops
the install naming each busy port, what it is *for* in plain language, and the
environment variable that moves it. Missing `ss` warns by name rather than
silently skipping (§16.1).

Verified against a host that *does* have the stack running (this dev box):

```
DIE: Another service already listens on port(s) Correlix must publish:
  514/tcp — syslog from your devices
  5514/udp — syslog from your devices (move it with SYSLOG_PORT=<port> in the environment)
  2055/udp — NetFlow (move it with NETFLOW_PORT=<port> in the environment)
  …
```

**Tests** (`tests/test_ingest_contract.py`): the registry is derived from
compose and must cover every published host port (and carry no stale entry that
could block an install for no reason); the check is wired into `preflight()`;
it is fresh-install-guarded; and it never silently skips.

---

### DEFECT‑5 — MEDIUM — the wizard offered an add-on that guarantees a failed install · **FIXED**

The Deployment step offered a fourth add-on, **"NetBox (bundled)"**, and
`knownAddons` in `main.go` accepted `netbox` as valid. But `addon_spec()` in
`install-correlix.sh` has no `netbox` case, and `make-installer.sh` excludes
netbox from customer bundles *by construction* ("Lab/dev profiles (mock-*,
netbox, flowgen) stay out of client bundles"). So ticking that one box wrote a
profile the installer then rejected with
`Unknown add-on in config: 'netbox'` — a guaranteed failed install, one click
away, in the shipped GUI.

**Fix**: the checkbox and its `addons.push('netbox')` removed from `ui.html`;
`netbox` removed from `knownAddons`.

**Tests** (`scripts/installer-gui/hardening_test.go`):
`TestKnownAddonsMatchInstallerRegistry` parses `addon_spec()` out of
`install-correlix.sh` and asserts the two registries are equal in **both**
directions, so adding a pack in one place and not the other fails the build;
`TestWizardOffersOnlyImplementedAddons` asserts the served HTML never offers an
add-on the profile validator rejects.

---

### DEFECT‑6 — CRITICAL — Docker claims `data/tls/services` as root, so the API can never mint · **FIXED**

**Symptom.** Install run 4 got furthest of all — the whole stack up, 22
containers, Postgres migrations applying — and then failed at 83 %, after the
full 300-second mint budget:

```
{"component":"tls","level":"warn","msg":"service SVID key mode widened by TLS_SERVICE_KEY_MODE …"}
2026/09/07 03:45:10 internal CA: tls ca: svid registry: api: mkdir /data/tls/services/api: permission denied
[fail ] the api did not mint the full identity set in time
```

On the host:

```
drwxr-xr-x 3 0    0    data/tls/services          <-- root
drwxr-xr-x 2 0    0    data/tls/services/vmauth   <-- root
drwxrwxr-x 6 1000 1000 data/tls                   <-- the api's, as intended
```

**Root cause.** `ensure_data_dirs` **does** chown `data/tls` to the api's
runtime uid, recursively, and the code comment even names this exact failure.
But on a *fresh* install `data/tls` is **empty** at that moment, so the
recursive repair has nothing to repair. Docker then creates a missing
bind-mount **source** as **root** the instant the first service that mounts one
starts — and `vmauth` mounts `data/tls/services/vmauth`. So Docker created
`data/tls/services/` as root during phase A, and the api (user-mapped,
`cap_drop:ALL`) could not create `services/api` beside it.

This was hidden behind DEFECT‑3: until `vmauth` actually shipped and started,
nothing mounted anything under `data/tls/services` during phase A, so nothing
created it as root.

`preflight-install.py` had flagged the precise path as a warning —

```
— data dir not pre-created by install.py (docker will, as root): ../../data/tls/services/vmauth
```

— under a comment reasoning that *"docker auto-creates a missing bind-mount dir
(as root), so this doesn't hard-break a fresh install ... Warn, don't block."*
For this path it does hard-break it: the api is not merely writing **into** a
root-owned directory, it has to create **siblings inside** it.

**Fix** (`scripts/install.py`): `ensure_data_dirs` pre-creates
`data/tls/services` **and every `data/tls/services/<name>` a compose file
bind-mounts**, owned by the api's runtime uid. The child list is *derived* from
`docker-compose.yml`/`compose.tls.yml` (16 today) rather than restated, so a new
TLS-fronted service cannot reintroduce the race by being added in one place
only.

**Tests** (`tests/test_install_data_dirs.py`): the derivation finds the vmauth
mount; `ensure_data_dirs` creates and chowns the services root and every derived
child to the api uid; and a source-order guard that `ensure_data_dirs` still
precedes the first `compose_up` — pre-creation is worthless if Docker gets there
first.

---

### DEFECT‑7 — MEDIUM — the sign-in URL the wizard shows is wrong, in both places · **FIXED**

The install succeeded. The URL it handed the operator did not work.

| What the wizard said | What actually answers |
|---|---|
| Settings + Review: `https://10.70.245.123:8000` | connection failed — 8000 has no TLS listener |
| Done screen: `https://localhost/` | only resolves on the server itself |
| — | **`https://10.70.245.123/` → 200** |

Under TLS the ingress moves to 443; the Deployment step's `port` field is the
**plaintext base port**. And `install.py` cannot know which address the
operator reached the host on, so it prints `localhost` — which the GUI then
rendered verbatim to a remote browser.

The compounding part: `http://10.70.245.123:8000/` **does** answer with the
full dashboard, and `POST /api/auth/login` over it returns 401 rather than a
refusal — so the operator's natural next move after the https URL fails is the
plaintext one, carrying the generated admin password in the clear, on an
install that advertised a *"Full TLS/mTLS mesh"*.

**Fix** (`scripts/installer-gui/ui.html`): under TLS the wizard quotes
`https://<host>/`; the Done screen rewrites a loopback host to
`location.hostname`, passing an unparseable URL through untouched.

**Tests**: the TLS branch must quote the default https port and the plaintext
branch must still quote the chosen base port (Review reuses the same element,
so the two screens cannot disagree); the Done screen must localize a loopback
host and must never blank a URL it cannot parse.

**Filed, not fixed — the other half.** nginx still *publishes* plaintext
:8000 after a `--tls` install. `compose.tls.yml` already documents this as
deliberate-for-now, and names this exact acceptance's finding as the
precondition for closing it:

> the LAB dropped the plaintext :8000 host ingress (`ports: !override` → 443
> only). The shipped variant keeps 8000 **DELIBERATELY for now**: install.py's
> printed URLs/readiness messaging are not TLS-aware yet — dropping it here
> would strand fresh `--tls` installs on dead http URLs. **Close both together
> (installer messaging + this drop).**

This acceptance delivered the messaging half for the graphical path. Dropping
the port publish — and making `install.py`'s terminal-path URL TLS- and
host-aware — is a customer-visible change that deserves its own tracker row.

---

### DEFECT‑8 — MEDIUM — the installer's own preflight failed on every installed appliance · **FIXED**

`preflight-install.py` ships inside the customer bundle. On the installed host
it exited **1**:

```
✗ docs/security/transport-inventory.yaml missing (SEC-001.1 as-built inventory)
preflight-install: FAILED — a clean install.py would miss something the stack needs
```

`make-installer.sh` deliberately leaves the security-design docs out of the
customer tree, so the gate was failing on the absence of a file the customer
was never sent, and explaining it in terms of an internal invariant they cannot
act on. Anyone following `TROUBLESHOOTING.md` would have found a red FAILED on
a perfectly healthy appliance.

**Fix**: the check now distinguishes an extracted customer tree from a git
checkout using the signal the script already computes for its scaffold check —
no git → warn and skip; a git checkout missing the inventory → still a hard
failure, because that is the drift the gate exists to catch.

Also fixed alongside: the informational migrations line pointed at
`src/backend/migrations`, a path that has not existed for a long time, so it
reported **"0 present"** on every run in the repo *and* in the bundle. It now
reads the real directory — 49 migrations, latest `0047_dem_incident_promotions.sql`.

**Proven**: `preflight-install.py` now exits **0** on the installed appliance,
and still exits 0 in the repo with the inventory checks actually running.

---

### DEFECT‑9 — HIGH — `disable self-monitoring` left a container running and reported success · **FIXED**

```
$ ./install-correlix.sh disable self-monitoring
✔ self-monitoring disabled (its images and data were kept).
$ docker ps | grep exporter
netops-kafka-exporter-1   Up 5 minutes
```

The `self-monitoring` compose profile has **four** members — `grafana`,
`cadvisor`, `node-exporter` and `kafka-exporter` — but `addon_spec()` listed
only the first three, and `cmd_disable` stops exactly what the registry names.
A customer who turned the add-on off kept a container running indefinitely,
with the product telling them otherwise.

The omission is only half of it. The stop was
`compose ... stop $svcs >/dev/null 2>&1 || true` — the cardinal never-swallow
rule, in the one place that could have caught this on the day it was
introduced.

**Fix**: `kafka-exporter` added to the registry; and `cmd_disable` now captures
the output instead of discarding it and **verifies** — after stopping, it
checks `docker ps` for anything belonging to the add-on and fails loudly,
naming the leftovers and how to stop them, rather than printing success over
them.

**Proven on the host**: enable → four containers up including
`kafka-exporter`; disable → all four gone; core stack intact (20 containers),
dashboard still 200.

**Tests**: the registry must name every service in its compose profile — and
no service that is not in it — for every add-on, parsed from compose and from
`addon_spec` so the two cannot drift; and `cmd_disable` must verify before it
claims success, with the check ahead of the success line.

---

### DEFECT‑10 — MEDIUM — `deploy-qualify.sh` fails by construction on a fresh install · **FILED**

Q6 greps the last **20 minutes** of container logs for bootstrap-class Kafka
errors. But the installer necessarily starts the stack (TLS phases A and B)
*before* it applies the Kafka ACL matrix, so a fresh install always writes
exactly those lines into its own logs:

```
04:00:09  vector-router   Message consumption error: Group authorization failed
04:02:21  correlation     TopicAuthorizationFailedError: netops.probes
04:03:21  correlation     TopicAuthorizationFailedError: netops.controller_events
          ^ last one — the ACL stage completed at 04:05:08
```

After 04:03 the errors stop and `netops-correlation` joins its group and stays
there. Run immediately after an install — which is exactly when an operator
runs it — the gate reports **NOT QUALIFIED** on a stack that is working. Re-run
after the window passed, Q6 **PASSES**, which is the proof.

It should bound its lookback to the ACL-application timestamp (or the newest
container start) rather than a fixed wall-clock window. Filed rather than
fixed: narrowing a gate's window is a judgement call about what it is guarding,
and this gate was written around two real incidents.

**Related, and worth its own line:** Q1/Q2/Q3 — correlation consumer joined,
router consumers joined, lag draining, the three checks that matter most — read
`kafka_consumergroup_*`, which only exists when `kafka-exporter` runs, and that
lives behind the optional `self-monitoring` profile. On the **default core
install** the script correctly SKIPS them and says so with the remedy, but the
consequence is that **`deploy-qualify.sh` cannot fully qualify a default
install**: its headline guarantee needs an add-on. Either the exporter belongs
in the base appliance, or the packaging should say that qualification requires
the add-on.

---

### DEFECT‑11 — HIGH — `uninstall --purge` cannot delete the data it says it deletes · **FILED**

`cmd_uninstall()` in `install-correlix.sh` ends with a plain
`rm -rf "$ROOT/data"`. The installer runs unprivileged, but the store data is
written by containers as *their* uids (postgres 999, clickhouse 101,
victoria root), so the `rm` fails with 295 × `Permission denied`, the command
**exits 1**, and 6.3 MB of `data/{postgres,clickhouse,victoria}` survives —
after the script has printed
`Purging data, configuration, and loaded images…`.

The fix is already written **four lines below**, in `cmd_reset_demo()`:

```bash
docker run --rm -v "$ROOT/data:/data" alpine sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} +'
```

Not fixed here: it is outside the bounded context of this acceptance (a
customer-visible uninstall behaviour change deserves its own change and its own
test), and it did not block the install. It should be a tracker row: *make
`cmd_uninstall` wipe `data/` through the same helper-container path
`cmd_reset_demo` already uses, and fail loudly if it still cannot.*

---

### DEFECT‑12 — LOW — `uninstall` leaves orphaned anonymous volumes · **FILED**

`cmd_uninstall()` runs `compose down --remove-orphans` without `-v`, so the 10
anonymous volumes the stack creates survive an uninstall — including a
`--purge` one. They were 0 B here, so the impact is clutter rather than disk,
but "purge" should mean purge. Same tracker row as DEFECT‑11.

---

---

## 5. Validation of the installed stack

Run 5 finished in **999 s (16 min 39 s)** and the wizard's own Done screen
reported all three of its verifications green:

> ✓ All services healthy — held stable through a re-check
> ✓ Ingress answered end to end
> ✓ Administrator login verified

Installer stage timings (`@CX@ timing`, run 5):

| Stage | | Stage | |
|---|---|---|---|
| prereq | 0.1 s | up-a (TLS phase A) | 14.5 s |
| scaffold | 0.0 s | mint (SVIDs) | **25.0 s** |
| env | 0.0 s | up-b (fail-closed mesh) | 265.6 s |
| sizing | 0.0 s | kafka-acls | 221.5 s |
| **bundle (`docker load`)** | **344.3 s** | status | 0.8 s |
| tls-env | 0.0 s | bootstrap-os | 36.9 s |
| data-dirs | 87.8 s | | |

`docker load` is a third of the wall clock on this box, and it is re-read in
full on every re-run — worth knowing before anyone times an install.

### What was checked afterwards

| Check | Result |
|---|---|
| `docker compose ps` | **19/19 services running.** 12 report `healthy`; the other 7 (`api`, `frontend`, `gnmic`, `goflow2`, `nginx`, `prober`, `vmauth`) declare no healthcheck, so they show a blank health column — running, not unhealthy. Nothing restarting, nothing exited non-zero. |
| Dashboard over TLS | `https://10.70.245.123/` → **200**, `<title>Correlix — Network Observability</title>` |
| **Administrator sign-in** | **works** with the generated password from `deployment/docker/.env` — a 244-char bearer token, `{"username":"admin","role":"admin","auth_source":"local","mfa_enabled":false}`. (The first attempts used the wrong `.env` key and tripped the lockout — 3 attempts / 900 s — which is itself the brute-force protection doing its job.) |
| **`/api/registries/status`** | `configured_backend: postgres` · `persistence: persistent` · `backend_healthy: true`, and all three registries (`applications`, `service_catalog`, `business_services`) report `active_backend: postgres`, `persistence: persistent`, `healthy: true`. **The tracker-245 default landed exactly as specified — no silent downgrade to files.** |
| `/api/system/licence` (authenticated) | **200** |
| Fonts | the served stylesheet (`/assets/index-DIJZkMsD.css`, 304 KB, `@font-face` present) references six `.woff2` files; **all six return 200 `font/woff2`** — Inter (2), JetBrains Mono (2), Space Grotesk (2), 15–133 KB each |
| Ask Iris marker | present in the served `Troubleshooting-CAc757iZ.js` chunk (57 KB) — it is code-split, so it is not in the entry bundle |
| Licences page | `/licenses/` → **200** (60 KB HTML); `/licenses/THIRD_PARTY_LICENSES.md` → **200** (42 KB) |
| `/api/system/licence` | 401 without a token — correctly gated |
| Installer preflight on the host | **exit 0** after DEFECT‑9 was fixed (it exited 1 on every installed appliance before — see below) |
| Licence / notice artefacts | all present exactly where `README.txt` says: `LICENSE` (1.7 KB), `LICENSING.md` (25 KB), `LICENSES.md` (44 KB), `NOTICE` (11 KB), `LICENSES/` (Apache-2.0 + Correlix-Enterprise), `source-offer/` (36 corresponding-source archives), `docs/index.html`. **There is no machine-readable SBOM in the bundle — and the README does not claim one**, so this is an observation, not a defect against the documentation. |
| Add-on `enable self-monitoring` | **3 min 55 s**, exit 0 — loaded the pack and started `grafana`, `cadvisor`, `node-exporter`, `kafka-exporter` |
| Grafana behind the gateway | `https://10.70.245.123/grafana/` → **403** (the platform-owner gate, as designed) and nginx resolves `grafana` to its container — i.e. wired and gated, not 502 |
| Add-on `disable self-monitoring` | **left `kafka-exporter` running while reporting success — DEFECT‑9**, fixed and re-proven: enable → 4 containers up, disable → all 4 gone, core intact (20 containers), dashboard still 200 |

### `deploy-qualify.sh`

Two things the acceptance learned here, both about the gate rather than the
stack.

**Q6 fails on a fresh install by construction — DEFECT‑10 (MEDIUM, filed).**
Q6 greps the last **20 minutes** of container logs for bootstrap-class Kafka
errors. But the installer necessarily starts the stack (TLS phase A and B)
*before* it applies the Kafka ACL matrix, so a fresh install always writes
exactly those lines into its own logs:

```
04:00:09  vector-router   Message consumption error: Group authorization failed
04:02:21  correlation     TopicAuthorizationFailedError: netops.probes
04:03:21  correlation     TopicAuthorizationFailedError: netops.controller_events
          ^ last one — the ACL stage completed at 04:05:08
```

After 04:03 the errors stop, `netops-correlation` joins its group
(`Stabilized group netops-correlation generation 2`) and stays quiet. So the
check is correct for a steady-state deploy and wrong for the ten minutes after
an install: it reports **NOT QUALIFIED** on a stack that is working. It should
bound its lookback to the ACL-application timestamp (or the newest container
start), not to a fixed wall-clock window. Filed rather than fixed — changing a
gate's window is a judgement call about what it is guarding.

**Q1/Q2/Q3 cannot be evaluated on a core-only install.** The three checks that
matter most — correlation consumer joined, router consumers joined, lag
draining — read `kafka_consumergroup_*`, which only exists when
`kafka-exporter` is running, and that lives behind the optional
`self-monitoring` profile. On the default core install the script correctly
SKIPS them and says so, with the remedy. Worth stating plainly in the report
because it means **`deploy-qualify.sh` cannot fully qualify a default install**
— the add-on is a prerequisite for its headline guarantee. (This acceptance
enabled the add-on and re-ran it for exactly that reason.)

**Re-run once the window had passed and the add-on was on — the real verdict:**

```
  passed: 9 · failed: 0 · skipped(required): 1 · skipped(advisory): 0 · advisory: 2
```

| Check | Result |
|---|---|
| B1 kafka ACL matrix | PASS — 72 ACL entries live (≥ 40 floor), including the load-bearing vector-router grant |
| B2 kafka-init topics | PASS — all 21 canonical topics present |
| B4 router lanes writable | PASS — 9 lanes covered by `netops_writer`, 9 templates present |
| **Q1 correlation consumer joined** | **PASS** — `kafka_consumergroup_members{consumergroup="netops-correlation"} = 1` |
| **Q2 router consumers joined** | **PASS** — 10 `netops-router-*` groups discovered, **all 10 with a live member** |
| Q3 correlation lag draining | SKIPPED — "the series does not exist (yet)". Correct: a device-less fresh install has produced no lag to drain |
| Q4 vector-aggregator emitting | PASS — 6 700 events/5 min |
| Q5 vector-router emitting | PASS — 7 899 events/5 min |
| **Q6 bootstrap-class Kafka errors** | **PASS** — none in the last 20 min, which is the proof that the earlier failure was the install's own bootstrap noise and nothing more |
| Q7 api serving | PASS |
| Q8 alert delivery heartbeat | ADVISORY — fresh, last webhook 21 s ago: vmalert evaluated a rule and the api received it (the end-to-end proof the alerting chain is wired) |
| Q9 opensearch cluster status | ADVISORY — **GREEN** |

Verdict `INCOMPLETE` rather than `QUALIFIED` only because Q3 could not be
evaluated, and the script is deliberate about not conflating "we could not
check" with "it passed". **Nothing failed.** The engines are demonstrably
consuming and producing: this stack is doing work, not merely running.

## 6. Screenshots

Every wizard step of all five runs, full-page PNG, captured headlessly from the
dev box against `https://10.70.245.123:8800` (`ignoreHTTPSErrors` for the
self-signed setup certificate). Scratchpad root:
`/tmp/claude-1000/-home-rao-Projects-NetOps-Observability/c1877382-7bdb-4c71-b803-462d023d52bf/scratchpad/accept/`

| Step | Run 1 (42 %) | Run 2 (67 %) | Run 3 (75 %) | Run 4 (83 %) | Run 5 (final) |
|---|---|---|---|---|---|
| 01 Readiness | `shots/01-readiness.png` | `shots2/01-readiness.png` | `shots3/01-readiness.png` | `shots4/01-readiness.png` | `shots5/01-readiness.png` |
| 02 Prepare host | `shots/02-prepare-host.png` | `shots2/02-prepare-host.png` | `shots3/02-prepare-host.png` | `shots4/02-prepare-host.png` | `shots5/02-prepare-host.png` |
| 03 Deployment | `shots/03-deployment.png` | `shots2/03-deployment.png` | `shots3/03-deployment.png` | `shots4/03-deployment.png` | `shots5/03-deployment.png` |
| 04 Discovery | `shots/04-discovery.png` | `shots2/04-discovery.png` | `shots3/04-discovery.png` | `shots4/04-discovery.png` | `shots5/04-discovery.png` |
| 05 Sizing | `shots/05-sizing.png` | `shots2/05-sizing.png` | `shots3/05-sizing.png` | `shots4/05-sizing.png` | `shots5/05-sizing.png` |
| 06 Settings | `shots/06-settings.png` | `shots2/06-settings.png` | `shots3/06-settings.png` | `shots4/06-settings.png` | `shots5/06-settings.png` |
| 07 Review | `shots/07-review.png` | `shots2/07-review.png` | `shots3/07-review.png` | `shots4/07-review.png` | `shots5/07-review.png` |
| 08 Install | `shots/08-install-started.png` | `shots2/08-install-started.png` | `shots3/08-install-started.png` | `shots4/08-install-started.png` | `shots5/08-install-started.png` |
| Failure screen + log | `shots/09-install-FAILED.png`, `…/10-install-FAILED-log.png` | `shots2/09…`, `shots2/10…` | `shots3/09…`, `shots3/10…` | `shots4/09…`, `shots4/10…` | — |
| Done | — | — | — | — | `shots5/11-done.png` |

`shots3/01-readiness.png` is the one to look at for §3: the whole prerequisite
inventory, rendered before the customer can press anything.

Supporting logs in the same directory:

| File | What it holds |
|---|---|
| `00-survey.log`, `00b-survey-existing.log` | the read-only host survey, before anything changed |
| `02-uninstall.log` | the old install's `uninstall --purge` (and its 295 permission errors — DEFECT‑7) |
| `03-post-uninstall.log`, `04*.log` | what the clean removed and what was left |
| `05-rsync.log`, `06-sha.log` | the 2.1 GB transfer and the 365-file checksum verification |
| `07-prepare-check.log`, `08-prepare.log` | the readiness audit and the host preparation |
| `11-wizard.log` … `23-wizard5.log` | the five Playwright walks, step by step |
| `13-installlog.log`, `18-run2-datadirs.log`, `21-tlsown.log` | the installer's own logs and the ownership evidence for DEFECT‑1 and DEFECT‑6 |
| `24-validate.log`, `25-addon.log` | §5's validation and the add-on exercise |
