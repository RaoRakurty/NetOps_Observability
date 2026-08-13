# Correlix GUI Installer — Finalized Design (2026-08)

**Status:** PROPOSED (owner review) · **Authority for the current state:** `scripts/installer-gui/` (shipped prototype), `scripts/install.py`, `scripts/install-correlix.sh`, `scripts/prepare-host.sh`, `scripts/make-installer.sh`
**Input:** owner-supplied research report *"Correlix GUI Installer for Ubuntu"* (49 pp, `/var/tmp/Correlix_GUI_Researchpdf.pdf`), reconciled against the codebase by two independent analyses (engine inventory + adopt/adapt/reject critique).

---

## 0. Executive summary

The research report recommends an **ephemeral, browser-based local installer backed by a privileged helper, driven by one declarative install specification** — and independently validates an architectural bet this repo has already made: `scripts/installer-gui/` is exactly that shape (Go stdlib-only single binary `correlix-setup` on `:8800`, one-time token, embedded UI, fixed-argv orchestration of `prepare-host.sh` / `install-correlix.sh`), and it already ships in every customer bundle.

So this design is **not greenfield**. It is:

1. **Keep the prototype's doctrine** — the GUI is a *thin orchestrator over the same battle-tested entry points the CLI uses*; it never re-implements install logic, so GUI and CLI cannot drift.
2. **Grow it from a 4-step "check → prepare → install → launch" runner into the research's guided experience** — detect-before-ask readiness, a small set of real decisions (port, add-ons, discovery CIDRs, sizing, TLS), Plan → Review → Apply → Verify, structured progress and actionable failure.
3. **Fix its security gaps** (sudo password over plaintext HTTP on `0.0.0.0:8800` is the worst) before adding any feature.
4. **Delete ~60% of the research's surface** that hedges against runtimes we don't ship (netplan/NIC management, APT repos, Kubernetes/snap adapters, Cockpit, Electron, disk formatting, host identity management).

The user model, quoting the research and keeping it: **"Tell Correlix what this server is for; Correlix determines how to configure Ubuntu."** The installer speaks network-operations language; the backend speaks Ubuntu.

---

## 1. What already exists (the ground truth this design builds on)

| Layer | Artifact | State |
|---|---|---|
| GUI wizard | `scripts/installer-gui/main.go` + embedded `ui.html` + tests | Shipped prototype: token auth, SSE log stream, phase machine `idle→checking→needs-prep\|ready→preparing→installing→installed\|error`, fixed argv, CSP `default-src 'none'`, single-flight, bounded log buffer |
| Customer CLI | `install-correlix.sh` | Menu console (TTY default), `preflight()` (arch/OS/CPU/RAM/disk/port/sysctl gates), bundle `SHA256SUMS` verify, `wait_healthy()` (420 s + 25 s stability re-check), `verify_admin_login()` |
| Engine | `install.py` (~2,100 lines) | .env generation (34 secrets + config blocks), scaffold validation, resource planning (default-ON), TLS two-phase boot, data-dir ownership, compose up ×3 retries, bootstraps |
| Host prep | `prepare-host.sh` | `--check` read-only PASS/FIX audit (13 items); fix mode installs docker-ce, daemon.json, sysctls, service account; optional `--firewall` with the Docker-bypasses-UFW caveat documented |
| Sizing | `resource_planner.py` | Pure-function engine: `detect_host` / `normalize_workload` / `compute_plan` / `plan_txt`, JSON out, refusal path, `--replan` / `--rollback-plan` |
| Upgrade | `update.sh` | Preserves `.env`+data, rebuilds changed images, re-runs bootstraps |
| Bundle | `make-installer.sh` | `SHA256SUMS` + `MANIFEST`, `--core`, lab-leak guards, `correlix-setup` compiled in |

**The research's "Phase A: build the CLI engine + spec" is complete. Its "High-effort" milestones for network transactions and package/runtime adapters are deleted by the Compose-only runtime decision. The remaining project is the wizard itself plus hardening — a Medium project, not the research's multi-quarter program.**

---

## 2. Decisions (adopt / adapt / reject)

### 2.1 Adopted from the research as-is

- **Ephemeral local web installer** as the canonical GUI (not Electron, not Cockpit, not an ISO). Auto-stops after success; idle-session timeout; single session by default.
- **Plan → Apply → Verify; "exit 0 is not success."** "Done" is gated on `wait_healthy` + `verify_admin_login`, surfaced as named health checks.
- **Detect before asking; no blank forms; recommended defaults labeled as such.** The three-state value model (**Detected / Recommended / Policy-locked**) is kept as UI vocabulary.
- **Structured error model** — every failure carries `{code, stage, userMessage, technicalDetail, retriable, logRef}`; never a bare exit code.
- **No `RunCommand`/`ExecuteShell` in any privileged surface — fixed, typed operations only.** Already true in the prototype; promoted to a stated invariant (§3, §8 of CLAUDE.md).
- **Destructive operations get a typed-confirmation gate** distinct from reversible ones (`--rotate-kafka-cluster-id`, `uninstall --purge`, `reset-demo-data`).
- **Offline = stricter validation, not skipped validation.** Bundle signature/checksum verification before anything mutates.
- **Idempotency token on job-creating POSTs** (browser retry must not double-install).
- **Export unattended profile from Review** — secret-free by construction (secrets are generated on-host).
- **Support bundle on failure** (sanitized; new capability).
- **Accessibility floor**: keyboard-complete, visible focus, error text never color-alone, copyable logs, no meaningless spinners. (Full WCAG-audit program deferred.)
- **Firewall honesty**: never claim "firewall configured" around Docker-published ports; UFW opt-in only, and only with the bypass caveat displayed.

### 2.2 Adapted (right idea, Correlix shape)

| Research idea | Correlix shape |
|---|---|
| `install.correlix.io/v1 InstallSpec` YAML dialect | **The spec is the existing flag/.env contract.** Exported profile = small JSON of `install.py`/`install-correlix.sh` flags + sizing inputs, consumed as `install-correlix.sh install --config profile.json`. No parallel schema to drift. |
| Core/Collector/Database/Metrics component graph | **`COMPOSE_PROFILES` + add-on registry.** Presets: *Standard* (default profile set), *Standard + external Kafka* (`--broker-urls`, drops `embedded-bus`); add-on checkboxes: `log-search-ui` (OSD), `self-monitoring` (Grafana/cadvisor/node-exporter), `netbox`, `sso`. TLS extras (`seal`,`security`,`vmauth`) are auto-added, never user-chosen. |
| Netplan / APT / systemd / Compose / kubeadm adapter tree | **Exactly one adapter and it is `install.py`.** |
| `netplan try` safe-apply with reconnect/rollback | **The reconnect pattern, applied to *our* reachability changes**: TLS phase B (http→https flip, full-mesh recreate) and `--port` change. Announce the new URL, heartbeat, confirm-on-reconnect. No auto-rollback claim (phase B recreate is not auto-rollbackable — the recovery is documented, honest, not magic). |
| Management/Discovery NIC roles | **A discovery-CIDR screen.** Correlix discovery is routed SNMP/gNMI, not passive capture. "Which networks should Correlix discover?" → CIDR list, opt-in, with a strong narrow-before-scanning nudge (`ENABLE_SNMP_DISCOVERY`, `SNMP_CIDR_RANGES`). No NIC-role plumbing. |
| Signed compatibility manifest | **`requirements.json`** (min RAM/disk per sizing profile, supported OS families, compose ≥ v2) consumed by preflight — the data already lives in `install-correlix.sh:preflight()`; make it machine-readable. Full signing PKI deferred; v1 integrity = `SHA256SUMS` + published checksum. |
| Upgrade engine | **`update.sh` behind the same GUI** (lifecycle page, v1.1). One engine, as the research demands — already true. |
| Facts API | Thin subset: os-release, arch, CPU/RAM, disk free at data path, docker/compose version, time-sync, port occupancy (`:8800`, `:8000`/`:443`), bundle integrity, `prepare-host.sh --check` results. No netplan state, no dpkg inventory. |

### 2.3 Rejected for v1 (with revival triggers)

| Rejected | Trigger to revive |
|---|---|
| Netplan / host NIC / VLAN / bond / MTU management | Appliance ISO, or a passive-capture collector needing an addressless NIC |
| APT repository management, APT-lock UX | Correlix publishes a package repo |
| Kubernetes/kubeadm/containerd adapter | K8s becomes a certified topology (tracker #114) |
| Snap adapter | — |
| Cockpit plugin | Customer fleet demand |
| Electron desktop installer | Never (concur with the research) |
| Subiquity / appliance ISO | VM/ISO graduates to certified deliverable (`make-vm-image.sh` is the seed) |
| Ansible engine as a milestone | Large-fleet demand (a thin role shelling to the CLI, not an engine) |
| Host identity (hostname/timezone/NTP/DNS config) | Appliance ISO only |
| Dedicated-disk selection + FORMAT flow | Documented dedicated-volume support |
| ACME + CSR certificate flows | Public-DNS deployments ask; import-your-own ingress cert is v1.x |
| Telemetry consent screen | Product telemetry ever exists (then adopt the research's framing verbatim) |
| i18n framework (ICU/CLDR/RTL) | First non-English commitment. Keep the cheap hygiene now: no string concatenation, ISO timestamps in diagnostics |

---

## 3. Architecture (v1)

```
                Operator's browser
                       │  HTTPS (self-signed, fingerprint printed at launch)
                       ▼
        correlix-setup  (Go stdlib, single binary, :8800)
        ├─ one-time token → short-lived HttpOnly session (exists)
        ├─ Facts/preflight API (new)
        ├─ Options → Plan → Review flow (new)
        ├─ Job engine: stages + SSE structured events (upgrade)
        └─ fixed-argv orchestration of:
               │
               ├─ prepare-host.sh --check          (unprivileged, read-only)
               ├─ sudo prepare-host.sh [--firewall] (privileged op #1)
               ├─ install-correlix.sh install …     (docker-group user — NEVER root)
               ├─ install.py …                      (via the above)
               └─ watchdog cron install             (privileged op #2, opt-in)
```

**Privileged vocabulary is exactly three operations** (vs the research's sixteen):
`CheckHost` (read-only), `PrepareHost(firewall: bool)`, `InstallWatchdogCron(config)`.
Everything else — install, TLS phases A+B, bootstraps, rotation, update — runs as the invoking docker-group user. No UDS root-helper daemon in v1: for a 3-verb vocabulary, hardened `sudo -S` (password on stdin, zeroed after use, **over TLS only**) is the right size. **Trigger to build the UDS helper:** the privileged vocabulary growing beyond host-prep (e.g., systemd unit management).

**Invariants (stated, tested):**
- **I1 — No shell string ever contains user input.** Fixed argv only. (Holds today; keep the test.)
- **I2 — Root touches host prep only.** The install itself always runs as the invoking user; `CORRELIX_UID` is stamped from that user. A sudo'd install would stamp `CORRELIX_UID=0` — the GUI must never cause that.
- **I3 — The GUI never re-implements install logic.** Every wizard action maps to an existing CLI verb + flags; anything the GUI can do, `install-correlix.sh` can do headless with the exported profile.
- **I4 — Nothing mutates before Review is confirmed.** Facts/check/plan are read-only.
- **I5 — Secrets never transit to the browser except the one-time credential handover** on the success screen (shown once, never persisted server-side beyond `.env`; recovery = `reset-admin.sh`).

**Dependency rules:** `net/http` + `embed` + stdlib only (CLAUDE.md §6 — no framework, no router, no template lib). The prototype's `go.mod` has zero requires; that stays.

---

## 4. The wizard (screen flow)

Recommended path = **7 screens**. Advanced options disclose contextually per screen — never a separate wizard.

### S1 — Welcome & readiness *(read-only)*
Auto-runs facts + `prepare-host.sh --check` + bundle verification on load:
```
CORRELIX SETUP
Let's get this server ready for Correlix.

✓ Ubuntu 24.04 LTS          Supported        ✓ Docker 27.1 + Compose v2
✓ x86_64 · 16 cores · 64 GB ✓ Clock synchronized
✓ 1.8 TB free at data path  ✗ vm.max_map_count too low   → Prepare host will fix
Installation source: ● Offline bundle 2026.08.0 — Signed ✓ Integrity ✓   ○ Source tree
                                        [ Import profile ]   [ Continue ]
```
FIX items route to **S1b — Prepare host** (the existing sudo step; password over TLS, on stdin, zeroed). The docker-group logout/`newgrp` chicken-and-egg is handled explicitly: preparation completes → "Preparation complete — click Continue to restart setup" → the service re-executes itself with refreshed groups and the browser reconnects (same reconnect pattern as S7-TLS).

### S2 — Deployment options
Port (`--port`, default 8000, live conflict check) · Preset (*Standard* / *Standard + external Kafka* → broker URLs field) · Add-ons (Log search UI, Self-monitoring, NetBox, SSO) · Retention profile (`lab|demo|production|extended`). Advanced: profiles CSV passthrough.

### S3 — Network discovery *(the research's flagship question, Correlix-shaped)*
"Which networks should Correlix discover?" → opt-in toggle + CIDR list with validation and a scan-scope estimate ("10.0.0.0/8 is 16.7M hosts — narrow this"). Also displays (read-only, with copy buttons) the device-side ingest ports the network team must point devices at: syslog 5514, NetFlow 2055, IPFIX 4739, sFlow 6343, traps 1162. Advanced: override those port numbers (`.env` vars exist today).

### S4 — Sizing
Front-end to `resource_planner.py`: auto-detected host (overridable), profile auto-selection with the real numbers shown, optional workload inputs (devices, interfaces, flows/s, syslog EPS, retention days). Renders `plan_txt` (per-component table, TOTAL vs budget, storage projection). A refusal (`SizingError`) renders as a blocker with the planner's own remediation text — the plan-refusal is a feature, not an error to suppress.

### S5 — Security
TLS toggle (default **ON** — research's position, and ours):
```
Transport security     ● Full TLS/mTLS mesh (recommended)   ○ Plaintext (lab only — warning)
Ingress certificate    ● Generate self-signed for this host  ○ I'll replace it after install (docs link)
Correlix administrator  admin  (created on first boot; password generated & shown once at the end)
```
Advanced: none in v1 (import-cert is v1.x; ACME rejected). The screen explains the *consequence* of TLS: "the dashboard will be served at https://…; installation includes a certificate-minting phase."

### S6 — Review *(nothing has mutated yet)*
Business-level summary (port, preset, add-ons, discovery scope, sizing profile, TLS) → preflight roll-up (n checks passed / advisories / blockers) → `[ View technical plan ]` (the resolved flag set + ordered stage list + which steps cross the rollback boundary) → `[ Export unattended profile ]` → **Install**.

### S7 — Installation *(structured progress, not a terminal)*
Stage list mirrors `install.py`'s real stages (prerequisites → scaffold → environment → resource plan → TLS env → data dirs → images → **start (TLS phase A)** → **certificate minting** (sentinel progress, m/7) → **TLS phase B: fail-closed mesh recreate** → bootstraps → health verification). `[ Show technical details ]` reveals the sanitized log stream (exists today).

**The TLS phase-B reconnect moment** (the hardest screen in the product):
```
Switching to encrypted transport…
Every service is restarting under mTLS. Your browser may disconnect.
New address:  https://10.20.30.42/        (was http://…:8000)
[ I have reconnected successfully ]
```
Heartbeat probes the new scheme; partial mint (< 7 sentinels) renders as a **blocker with the missing-sentinel list** — never a blind retry. Failure at any stage → the structured-error card: what happened, "your data has not been deleted" when true, `[ Retry (idempotent) ] [ Diagnostics ] [ Download support bundle ]`.

### S8 — Done
```
Correlix is ready        ✓ 18/18 services healthy · ✓ ingress serves · ✓ admin login verified
Dashboard  https://correlix-dal-01/       Administrator  admin / <shown once>
Keep watch on this stack   [ ntfy topic … ] [ healthchecks.io URL … ]  → installs watchdog cron (sudo, op #3)
[ Download installation profile ]   [ Open Correlix ]
The setup service will stop automatically.
```

---

## 5. Security model (v1 hardening — do these BEFORE any new feature)

| # | Item | Today | v1 |
|---|---|---|---|
| H1 | **Transport** | plaintext HTTP on `0.0.0.0:8800`; sudo password transits cleartext | **TLS always** (self-signed minted at launch, SHA-256 fingerprint printed beside the token); default bind `127.0.0.1`, remote requires explicit `--remote` flag |
| H2 | Session | token → cookie (exists) | + single-session enforcement, idle timeout (15 min), **auto-stop after success** |
| H3 | Sudo password | stdin-only (good) | + zeroed after use; never in state/logs; accepted only over TLS |
| H4 | CSP | `default-src 'none'` (exists) | keep; add `frame-ancestors 'none'`, no-store on API responses |
| H5 | Job creation | single-flight (exists) | + idempotency token per job POST |
| H6 | **Bundle integrity gap (real finding):** `correlix-setup` is **not covered by `SHA256SUMS`** (`make-installer.sh:420` covers `*.tar.*`, `*.md`, `MANIFEST`, the two shell scripts — not the binary) | — | add the binary to the checksum set |
| H7 | Secrets in exports | — | profile export contains flags/config only — assert with a redaction test |

Threat framing stays the prototype's honest one: the token+TLS gate is the same trust model as the SSH session that launched the installer — no more, and now no less.

---

## 6. Engine refactors (small, load-bearing)

1. **`install.py --progress-json`** — emit one JSON line per stage transition (`{stage, status, detail}`) alongside human output, so the GUI parses structure instead of regexing logs. The stage list already exists as `step()` calls.
2. **Prompt/flag parity audit** — every interactive prompt must have a non-interactive flag. Two of three already do (`--tls`, `--assume-yes`); the Docker-bootstrap prompt (`install.py:173`) does not — add `--bootstrap-docker yes|no`. Extend `preflight-install.py` to enforce parity so drift is CI-caught.
3. **`install-correlix.sh install --config profile.json`** — expand an exported profile to the existing flags. This *is* the unattended path; machine-readable result JSON (`{status, version, url, health}`) on completion.
4. **`requirements.json`** — extract the hardcoded preflight thresholds into data consumed by both `preflight()` and the GUI facts API.
5. **Structured errors** — map `fail()` call sites to stable error codes + stage; the GUI renders `userMessage`, the support bundle carries `technicalDetail`.

---

## 7. Support bundle (new)

Generated on demand and offered on failure: sanitized `.env` (secret values redacted, names kept), `docker compose ps -a`, per-service log tails, `prepare-host.sh --check` output, facts snapshot, resource plan, install stage journal with error codes, versions/MANIFEST. Secret-redaction is tested (§11 below). No packet payloads, no customer telemetry data.

---

## 8. Watchdog handover (post-install, opt-in)

`stack-watchdog.sh` is the "who watches the watcher" answer but is **LAB_PATHS-excluded from customer bundles today** (`make-installer.sh:196`). Decision required (owner): promote a shippable variant (it already reads gitignored `stack-watchdog.env`, has `--test`, and its checks are generic). Design assumes YES: S8 collects `NTFY_TOPIC`/`HC_PING_URL`, writes `stack-watchdog.env`, installs the cron via privileged op #3. If NO, S8 shows the manual runbook instead.

---

## 9. Lifecycle page (v1.1, explicitly out of v1.0)

Same binary, post-install mode (or re-launched on demand): status/health (wraps `install-correlix.sh status` + smoke test), logs, stop/start, **update** (wraps `update.sh` with the same plan→apply→verify framing), **secret rotation** (`--rotate-app-secrets`; `--rotate-kafka-cluster-id` behind the typed-confirmation destructive gate), add-on enable/disable (profile edit + `up -d`), support bundle. One lifecycle engine, as the research demands — all wrappers over existing verbs.

---

## 10. What this explicitly does NOT do (v1)

No host NIC/netplan/DNS/hostname/NTP changes · no APT repo management · no disk formatting · no Kubernetes · no license gate (no entitlement mechanism exists in the product — flagged as an open product decision, not an installer gap) · no telemetry (none exists to consent to) · no in-product i18n framework.

---

## 11. Testing & CI (§11/§12/§16 bar)

- **Unit** (exists, extend): token gate, single-flight, PASS/FIX parsing, credential extraction — add: TLS-on-:8800, session timeout, idempotency token, redaction (support bundle + profile export), progress-JSON parsing, error-code mapping.
- **Contract:** exported profile → `--config` expansion round-trips to the identical flag set; `preflight-install.py` gains prompt/flag parity + requirements.json coverage.
- **CI leg (extend `fresh-install-integrity`):** a **GUI-driven install** on a virgin runner — launch `correlix-setup`, drive the API (facts → plan → install → health) headlessly via curl, assert the same post-conditions as the existing tls-boot leg. This closes the loop the research asks for: the GUI path is proven, not assumed.
- **Failure injection** (subset, prioritized): port conflict, insufficient RAM/disk refusal, corrupt bundle checksum, partial TLS mint (sentinel missing), docker-group chicken-and-egg restart, browser disconnect during phase B, health-gate failure after up.
- Frontend `ui.html` stays framework-free; accessibility floor checked by the e2e (keyboard walk of all screens).

---

## 12. Delivery phases

| Phase | Scope | Size |
|---|---|---|
| **P0 — engine prep** | `--progress-json`; prompt/flag parity (+CI gate); `--config` profile import/export; `requirements.json`; error codes | S |
| **P1 — hardening** | H1–H7 (TLS, localhost-default+`--remote`, single session, idle timeout, auto-stop, sudo-password handling, binary into SHA256SUMS, idempotency token) | S–M |
| **P2 — the wizard** | Facts API, S1–S6 screens, job engine + SSE structured events, S7 progress with structured errors | M — this is 80% of the user value |
| **P3 — the hard UX** | TLS phase-B reconnect flow, docker-group restart flow, support bundle, watchdog handover (S8) | M |
| **P4 (v1.1) — lifecycle** | Status/update/rotation/add-ons page | M, low-risk wrapping |

P0+P1 ship value even if P2 slips (hardened prototype + unattended profiles). Each phase carries its tests per §11; no phase is complete without them.

---

## 13. Open decisions for the owner

1. **Watchdog shipping** — promote `stack-watchdog.sh` (or a trimmed variant) into the customer bundle so S8 can wire it? (Design assumes yes.)
2. **Remote setup default** — H1 proposes localhost-bind default with `--remote` opt-in. Headless-server customers will mostly need `--remote`; acceptable friction, or should remote stay the default with TLS+token deemed sufficient?
3. **Licensing** — no entitlement mechanism exists; confirm v1 ships without a license gate.
4. **Bundle signing** — GPG signing is a make-installer TODO; v1 stays checksum-only unless prioritized.
5. **`ui.html` growth path** — the wizard multiplies UI surface; keep single-file embedded HTML (zero-dependency doctrine) vs. adopt the SPA build for the installer too. Design recommends **staying single-file** (the installer must work when the product stack is down and must stay auditable).
