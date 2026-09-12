# Config Backup & Drift — module design (2026-08-25)

Owner request: (1) a **config backup module** storing every device's config in
local OR remote storage per configuration, **secure options only**; (2) device
inventory shows whether each device's config is **in sync**, flipping to **not
in sync** on drift.

Both are the same keystone — **config capture + versioned storage + drift
comparison** — surfaced two ways. This is a FOUNDATIONAL capability (NMS-grade,
Oxidized/RANCID/SolarWinds-NCM territory) that the security, compliance, and
RCA modules all CONSUME. It is its own module, not part of security, so the
removable-module constraint holds: it produces config artifacts + drift events
onto the bus; consumers subscribe.

## Grounding (what exists / what's new)

- **New:** running/startup config capture, versioned config store, config drift
  (running-vs-startup, running-vs-golden), the inventory sync badge.
- **Reuse:** the SSH gateway (`device_ssh.go`, `golang.org/x/crypto/ssh`,
  `FEATURE_DEVICE_SSH`) for capture; the verify engine's `ssh_config_change`
  as a change TRIGGER; **sealing/vault** (`src/backend/sealing/`, per-tenant
  DEK) for encryption at rest; FORCE-RLS for tenant isolation; the Devices
  inventory page for the sync badge; the maintenance-window model for
  planned-vs-unplanned drift.
- **NOT the same as** the existing compliance "SoT drift" (that pairs a device
  against the source-of-truth INVENTORY record — name/IP/serial/platform).
  This is CONFIG drift. Distinct; keep both.

## 1. Capture

- **Sources:** running-config (primary) + startup-config (for the
  running-vs-startup "unsaved changes" drift). Per-vendor `show`/RPC via the
  SSH gateway; NETCONF/gNMI where available.
- **Triggers:** (a) scheduled (configurable; default daily); (b) **on-change**
  — the verify engine / syslog already detects a config-change event
  (`SYS-5-CONFIG_I`, commit logs), so capture fires within minutes of a real
  change (the drift-in-minutes differentiator, §5c). Event-driven beats
  polling.
- **Secrets in configs:** running-configs contain SNMP communities, key
  material, password hashes. They are SENSITIVE by definition — this drives
  the storage rules below.

## 2. Secure-options-only storage (the owner's hard constraint)

The backup module must not itself use the insecure methods the hardening
checks (§5e) flag on devices — it practices what it preaches.

- **Transport to remote storage:** SFTP / SCP / HTTPS / S3-with-TLS ONLY.
  **FTP and TFTP are REFUSED** (the exact protocols §5e flags as insecure).
  The config UI offers only secure backends; an insecure URL is rejected at
  the boundary, not silently downgraded.
- **Encryption at rest:** every stored config is sealed under the **tenant
  DEK** (reuse `sealing/`), local or remote alike. A backup blob at rest is
  ciphertext; a stolen disk / bucket yields nothing. Never store a config in
  plaintext.
- **Remote credentials in vault:** S3 keys / SFTP creds are write-only,
  sealed, never in the config file or logs (§8).
- **Backends (per-tenant configurable):**
  - **Local** — encrypted blobs on the platform volume (default; air-gap
    friendly).
  - **Remote** — S3-compatible (TLS + SSE) or SFTP target, creds in vault.
  - Retention = N versions and/or time window (ties to the retention-upsell
    pricing lever; older versions prune, newest always kept).
- **Tenant isolation:** §3a — a config belongs to exactly one tenant; the
  store keys/filters by tenant (FORCE-RLS for the index rows, per-tenant DEK
  for the blobs). No cross-tenant "list all backups".

## 3. Versioning & diff

- Content-addressed versions (hash of the normalized config) — an unchanged
  capture stores no new version, just advances "last verified". This is also
  the audit trail and the cache key reused by §5c compliance evaluation
  (config_hash).
- Diff between any two versions (unified, secret-redacted in the UI — show
  "community ****" not the value). "Who/when" from the change event where the
  device reports it.

## 4. Config sync status on the Devices inventory (the second ask)

Per-device status, a new column/badge on the Devices page:

| Status | Meaning |
|---|---|
| **In sync** | running == startup AND running == golden baseline (if a baseline is set) |
| **Not in sync** | drift: running != startup (unsaved changes) OR running != golden (baseline drift) |
| **Never captured** | no backup yet (honest — never blank/green by default) |
| **Unreachable** | last capture failed (device down / creds / transport) — NOT "in sync" |

- "Golden baseline" is optional per device (operator marks a known-good version
  as golden; without one, sync = running-vs-startup only). This is the
  golden-config model §5b/§5e reference.
- The badge links to the diff that explains the drift.
- **Drift is also a SIGNAL** emitted onto the bus (a `ConfigDrift` event with
  device + seam + what-changed + planned-vs-unplanned from the maintenance
  window). Consumers: the security lane (config change outside a window =
  a hardening/threat signal, §5e), compliance (re-evaluate the drifted device,
  §5c), and RCA (what changed on this device right before the incident — the
  single most valuable RCA input). One capture, four beneficiaries.

## 5. Where it sits

- **Nav:** Infrastructure (config management is NMS-grade), with the sync badge
  on the Devices inventory. NOT under Security — security is a consumer, not
  the owner. Feature-flagged (`FEATURE_CONFIG_BACKUP`), dormant by default.
- **Module boundary:** a producer of config artifacts (the store) + drift
  events (the bus). Correlation/security/compliance consume via the generic
  evidence path — remove the module and they simply have one fewer input. Same
  removable-module discipline as the security lanes.

## 6. Build order (when green-lit — goes to Opus)

1. Config store (versioned, sealed-at-rest, tenant-scoped) + local backend +
   the capture path over the SSH gateway (scheduled first).
2. Sync-status computation (running-vs-startup) + the Devices inventory badge +
   the diff view (secret-redacted).
3. On-change trigger (wire the existing config-change detection to capture) —
   drift-in-minutes.
4. Golden baseline + running-vs-golden drift; the `ConfigDrift` bus event so
   security/compliance/RCA consume it.
5. Remote backends (S3-TLS / SFTP), creds in vault, retention policy.

## Risks

- **Secret handling** is the headline risk — configs are secrets; at-rest
  sealing + UI redaction + write-only remote creds are non-negotiable (§8).
- **Capture credentials** — the platform needs read access to devices; reuse
  the audited SSH gateway's ticketed model, least-privilege (a read-only
  `show running-config`-class command set), never a general shell.
- **Scale** — the soak proves the compute budget; content-addressed versioning
  keeps storage flat for unchanged fleets (only real changes cost a version).
