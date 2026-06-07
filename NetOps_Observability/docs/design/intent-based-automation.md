# Intent-Based Automation — Architecture (with Opsis Ai intake)

Status: **design / proposal — awaiting review & sign-off (no code yet).**
Date: 2026-06-07.

---

## 0. Executive summary & review guide

**What this is.** A plan to turn a *desired outcome* — typed into a form, written
as a declarative file, or asked in plain English to **Opsis Ai** ("configure VLAN
100 on the access leaves in BLR") — into the right config on the right devices,
**safely**, and then keep it that way. Plus a config-management layer: **NETCONF
push, config backup/storage, snapshots, 5-minute drift detection with a Sync
status, and rollback.**

**The one idea that drives the whole design.** Because a request can come from an
LLM, **Opsis Ai only *proposes* a structured intent (validated JSON) — it never
renders config and never touches a device.** A deterministic, reviewable,
human-approved pipeline does everything downstream. (Zero-trust; OWASP LLM02/08.)

**What you're being asked to review.**
- The **pipeline** (§3) and **intent model** (§4) — is this the right shape?
- The **safety/trust model** for AI-originated change (§6) — is it strict enough?
- The **config-management subsystem** (§12) — does it match features 1–5?
- The **build phases** (§10) and the **decisions to confirm** (below / §13).

**How to read it.** §0 → §3 (the pipeline) → §5 (the VLAN-100 walkthrough) → §6
(safety) → §12 (config mgmt) → §10 (phasing). The rest is depth.

### Decisions to confirm before we build (sign-off checklist)
1. **Approval posture** — AI-originated changes are *approval-required, dry-run-
   first* by default. OK? Any kinds allowed to auto-apply later, and when?
2. **Intent store** — DB-first (UI-native) for v1, add Git (network-as-code) later
   — or Git-first from day one?
3. **Config store backend** — internal (Postgres/object, no new infra) for v1;
   external **Git** vs **S3/MinIO** as the first add-on?
4. **Golden baseline for drift** — an explicitly-approved snapshot, or *derived
   from active intent*, or both?
5. **NETCONF** — hand-rolled over the existing `x/crypto/ssh` + `encoding/xml` (no
   new dependency, matches the budget) — acceptable?
6. **Rendering engine** — in-house Go templates (stdlib) vs an external automation
   engine (Ansible/Nornir) as an executor driver.
7. **First scope** — start with the **config-management track (C0: backup +
   history, read-only/no device writes)** as the safe entry point, or the
   **intent track (P0: NL→intent→diff)** first? (They can run in parallel.)
8. **Vendor priority** — confirm the first drivers: Arista EOS + Nokia SR Linux
   (the lab), then Cisco IOS-XE/Junos?

Annotate inline or reply with answers; nothing gets built until you're satisfied.

---

## 1. Goal

Let an operator express a *desired outcome* — in a form, a declarative file, or
**natural language to Opsis Ai** ("configure VLAN 100 on the access leaves in
site BLR") — and have the platform safely turn it into the right config on the
**right devices**, then **continuously verify** it stays that way.

The hard part is not "send a command." It is doing so **safely** on a live,
multi-vendor network when the request may originate from an LLM. So the spine of
this design is a deterministic, reviewable pipeline with the AI strictly at the
*front door*.

### Non-goals (v1)
- Auto-applying AI-originated changes without human approval (off by default).
- Replacing a commercial IBN engine (Apstra/NSO) — this is the open, observable
  core: intake → compile → validate → approve → execute → verify.
- LLM-generated device config (the LLM picks *intent*; deterministic templates
  render *config*).

## 2. Principles

1. **The LLM proposes; it never executes.** Opsis Ai emits a *structured intent
   proposal* (validated JSON), not config and not a device action. (OWASP LLM02
   insecure-output-handling, LLM08 excessive-agency; CLAUDE.md §3/§15.)
2. **Layered source of truth.** *Resources* (devices/sites/VLAN ranges) live in
   **NetBox**; *desired config/policy* (the intents) is **version-controlled**
   (the config SoT); the **network is never a SoT** — it's what we reconcile to.
3. **Deterministic rendering.** Vendor config comes from reviewed templates +
   SoT data, not from a model. Reproducible and diffable.
4. **Safety by construction.** Every change is dry-run + diffed, blast-radius-
   bounded, approved, staged, and auto-rolled-back on failed verification.
5. **Closed loop.** After apply, the platform's own telemetry/discovery proves
   actual == intent; divergence becomes a drift Finding/Incident.
6. **Zero-trust + multi-tenant.** Intents are tenant-scoped; every hop is
   authenticated, authorized (RBAC), and audited.

## 3. Pipeline (the spine)

```
                         ┌──────────────────────────────────────────────┐
  NL ("configure VLAN    │  Opsis Ai  — constrained tool/function call   │
  100 on access leaves") │  emits a STRUCTURED INTENT PROPOSAL (JSON).   │
        │                │  Never config. Never a device action.        │
        ▼                └───────────────┬──────────────────────────────┘
  Form / declarative ───────────────────►│  (same schema — UI & API are peers
  intent file (Git/API)                  │   of the NL path, not downstream)
                                          ▼
                              (1) INTENT SCHEMA VALIDATION  ── reject if malformed
                                          ▼
                              (2) INTENT STORE  (versioned; the config SoT)
                                          ▼
                              (3) COMPILER / RESOLVER
                                   • scope selector → device set  (query NetBox)
                                   • policy checks (VLAN range, reserved ids,
                                     conflict, tenant ownership)
                                          ▼
                              (4) RENDERER (per-vendor, deterministic)
                                   • EOS / SR Linux / IOS-XE / Junos templates
                                   • output: candidate config + DIFF vs running
                                          ▼
                              (5) CHANGE PLAN  (devices, diffs, risk, blast radius)
                                          ▼
                              (6) APPROVAL GATE  ── RBAC + change window + caps
                                   (MANDATORY for AI-origin by default)
                                          ▼
                              (7) EXECUTOR  (staged/canary; commit-confirm; rollback)
                                   • transport: SSH gateway / gNMI / NETCONF
                                          ▼
                              (8) VERIFY  (telemetry/discovery: is VLAN 100 there?)
                                   • actual == intent? → done | drift → Finding
                                          ▼
                              (9) AUDIT + EXECUTION HISTORY (immutable)
```

The UI form, a declarative intent file (Git/API), and Opsis Ai are **three peer
front-ends that all produce the same validated intent object** — so the risky
downstream stages are identical and testable regardless of origin.

## 4. The intent model

Declarative, vendor-neutral, additive. Each intent is a small typed object with
a **scope selector** (who) and **parameters** (what), plus provenance.

```jsonc
{
  "kind": "vlan",                       // vlan | svi | interface | bgp_peer | acl | …
  "id": "vlan-100",
  "tenant": "acme",
  "params": { "vlan_id": 100, "name": "USERS", "mtu": 9000 },
  "scope": { "roles": ["leaf"], "sites": ["BLR"], "tags": ["access"] },
  "origin": { "via": "opsis-ai", "actor": "rao", "prompt_id": "…", "ts": "…" },
  "approval": { "required": true, "state": "pending" }
}
```

- **Vendor-neutral** — `vlan_id: 100` renders to `vlan 100` on EOS, the SR Linux
  equivalent, etc. The model never carries vendor CLI.
- **Scope = selector, not a device list** — resolved against NetBox at compile
  time, so adding a device to the role/site auto-includes it (declarative).
- **Versioned** — the intent store keeps history; a change is a new revision with
  a diff. Git-backed is the recommended store (network-as-code) with a DB mirror
  for query/UI.

## 5. Worked example — "configure VLAN 100"

1. **Opsis Ai** receives *"configure VLAN 100 on the access leaves in BLR."* It is
   in **intent mode**: a function/tool schema forces it to return
   `{kind:"vlan", params:{vlan_id:100}, scope:{roles:["leaf"], sites:["BLR"], tags:["access"]}}`
   — and to **ask for missing required fields** (name? SVI?) rather than guess.
   It returns the proposal to the user for confirmation; it executes nothing.
2. **Validate** the proposal against the `vlan` schema (id 1–4094, name policy…).
3. **Compile/Resolve**: query NetBox → devices with role=leaf, site=BLR, tag=access
   → `[blr-leaf1, blr-leaf2]`. Policy: is 100 inside the site's allowed VLAN range?
   already used for something else? tenant owns these devices? → pass/deny.
4. **Render** per device by its detected vendor: `blr-leaf1` (Arista EOS) →
   `vlan 100 / name USERS`; `blr-leaf2` (SR Linux) → its equivalent. Produce a
   **diff** vs each device's running config (no change if already present →
   idempotent, possibly a no-op plan).
5. **Change Plan** shows: 2 devices, 2 diffs, blast radius "2 leaves / 1 site",
   risk low. Presented in **Automation → Intent**.
6. **Approve** (operator with `automation:write`). AI-origin ⇒ approval required.
7. **Execute** staged: blr-leaf1 first (canary) → verify → blr-leaf2. Use
   commit-confirm where the platform supports it (SR Linux/Junos); SSH-gateway
   apply for EOS/IOS. Failure on any stage → **rollback** + halt.
8. **Verify**: next discovery/gNMI poll confirms VLAN 100 present on both. Match →
   intent `state: active`. Mismatch later (someone deletes it on the box) →
   **drift Finding/Incident** ("VLAN 100 missing on blr-leaf2, expected by
   intent vlan-100").
9. **Audit**: every stage recorded with actor, origin (opsis-ai + prompt id),
   diff, result.

## 6. Safety & security model (the crux for AI intake)

| Risk | Control |
|------|---------|
| LLM emits a dangerous/garbled action | LLM returns **schema-constrained intent only**; validated as *data*, never `eval`/executed (LLM02). Unknown fields rejected. |
| LLM "over-reaches" (excessive agency) | LLM cannot select the executor, bypass approval, or widen scope; it only fills the intent form. AI-origin intents are **approval-required by default** (LLM08, least privilege). |
| Prompt injection via pasted logs/config | Intake sanitizes; pasted content is data, not instructions; the compiler re-derives scope from NetBox, not from the prompt text. |
| Blast radius / fat-finger | Per-intent **device cap + site cap**, change windows, **canary + staged** rollout, mandatory dry-run diff before apply. |
| Bad config sticks | **commit-confirm / auto-rollback** on failed post-checks; verification closes the loop. |
| Wrong tenant | Intent is tenant-scoped; resolver filters NetBox by tenant; RBAC on approve/execute; full audit. |
| Secret/credential exposure | Device creds come from the existing SNMP/SSH credential store (Vault-encrypted), never from the LLM or the intent. |

Default posture: **dry-run + human approval for everything AI-originated**;
fully-automated apply is an explicit opt-in per intent-kind for low-risk,
well-tested kinds (e.g. `vlan`) once an org trusts the loop.

## 7. Multi-vendor rendering

- A **driver per platform** (EOS, SR Linux, IOS-XE/NX-OS, Junos) implementing
  `render(intent, deviceFacts) → (config, isNoOp)` and
  `diff(device) → changes`. Deterministic templates (Go `text/template` /
  Jinja-style), reviewed like code.
- **Device facts** (vendor/model/OS) come from NetBox + the platform's existing
  **SNMP sysObjectID vendor detection** and gNMI/NETCONF capabilities.
- New vendor = new driver; the intent model and pipeline are unchanged.

## 8. Closed-loop verification (where this platform already wins)

After apply, verification is just observability — which you already have:
- **Discovery / SNMP / gNMI** read back the intended object (VLAN table, SVI, BGP
  session) and compare to the intent.
- A reconciler (model the existing **ITSM ordering/reconcile engine** and the
  **report async pipeline**) runs the compare on a cadence and on-demand.
- Divergence → a **drift Finding** (Anomalies) or **Incident**, with the offending
  device and the expected-vs-actual — surfaced in the UI you already have.

## 9. Mapping to existing components (what to reuse, not rebuild)

| Need | Reuse |
|------|-------|
| NL intake | **Opsis Ai** (`copilot.go`) — add an *intent tool/function* mode that returns validated intent JSON |
| Resource SoT / scope resolution | **NetBox** (Automation → Source of Truth) |
| Device transport | **device-SSH gateway** (`device_ssh.go`, `golang.org/x/crypto/ssh`, FEATURE_DEVICE_SSH) + gNMI/NETCONF collectors |
| Async execution (queue/workers/history) | the **report pipeline** pattern (PG `FOR UPDATE SKIP LOCKED`, lease heartbeat, immutable execution history, RLS) |
| State changes / ordering / idempotency | the **ITSM integration** ordering+reconcile engine pattern |
| Approval / RBAC / audit / tenancy | existing `requirePerm`, audit store, RLS, tenant scoping |
| Drift surfacing | Alerts / Findings / Incidents |
| Verification telemetry | discovery + collectors (SNMP/gNMI) |

New surfaces: **Automation → Intent** (author/list intents, change plans,
approvals, history) as a sibling of **Source of Truth**; new pkg `intent/`
(model, compiler, drivers, executor, verifier); `/api/intent/*` routes
(platform/automation-scoped).

## 10. Phased roadmap

- **P0 — Intent core (read-only/dry-run).** Intent schema + store (Git/DB),
  compiler/resolver against NetBox, EOS+SR Linux renderers, **change plan + diff
  only (no apply)**. Opsis Ai intent-tool mode producing proposals. → proves the
  NL→intent→diff path safely with zero device risk.
- **P1 — Guarded execution.** Approval gate + RBAC + caps + change windows;
  executor via SSH/gNMI with canary + commit-confirm + rollback; immutable
  execution history. `vlan` kind end-to-end on the lab fabric.
- **P2 — Closed loop.** Verifier + drift Findings/Incidents; periodic + on-demand
  reconcile.
- **P3 — Breadth.** More intent kinds (SVI, interface, BGP, ACL), more vendor
  drivers, optional auto-apply for trusted low-risk kinds, Git-backed intent
  (network-as-code) with PR review as the change-management front door.

Config-management track (§12), can run in parallel — it has value even before
intent execution:
- **C0 — Backup + history.** NETCONF/gNMI/SSH config collector + `ConfigStore`
  (internal backend) + manual/scheduled snapshots + per-device Config tab (revision
  history + diffs). Pure read — no device writes.
- **C1 — Drift + Sync column.** 5-minute drift checker, golden baseline, the
  🟢🟡🔴⚪ Sync column + drift Findings.
- **C2 — Rollback + external store.** One-click rollback to a snapshot via the
  safe executor (NETCONF confirmed-commit); opt-in Git/S3 external backend.

## 12. Config management, backup, drift & rollback

These five capabilities form a **Config Management subsystem** that the intent
pipeline reuses (snapshot before apply; verify by full-config compare; rollback
to a known-good). They also stand alone as classic config backup + drift (think
Oxidized/RANCID, done natively and observably).

```
   per device, per transport (NETCONF / gNMI / SSH)
   ┌─────────────┐   pull running-config        ┌──────────────────────────┐
   │ Config       │ ───────────────────────────►│ ConfigStore (versioned)  │
   │ Collector    │                              │  backends:               │
   └─────┬───────┘                               │   • internal (PG/object) │
         │ hash + diff vs baseline               │   • EXTERNAL: Git / S3   │
         ▼                                        │  immutable revisions     │
   ┌─────────────┐  every 5m (CONFIG_DRIFT_INTERVAL)└──────────┬─────────────┘
   │ Drift Checker│ ◄─ baseline = golden/approved snapshot      │ snapshots
   │  sets SYNC   │     (or previous backup)                    │ (labeled
   │  status      │ ── drift → new revision + diff + Finding     │  revisions)
   └─────┬───────┘                                              ▼
         ▼                                            ┌──────────────────┐
   Devices UI: "Sync" column  🟢🟡🔴⚪                 │ Rollback (apply a │
                                                       │ stored snapshot)  │──► Executor
                                                       └──────────────────┘    (§3.7, safe)
```

### 12.1 NETCONF transport (feature 1)
A **NETCONF driver** alongside the SSH-gateway and gNMI transports, used to both
**push** config (candidate datastore → validate → `commit`, with
**confirmed-commit** for auto-rollback) and **pull** running-config
(`<get-config>`). NETCONF runs over the SSH "netconf" subsystem (RFC 6242 framing
+ XML RPC), so it is built on the **already-allowlisted `golang.org/x/crypto/ssh`**
(the device-SSH gateway precedent) + stdlib `encoding/xml` — **no new module**.
The executor (§3.7) picks the transport per device capability: NETCONF where
available (best: candidate + confirmed-commit), else gNMI Set, else CLI over the
SSH gateway. Confirmed-commit is the safety jewel: push → `commit confirmed 120`
→ post-check → confirm; miss the confirm window → device auto-reverts.

### 12.2 Config store — internal or external (feature 2)
A `ConfigStore` interface; the config text/XML is opaque, keyed by
`(tenant, device, revision)` with metadata (hash, captured_at, trigger, author,
transport). **Pluggable backends:**
- **internal** (default): Postgres + the existing object/artifact store (like the
  report `ArtifactStore`) — zero new infra.
- **external** (opt-in): **Git** (configs-as-code — diff/blame/history for free,
  the network-engineering norm) or **S3/MinIO** object storage. Selected by
  `CONFIG_STORE_BACKEND`; credentials via the secret-custody Vault.
Revisions are **immutable**; a config is stored **only when its hash changes**
(dedup) so the 5-minute poll doesn't explode storage.

### 12.3 Snapshots (feature 3)
A **snapshot** is a labeled config revision with a trigger:
`manual | scheduled | pre-change | post-change`, plus an optional **`golden`**
(approved/intended) flag. The intent executor takes a **pre-change snapshot**
automatically before every apply (the rollback target) and a **post-change**
snapshot after. Scheduled daily snapshots give a backup history; `golden` marks
the compliance baseline.

### 12.4 Drift check every 5 min + Sync column (feature 4)
A scheduled job (default `CONFIG_DRIFT_INTERVAL=5m`, reusing the report-pipeline
worker/queue pattern) for each device: pull running-config → hash → compare to
the **baseline** (the `golden` snapshot if set, else the previous backup):
- **🟢 green** — matches the golden/approved baseline. In sync.
- **🟡 amber** — changed since last check; a new revision was captured and a diff
  recorded, pending review (or no golden set yet → compares to previous backup).
- **🔴 red** — drifted from the **golden/intended** config (unauthorized /
  non-compliant change) — raises a **drift Finding/Incident** with the diff.
- **⚪ grey** — unknown / unreachable (couldn't fetch config).

Surfaced as a **"Sync" column** in **Infrastructure → Devices** (per device:
color + last-checked + a click-through to the diff), and as a fleet rollup.
When an intent is active, "golden" can be *derived from intent* so drift = "the
box no longer matches what we declared," closing the §8 loop at full-config
granularity.

### 12.5 Rollback (feature 5)
Restore a device to any stored snapshot. Rollback is just an **apply of a
known-good revision** through the same safe executor (§3.7): show the diff
(current → snapshot), approve, push via NETCONF candidate + **confirmed-commit**
(or vendor config-replace: IOS-XE `configure replace`, Junos `load override`),
then **verify** the device now matches the snapshot. One-click "roll back to
pre-change snapshot" is offered automatically when an intent apply fails its
post-check.

### 12.6 New surfaces / reuse
- New pkg `config/` (collector, ConfigStore + backends, drift checker, NETCONF
  driver), reusing the report-pipeline async substrate + the secret Vault for
  store/device creds.
- Devices gains a **Sync** column + a per-device **Config** tab (revision history,
  diffs, snapshot/restore).
- Routes `/api/devices/{id}/config[/snapshots|/diff|/rollback]`,
  platform/automation-scoped, RBAC + audit.

## 13. Open decisions
- **Intent store**: Git-first (network-as-code, PR review) vs DB-first (UI-native)
  vs both (DB mirror of Git). Recommendation: DB for v1 UX, add Git sync in P3.
- **Renderer engine**: hand-written Go templates (stdlib, matches the dependency
  budget) vs adopting an external templating/automation engine (Nornir/Ansible
  as an executor driver behind the same intent API).
- **Auto-apply**: which kinds (if any) may skip approval, and the trust criteria.
- **Verification depth**: config-presence (cheap) vs operational-state (e.g. SVI
  up, MAC learned) per intent kind.
- **Config store backend**: internal PG/object (no new infra) vs Git (configs-as-
  code, best history/diff) vs S3/MinIO. Recommendation: internal for C0, add Git
  as the first external backend in C2.
- **Golden baseline source**: an explicitly-approved snapshot vs *derived from
  active intent* (drift = divergence from declared intent). Support both; prefer
  intent-derived once the intent pipeline is live.
- **NETCONF library**: hand-rolled over `x/crypto/ssh` + `encoding/xml` (no new
  module, matches the dependency budget) vs adopting a NETCONF/automation library.
- **Confirmed-commit coverage**: native on Junos/SR Linux; for EOS/IOS use
  config-replace/checkpoint + verify-or-revert — confirm per-vendor rollback story.
