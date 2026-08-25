# Security Track — build plan (2026-08-25)

Execution plan for building the Security Track on the finalized design (HLD
`SECURITY_OBSERVABILITY_HLD_2026-08-25.md` + siblings). Owner ordered:
**Security track first, then config backup, then sync/drift, then other
modules.** Per the model rule, Fable specs + reviews; **Opus subagents build**.
Per the soak rule, **nothing deploys** until the current 72h soak closes
(~2026-08-27 06:28Z) — building in the repo is fine (this code is
feature-flagged, dormant, not in the correlation hot path), but no image
builds / no `docker` / no `--force-recreate` / no full `go test ./...` while
the soak runs (targeted package builds+tests only, to stay soak-safe).

## Assessment (why this is rebuild-foundation + evolve-seeds, not scratch-all)

- **Keep + evolve:** `internal/vuln` (version-constraint matcher — already the
  design's approach), `internal/compliance` (framework-tagged Finding + 9
  checks — the OCSF-superset base), `internal/secobs` (security-metric
  contract). ~1,300 lines of tested, design-aligned code — scratching it would
  be waste.
- **Rebuild:** the threat-detection LANE (today `ThreatDetection.tsx` is a thin
  121-line flow-heuristic placeholder). The flow panels survive as a "Network
  Behavior" sub-view; the detection ARCHITECTURE (rules-as-code, SecuritySignal
  events, MITRE tags, exposure story) is built fresh.
- **Build fresh:** OCSF finding model, security-as-producer bus seam, config
  capture, exposure story, PSIRT connectors, vendor profiles.

## Security Track — ordered build tasks (each an Opus subagent)

**T1 — Security finding foundation (Go).** OCSF-aligned `Finding` model
(superset of `compliance.Finding`): id, tenant, source, evidence_class,
status+status_id (Pass/Warn/Fail), standards[], control_id/title, severity,
resource{device,host,kind,platform}, observed/intended/detail, remediation,
evidence_ref. Converter from the existing `compliance.Finding`. Fully tested.
No HTTP/engine wiring yet. **← STARTED.**

**T2 — Security-as-producer bus seam.** The generic evidence object
(entity+seam+timestamp+evidence-refs) a security lane emits, and the contract
by which the correlation engine grounds it with ZERO security-specific code
(the removable-module constraint). Go producer side + the Kafka topic; the
Python engine consume-and-ground side is a separate, careful step (T2b) since
it touches the engine — spec'd not to add security branches.

**T3 — Evolve vuln lane onto the foundation.** `internal/vuln` emits `Finding`s
(exposure class) with EPSS + EoL fields; the vendor-advisory-by-version model
(§5g); keep the offline feed, add the EPSS/KEV columns to the prepare script.
Emits onto the T2 bus seam.

**T4 — Evolve compliance lane onto the foundation (SCOPE-TIGHTENED by Q4).**
`internal/compliance` findings become `Finding`s. Per Q4 (do NOT fund broad
benchmark maintenance yet): v1 = drift + golden-config + the existing
framework TAGS on the small check set; INGEST OpenSCAP/SSG for Linux (community
maintains content). The broad 800-53↔PCI/HIPAA/CSF/ISO crosswalk DATA
(§5d full realization) is DEFERRED — keep the Check→Control tag on our own
rules (cheap, ours) but do not import/maintain the full framework crosswalk
until there is demand. Claim "hardening findings"/control evidence on the
tagged set, not broad "framework compliance".

**T5 — Network hardening rule engine (§5e).** Concept catalog (~20-30 rules) +
per-vendor detect/remediate bindings; the SEAM-AWARE exposure check (the
differentiator); remediation in every finding. Needs config capture (T-config
below) for input — stub the config source first, wire it when config capture
lands.

**T6 — Threat-detection lane rebuild.** SecuritySignal events + rules-as-code
catalog (device-log detections: logging-disabled, off-window config change,
new user, GRE tunnel — MITRE-tagged) over existing syslog; flow-behavioral
(beaconing/exfil) over existing flows; the old flow panels become a sub-view.

**T7 — Exposure Story (flagship).** The correlation output class that folds
security-lane evidence into a seam-attributed story (reuse the RCA object
shape). Depends on T2b (engine grounding).

**T8 — Security section UI.** Overview posture + Exposure/Findings + Threat
Detection + Compliance surfaces (evolve the existing pages), all lazy-loaded,
§3a tenant-scoped, honest coverage.

**T9 — Vendor Profile registry.** Consolidate scattered vendor knowledge
(detection, dialect, CVE binding, capture commands, hardening bindings) behind
one declarative profile; migrate existing vendors without regression.

## Then (owner order): the infrastructure modules

- **Config Backup** (`CONFIG_BACKUP_AND_DRIFT_DESIGN`) — sealed store
  (local/remote, secure transport only), capture over the SSH gateway.
- **Config Sync/Drift** — the in-sync/not-in-sync badge + the ConfigDrift bus
  event (feeds security/compliance/RCA).
- **Packet Capture** (`PACKET_CAPTURE_DESIGN`) — per-interface bounded on-device
  capture, sealed store, guardrails.

Each gets its own incremental qualification when enabled (§5f — the base soak
stands; enabled-feature configs characterize the delta, no full redo).

## Cross-cutting rules for every task

§3a tenant isolation + isolation test per feature · feature-flagged, dormant by
default · findings by-reference to evidence · honest "unassessed"/coverage
never false-clear · full gate (vet/staticcheck/gosec/tests) before any deploy ·
deploy only post-soak, one batch, smoke-gated.
