# Telemetry Normalization & Enrichment Architecture (syslog + SNMP traps)

> Research + design. **No production code here** — precise recommendations the
> implementer follows. Status: design proposal for tracker **#26 (MIB index)**,
> **#31 (syslog normalization)**, **#32 (trap normalization)**.
> Author pass: 2026-06-17.

---

## 0. Problem statement (what's actually wrong today)

Our metrics plane already obeys the standing law — *ingestion = a source-agnostic
canonical contract*. SNMP polls and gNMI both land as `device_*{device,vendor,ifName}`
(see the metrics memory + `metrics_normalized` in
`deployment/docker/vector/vector.yaml:280`). **Syslog and trap MESSAGE BODIES do
not.** They are stored and displayed raw, and where we *do* extract meaning we do
it three separate times with three hand-curated maps:

1. **Go trap receiver** — `src/backend/collectors/snmptrap.go:83` (`wellKnownTraps`,
   ~12 OIDs), `:125` (`varbindObjects`, ~11 column OIDs), `:144` (`varbindExact`,
   4 scalars), `:68` (`genericTrapMeta`). This is the "curated OID map" the owner
   flagged: it resolves a dozen OIDs and labels *everything else*
   `enterpriseSpecific / notice` (`snmptrap.go:119`). Arista's
   `1.3.6.1.4.1.30065.*`, Cisco `9.9.*`, Juniper `2636.*`, Nokia `6527.*` traps —
   the bulk of a real NOC's trap firehose — render as a raw OID string.
2. **Vector VRL syslog** — `vector.yaml:187` does *vendor* classification by regex
   signature (fortinet/paloalto/juniper/arista/cisco) and a FortiOS kv-parser
   (`vector.yaml:217`), but for every other vendor it leaves the body raw and the
   severity = the syslog PRI severity only.
3. **Correlation producers** — `src/correlation/producers.py:224`
   (`syslog_control_signal`) and `:419` (`trap_control_signal`) re-parse the *same*
   raw strings/OIDs with a *third* curated set of regexes/OID constants
   (`_VB_IFNAME` etc.) to mint a `Signal`. Anything unrecognized returns `None`
   (correct anti-noise guardrail — `test_trap_classify.py:9`) but it means the
   parsing intelligence is duplicated and drifts.

The gap is twofold:

- **(A) OID/name decode** is a hand-list, not a real MIB-backed registry. It can
  never cover the enterprise trees a multi-vendor fabric emits.
- **(B) Body structure** (the SR Linux `subsys|pid|tid|seq|sev:` frame, Cisco
  `%FAC-SEV-MNEMONIC`, Junos `[junos@2636 …]` SD) is not parsed into a *canonical
  event contract*, so Events/Anomalies/Incidents/RCA each re-derive it.

**Goal.** A normalization + enrichment layer that turns every syslog line and
every trap PDU into ONE canonical, source-agnostic **NormalizedEvent** — decoded
(real MIB-backed OID names + enums), structured (vendor body parsed), severity-
normalized, classified into a maintainable taxonomy with a stable dedup
`message_key`, and inventory-enriched — *without adding a runtime third-party Go
dependency* (CLAUDE.md §6).

---

## 1. How production systems do this (research, cited)

### 1.1 MIB / OID decode

- **LibreNMS / snmptrapd.** LibreNMS does not compile MIBs at runtime in its hot
  path. It runs net-snmp `snmptrapd` configured with an explicit MIB search path
  (`-M /opt/librenms/mibs`), and ships a large **checked-in vendor MIB tree**
  (`librenms/mibs/<vendor>/…` in the repo). Resolution quality is purely a
  function of *which MIB files are present*; with no MIB an event shows as a raw
  numeric OID (`RFC1155-SMI::enterprises.9.9.46.2.0.11`). Trap *handlers* are then
  registered by mapping a resolved trap OID → a handler class, and pull fields by
  substring (`$trap->findOid()`). ([LibreNMS SNMP-Trap-Handler docs][librenms-trap],
  [LibreNMS MIB tree][librenms-mibs])
- **Telegraf `snmp_trap`.** Uses **gosmi** (net-snmp backend is deprecated). At
  startup it `LoadMibsFromPath(paths)` and at receive time calls
  `snmp.TrapLookup(oid)` / a node lookup returning a `MibEntry{MibName, OidText,
  …}`; the resolved varbind *name* becomes the field name and it tags
  `mib=SNMPv2-MIB,name=coldStart`. The model node (`gosmi`) carries `Name`, `Oid`,
  a `Type` (base syntax), enum named-values, and the owning module — i.e. exactly
  the (name, type, enum, module) tuple a decode needs. ([Telegraf gosmi.go][tg-gosmi],
  [Telegraf snmp_trap README][tg-readme], [gosmi node model][gosmi-node])
- **net-snmp `snmptranslate`.** The canonical *build-time* translator. Given a MIB
  search path it maps OID↔name, prints type and the `-Td` detail (SYNTAX, enums,
  INDEX). On *this* host `snmptranslate` is present (`/usr/bin/snmptranslate`) but
  only the 13 net-snmp bundled MIBs are installed — **IF-MIB/BGP4-MIB/the whole
  IETF+IANA set are NOT present** (`snmptranslate IF-MIB::ifOperStatus` → "Cannot
  find module"). So a pipeline that shells `snmptranslate` must *vendor the MIB
  source files itself*; it cannot rely on the host's MIB store.
- **pysmi / `mibdump`.** Pure-Python SMI compiler that turns ASN.1 MIBs into
  **JSON** (`mibdump --destination-format json IF-MIB`) and maintains a **JSON
  index** across many modules for fast OID→module lookup. Reads MIBs from local
  dirs / ZIPs / HTTP, so it runs fully offline against a vendored MIB tree. This is
  the most direct route to a *checked-in OID→{name,type,enum,index} JSON index*.
  ([pysmi README][pysmi], [pysmi compile-to-JSON][pysmi-json])

**Takeaway.** Every mature system is *MIB-file-driven*, not hand-list-driven, and
the offline ones (LibreNMS, Telegraf) win by **shipping a curated MIB tree** and
loading it. The right replacement for our curated Go map is therefore a
**checked-in MIB tree → build-time compile → embedded OID index → pure runtime
lookup** — which keeps the Go runtime stdlib-only (no MIB compiler at runtime).

### 1.2 Vendor syslog body formats (the ones we must parse)

| Vendor / OS | Body shape after the syslog header | Source |
|---|---|---|
| **Cisco IOS / IOS-XE** | `%<FACILITY>-<SEV 0-7>-<MNEMONIC>: <text>` (opt. `<seq>:` + timestamp prefix; Cat6500 adds a `-SUBFAC-`) | [Cisco IOS-XE System Message Guide][cisco-iosxe] |
| **Cisco NX-OS** | Same `%FACILITY-SEVERITY-MNEMONIC: text` (RFC 3164 transport) | [NX-OS System Message Logging][nxos] |
| **Arista EOS** | Cisco-compatible `%FAC-SEV-MNEMONIC:`; app names like `Ebra/Mlag/Stp` | (matches Cisco grammar) |
| **Nokia SR Linux** | `<app>: <subsys>\|<pid>\|<tid>\|<seq>\|<SEV-char>: <text>` where SEV ∈ {I,N,W,E,C…} | [Nokia SR Linux Logging][srl-log] |
| **Nokia SR OS (7750)** | numbered event `<seq> <severity> <app>-<sev>-<event-name>: <text>` | [Nokia SR OS event logs][sros-log] |
| **Junos** | RFC5424 structured-data: `… <proc> <pid> <MESSAGE-ID> [junos@2636.x.y SD-params] text` | [Junos structured-data][junos-sd] |
| **FortiOS** | space-separated `key="value"` incl. `devname=`,`logid=`,`type=`,`subtype=`,`level=` | already parsed, `vector.yaml:217` |

Key insight: each format has a **stable, vendor-specific "event identity token"** —
Cisco/Arista/NX-OS `MNEMONIC` (e.g. `UPDOWN`, `ADJCHANGE`), Junos `MESSAGE-ID`
(e.g. `UI_DBASE_LOGOUT_EVENT`, `RPD_BGP_NEIGHBOR_STATE_CHANGED`), SR Linux the
`<app>+<subsys>` pair, FortiOS `logid`. **That token, not the free text, is the
basis for classification and dedup** — it is the vendor's own stable message id.
This is exactly the napalm-logs model (vendor message-id → structured event).

### 1.3 Severity normalization

RFC 5424 severities are 0(emerg)…7(debug); `PRI = facility*8 + severity`
([RFC 5424][rfc5424]). The well-known trap: the transport PRI severity and the
*embedded* application level disagree (an app logs a routine check as `error`, or
sends `notice` PRI on a `W:`-marked warning). Vendors differ — Cisco treats 0–2 as
critical-by-default, Junos omits priority unless `explicit-priority`/structured-data
is on ([rsyslog severity][rsyslog-sev], [Last9 syslog levels][last9],
[Junos explicit-priority][junos-sd]). **The standard reconciliation is "take the
stronger (lower-numbered) of the two signals,"** then map to our 4-level engine
severity. We already do a weak version of this (FortiOS `level` overrides PRI at
`vector.yaml:232`); the design generalizes it.

### 1.4 Event identity / dedup keys

Alertmanager identifies an alert by a **fingerprint = hash of its full label
set**, and dedups/groups on labels ([Alertmanager grouping/dedup][am-dedup]). The
lesson: **identity is a deterministic function of the stable structural fields,
not of the rendered text.** Our correlation `Signal` already embodies this —
`signal_id = UUIDv5(source|native_id|ts_ms)` and `native_id` is built from
`host|kind|entity|state` (`signals.py:251`, `producers.py:262`). The
NormalizedEvent `message_key` should follow the same principle: a stable composite
of `(source, device, subsystem/facility, event_type, [entity])` — *never* the
free-text — so the same recurring condition collapses to one key across flaps. The
owner's example `syslog:spine2:sr_grpc_server:grpc_tls_profile_missing:EDA` is
precisely this shape.

---

## 2. Recommended end-to-end architecture

### 2.1 The four normalization stages and where each lives

The decisive constraint is **CLAUDE.md §6: the Go runtime stays stdlib-only; no
runtime MIB compiler, no runtime parser-rule engine pulling deps. Build-time
codegen IS allowed.** That dictates the split:

```
                         ┌───────────────────────────────────────────────────────────┐
                         │ BUILD TIME (offline, host has snmptranslate + vendored MIBs)│
                         │  mibs/  ──make mib-index──▶  oididx.json ──go:embed──▶ Go bin│
                         └───────────────────────────────────────────────────────────┘

 SNMP trap (UDP/162)            syslog (syslog-ng / 5514)             [future sources]
        │                               │
        ▼                               ▼
┌───────────────────┐         ┌───────────────────────────────────────────────┐
│ Go trap receiver  │         │ Vector aggregator — VRL                         │
│ collectors/       │  POST   │ syslog_normalized                               │
│  snmptrap.go      │ ───────▶│  Stage A: vendor classify (have it)             │   STAGE A+B+C
│  Stage A: BER     │ (HTTP   │  Stage B: per-vendor body parse → struct fields │   (cheap, hot-path,
│  Stage B: OID     │  src)   │  Stage C: severity reconcile                    │    no deps, hot-reload
│  decode via       │         │  Stage D(lite): taxonomy lookup (enrich table)  │    friendly)
│  EMBEDDED index   │         │  emit NormalizedEvent envelope                  │
│  (replaces map)   │         └───────────────────┬───────────────────────────┘
│  emit Normalized  │                             │
│  Event envelope   │─────────────────────────────┤  (trap receiver POSTs into the SAME
└───────────────────┘                             │   Vector http source → its VRL adds the
                                                   │   shared Stage C/D + envelope)
                                                   ▼
                                          Redpanda  netops.syslog / netops.snmptrap
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                     ▼
                 OpenSearch (search/UI, raw+normalized)            correlation service (Python)
                 netops-syslog-* / netops-snmptrap-*                producers.py
                                                                    Stage D(full): NormalizedEvent
                                                                    → Signal (control_plane), entity
                                                                    binding, episode/RCA. Unrecognized
                                                                    event_type ⇒ no Signal (anti-noise),
                                                                    stays searchable.
```

**Why this placement:**

- **OID decode (trap) → Go receiver, via embedded index.** The receiver already
  owns the BER decode and the `resolveVarbind`/`trapMeta` seam
  (`snmptrap.go:108,153`). Swapping the curated maps for an embedded-index lookup
  is a drop-in at exactly those two functions and keeps the decode where the bytes
  are decoded. The index is generated at build time and `go:embed`-ed, so the
  *runtime* adds no dependency and no I/O. This is the literal replacement for the
  hack and the core of **#26 + #32**.
- **Vendor body parse + severity reconcile → Vector VRL.** This is text/regex/kv
  work, it is already the established pattern for FortiOS/PAN
  (`vector.yaml:217`, firewall-onboarding memory), and VRL is **hot-reloadable**
  (SIGHUP / `--watch-config`) so a new vendor parser ships *without a backend
  redeploy*. Doing it in Go would (a) duplicate the syslog source Vector already
  owns and (b) require a backend deploy per vendor. This is **#31**.
- **Taxonomy classification → split.** A *lite* lookup (event_type → category/
  family/normalized-severity) belongs as an **enrichment table** consulted in VRL
  *and* readable by the trap receiver, so the canonical envelope is classified at
  emit time and searchable in OpenSearch. The *full* RCA mapping (event_type →
  `Signal.kind`, entity binding, modality) stays in the correlation service
  (`producers.py`) where the entity/seam model lives — but it now keys off the
  **already-parsed `event_type`** instead of re-running regexes on raw text. This
  removes the third curated map and the drift.
- **Inventory enrichment → Vector enrichment table** (`device_tenant` pattern,
  `vector.yaml:36`) extended; correlation re-resolves against the same source of
  truth (it already does — `producers.py` resolver).

### 2.2 Vector enrichment-table reload caveat (must design around)

Vector loads `enrichment_tables` of `type: file` **at config load only** — it does
*not* live-reload a changed CSV; you reload Vector (SIGHUP / restart) to pick up
changes ([Vector hot-reload issue #20276][vec-reload], [Vector discussion
#19782][vec-discuss]). The existing `device_tenant.csv` is already exported by the
API into a bind-mount (`docker-compose.yml:275`). **Design consequence:** the
*taxonomy* and *OID* tables are **slow-moving content artifacts**, not live data —
they should be (a) checked-in build artifacts for the embedded Go index, and (b)
for VRL, a generated CSV/file the API publishes the same way as `device_tenant`,
with a documented `vector reload` step (same operational pattern as the nginx
stale-bind-mount gotcha in memory). We do *not* need per-event hot updates; we
need "add a vendor/OID, regenerate, reload."

---

## 3. The NormalizedEvent contract (source-agnostic)

One schema that syslog, traps, and future log-shaped sources all produce. It is
the **log-plane analogue of the canonical `device_*` metric contract**, and it is
designed to feed Events/Anomalies/Incidents directly and to be the *single* input
`producers.py` reads to mint a `Signal`. It is additive to the existing
`TrapEvent` (`snmptrap.go:46`) and syslog docs — existing raw fields are retained
for search; these add the normalized layer.

```jsonc
{
  // ── identity & provenance ──────────────────────────────────────────────
  "schema": "netops.event.v1",
  "signal": "syslog | snmptrap",          // existing router key, unchanged
  "event_id": "uuid",                     // deterministic = UUIDv5(NS, message_key)
  "message_key": "syslog:spine2:sr_grpc_server:grpc_tls_profile_missing",
                                          // dedup identity (§5) — NEVER the raw text
  "ts_event": "RFC3339Nano",              // device/source clock
  "ts_ingest": "RFC3339Nano",             // receiver clock (clock-skew aware)

  // ── inventory enrichment (§6 in research; resolved fields) ──────────────
  "source_ip": "172.40.40.21",            // observed UDP src / syslog sender
  "device": "spine2",                     // resolved inventory id ("" if unmatched)
  "device_matched": true,                 // false ⇒ enrichment_status=unmatched
  "site": "fab1", "role": "spine",        // from inventory; "" when unknown
  "vendor": "nokia", "os": "srlinux",     // authoritative from SNMP sysObjectID;
                                          //   falls back to syslog-signature guess

  // ── decoded / parsed structure ─────────────────────────────────────────
  "subsystem": "sr_grpc_server",          // syslog app/subsys OR trap MIB module
  "facility": "GRPC",                     // Cisco FACILITY / syslog facility
  "event_type": "grpc_tls_profile_missing", // the vendor MNEMONIC / MESSAGE-ID /
                                          //   trap object name → normalized token
  "native_event": "tls-profile-not-found",   // vendor-native id, verbatim (audit)
  "category": "management_plane",         // taxonomy tier 1 (§4)
  "family": "grpc_tls",                   // taxonomy tier 2
  "severity": "warn",                     // engine severity (§ severity reconcile)
  "severity_source": "max(pri=notice, embedded=W)",   // how it was reconciled (audit)

  // ── entity binding (lets correlation skip re-parsing) ───────────────────
  "entity_type": "device | interface | path | peer | service",
  "entity_id": "spine2",                  // e.g. "spine2:Ethernet7", "spine2:10.0.0.5"
  "entity_tokens": ["spine2", "EDA"],     // weak tokens for the correlation graph

  // ── decoded payload (typed where known, raw kept) ──────────────────────
  "fields": {                             // structured kv after body parse
    "tls_profile": "EDA", "instance": "default"
  },
  "varbinds": [                           // traps only — now MIB-decoded
    {"oid":"1.3.6.1.2.1.2.2.1.8.7","name":"ifOperStatus",
     "type":"INTEGER","value":"2","label":"down","mib":"IF-MIB"}
  ],
  "trap_oid": "1.3.6.1.4.1.30065.3.…",    // traps only
  "trap_name": "aristaIfStateChange",     // traps only — from embedded index
  "message": "…rendered human line…",     // for the UI; derived, never parsed-from

  // ── pipeline state machine (observability of the normalizer itself) ─────
  "parser_status": "parsed",   // parsed | partial | unparsed | error
  "parser_id": "srlinux.v1",   // which vendor parser fired (audit / coverage metric)
  "enrichment_status": "matched",  // matched | unmatched | ambiguous
  "classify_status": "classified", // classified | unclassified (taxonomy miss)

  // ── tenancy (unchanged, already enforced) ──────────────────────────────
  "tenant_id": "",
  "authenticated": true        // traps: v3 verified; v1/v2c spoofable ⇒ false
}
```

### 3.1 The three status state-machines (no silent failure — CLAUDE.md §10)

These make the normalizer *observable* and let the UI be honest (memory:
"instrument-grade, honest empty states"):

- **`parser_status`** — `parsed` (vendor parser matched, all expected fields
  extracted) · `partial` (matched but some fields absent) · `unparsed` (no vendor
  parser matched the body — kept raw, searchable, never blocks) · `error`
  (parser threw / malformed). Each transition increments a metric; a rising
  `unparsed` rate for a vendor = a coverage gap, surfaced as a board panel.
- **`enrichment_status`** — `matched` (source resolved to one device) ·
  `unmatched` (no inventory match — emit with `device:""`, `tenant_id:""` →
  platform/global, never dropped) · `ambiguous` (source IP maps to >1 device, e.g.
  a collector relaying; flagged, lowest-confidence device chosen + logged).
- **`classify_status`** — `classified` (event_type found in taxonomy) ·
  `unclassified` (decoded but no taxonomy entry — stays searchable, mints **no**
  Signal: the existing anti-noise guardrail, `test_trap_classify.py:9`, now
  expressed as a first-class status not a silent `None`).

**Invariant: nothing is ever dropped for being un-parsed/un-classified.** Every
event lands in OpenSearch raw+decoded; only *RCA Signal creation* is gated, and
that gate is now a visible status, not a buried `return None`.

---

## 4. Classification taxonomy + maintainability

### 4.1 Three-tier taxonomy `category → family → event_type`

A fixed, small **category** set (tier 1) — the control-surface a NOC reasons in,
aligned to our existing `ModalityClass`/catalog domains
(`signals.py:49`, `catalog.py`):

| category | meaning | example families |
|---|---|---|
| `data_plane` | forwarding / interfaces / traffic | `link_state`, `if_errors`, `qos_drops`, `optics` |
| `control_plane` | routing / adjacency / signaling | `bgp`, `ospf`, `isis`, `lldp`, `stp`, `mpls`, `vrrp` |
| `management_plane` | mgmt access / config / APIs | `grpc_tls`, `aaa`, `config_change`, `netconf`, `snmp` |
| `platform_health` | device hardware / env / process | `psu`, `fan`, `temp`, `memory`, `process_crash`, `restart` |
| `security` | authn/authz/policy/threat | `auth_fail`, `acl_deny`, `threat`, `ips` |
| `service` | overlay / tunnel / SD-WAN / VPN | `ipsec`, `sdwan_path`, `evpn`, `l3vpn` |

- **tier 2 `family`** is an open-but-reviewed set under each category (above).
- **tier 3 `event_type`** is the normalized leaf, derived 1:1 from the vendor's own
  stable token (Cisco MNEMONIC `UPDOWN`→`link_state_change`, Junos
  `RPD_BGP_NEIGHBOR_STATE_CHANGED`→`bgp_adjacency_change`, trap `linkDown`→
  `link_state_change`, SR Linux subsys+text→`grpc_tls_profile_missing`).

This mirrors what `producers.py` already produces as `Signal.kind`
(`link_state_change`, `bgp_adjacency_change`, `isis_adjacency_change`) — so
`event_type` ⇒ `Signal.kind` becomes a *table*, not code.

### 4.2 The taxonomy as a checked-in data artifact (not code)

Author the taxonomy + the per-vendor `(vendor, native_token) → event_type, family,
category, normalized_severity, entity_hint` mapping as a **single versioned YAML/CSV
in `src/config/`** (sibling to the SNMP profile library which already works this
way — 173 profiles / 6,436 OIDs, tracker #6). Properties:

- **Content-hashed + schema-validated on load** — reuse the exact pattern
  `catalog.py` already uses for hypothesis templates (`CATALOG_SCHEMA_VERSION`,
  load-time pydantic validation, content hash as version). A malformed row is
  rejected at load, never half-applied.
- **CI-gated by fixtures** — for each mapped event, a sample raw line/PDU in
  `fixtures/` whose normalization output is asserted (mirrors the replay-fixture
  discipline in `catalog.py` docstring). Adding a vendor mapping without a fixture
  fails CI.
- **Two consumers, one source.** A `make` target renders this master file into
  (a) the VRL-readable enrichment CSV the API publishes, and (b) the Python loader
  reads it directly. The vendor *body grammar* (regex/kv) lives with the VRL parser
  (§ below); the *semantic mapping* lives here.

### 4.3 Adding a vendor / event without redeploy — what's actually possible

- **New `(vendor, token) → taxonomy` mapping:** edit the master file → `make` →
  publish CSV → `vector reload`. **No backend rebuild.** The body parser must
  already emit that token; if the token is already extracted (e.g. any Cisco
  MNEMONIC, any Junos MESSAGE-ID), this is pure data.
- **New vendor *body grammar* (a whole new format):** add a VRL parse branch in
  `syslog_normalized` (the firewall pattern) → `vector reload`. **No backend
  rebuild.** Hot-reloadable.
- **New trap MIB (new OIDs):** drop the `.mib` into `mibs/<vendor>/`, run
  `make mib-index`, **rebuild the Go binary** (the index is `go:embed`-ed). This is
  the one case needing a backend build — acceptable because MIBs change rarely and
  the alternative (runtime MIB compiler) violates §6. Frequency is low; batch them.

---

## 5. `message_key` (dedup identity) design

**Principle (from Alertmanager fingerprinting, §1.4):** identity = deterministic
hash of stable *structural* fields, never the free text.

```
message_key = "<signal>:<device|source_ip>:<subsystem>:<event_type>[:<entity_disc>]"
```

- `<signal>` — `syslog` / `snmptrap` (source class).
- `<device|source_ip>` — resolved device id, or source IP when unmatched (so an
  unknown sender still dedups stably).
- `<subsystem>` — syslog app/subsys or trap MIB module (`sr_grpc_server`, `IF-MIB`).
- `<event_type>` — the normalized leaf (§4).
- `<entity_disc>` — optional discriminator that keeps *distinct* objects distinct:
  the interface (`Ethernet7`), peer (`10.0.0.5`), or the owner's `EDA` tls-profile.
  Chosen from `entity_tokens` per the taxonomy `entity_hint`.

This yields the owner's target exactly:
`syslog:spine2:sr_grpc_server:grpc_tls_profile_missing:EDA`.

`event_id = UUIDv5(NS, message_key + bucket(ts))` for a coarse time bucket if we
want per-occurrence ids, or `UUIDv5(NS, message_key)` for a pure "condition"
identity that flaps collapse onto — recommend **both**: `message_key` for
dedup/grouping (the Alertmanager group key), `event_id` per occurrence for the
event log. This is consistent with `signals.py:251`'s `native_id`→`signal_id`
derivation, so traps and syslog feed correlation with the same identity discipline
they already use.

---

## 6. MIB-index generation + embed pipeline (the real fix for #26/#32)

### 6.1 What we generate

A single checked-in **`oididx.json`** (plus a small `oididx_meta.json` with the
content hash + source-MIB manifest), embedded into the Go binary via `go:embed`.
Schema, derived from what gosmi/snmptranslate expose and what
`resolveVarbind`/`trapMeta` need:

```jsonc
{
  "version": "sha256:…",          // content hash → logged at startup, replay-stable
  "generated": "2026-06-17",
  "mibs": ["IF-MIB","BGP4-MIB","ARISTA-…", …],  // manifest for audit
  "nodes": {
    "1.3.6.1.2.1.2.2.1.8": {                 // OID prefix (column, no row index)
      "name": "ifOperStatus", "mib": "IF-MIB",
      "type": "INTEGER", "kind": "column",
      "enum": {"1":"up","2":"down","3":"testing","4":"unknown",
               "5":"dormant","6":"notPresent","7":"lowerLayerDown"},
      "index": ["ifIndex"]                    // table INDEX clause
    },
    "1.3.6.1.6.3.1.1.5.3": {                  // notification
      "name":"linkDown","mib":"IF-MIB","kind":"notification",
      "severity_hint":"warning"               // optional curated overlay (§6.4)
    }
  }
}
```

Lookup at runtime is then: longest-prefix match for column OIDs (replacing the
linear `varbindObjects` scan, `snmptrap.go:157`), exact match for scalars/
notifications (replacing `varbindExact`/`wellKnownTraps`). Same two seams, real
coverage.

### 6.2 Generation pipeline — `make mib-index`

The host has `snmptranslate` but an **empty standard/vendor MIB store** (verified:
`IF-MIB` not found). So the pipeline **vendors the MIB source files** and compiles
from them — exactly the LibreNMS model. Recommended generator = **pysmi** (pure
Python, offline, emits JSON + index; already aligned with our Python tooling):

```
src/backend/collectors/mibs/
  ietf/        ← IF-MIB, BGP4-MIB, OSPF-TRAP-MIB, ENTITY-MIB, SNMPv2-MIB, …
  iana/        ← IANAifType-MIB, …
  vendor/
    arista/    ← ARISTA-*.mib  (enterprise 30065)
    cisco/     ← CISCO-*.mib   (9)
    juniper/   ← *-MIB         (2636)
    nokia/     ← TIMETRA-*, SRL-* (6527 / 6997)
    fortinet/  ← FORTINET-*    (12356)
  index/oididx.json            ← GENERATED, checked in
```

`make mib-index` (pseudostep, **build-time only**):

1. Run pysmi `mibdump --destination-format json --mib-source <each dir>` over the
   vendored tree → per-module JSON. (pysmi resolves IMPORTS across the tree
   offline.) ([pysmi compile-to-JSON][pysmi-json])
2. A small Python merger walks the per-module JSON, extracts for every
   object/notification: OID, name, base SYNTAX, enum named-values, table INDEX,
   owning module → flattens into the `nodes` map above.
3. Compute the content hash → `version`; write `oididx.json` + meta.
4. **Validation gate:** assert a fixed set of known OIDs resolve
   (`1.3.6.1.2.1.2.2.1.8`→`ifOperStatus` with the 7-value enum;
   `1.3.6.1.6.3.1.1.5.3`→`linkDown`) so a broken MIB tree fails the build, not prod.
5. `snmptranslate` (present on the host) is the **cross-check oracle** in CI: a
   sample of index entries is verified against `snmptranslate -Td` over the same
   vendored tree, so we don't trust a single compiler. (Dual-source, zero-trust on
   our own toolchain.)

The generator is **build-time tooling**, not a runtime import — fully compatible
with §6 (codegen is explicitly allowed; the runtime Go keeps only `embed` from
stdlib). Pin pysmi in a build-only `requirements` (it never ships in the API
image).

### 6.3 How vendors add MIBs (documented runbook)

1. Drop vendor `.mib` files into `collectors/mibs/vendor/<vendor>/`.
2. `make mib-index` → regenerates `oididx.json` (diff is reviewable in PR).
3. `go build` (the embed picks it up) → CI runs the resolve-assertions + fixtures.
4. Optionally add `severity_hint` overrides (§6.4) for that vendor's NOTIFICATIONs.

### 6.4 Severity from MIBs

MIBs carry no universal severity. So: derive a **`severity_hint`** at generation
time where the MIB *does* express it (some vendor MIBs annotate a perceived
severity / there are well-known IETF defaults like `linkDown`=warning), and allow a
tiny **curated YAML overlay** (`mibs/severity-overrides.yaml`) for the high-value
traps — a *much* smaller, MIB-anchored list than today's `wellKnownTraps`, used
only to *seed* severity, with final severity reconciled in Stage C (§ severity).

---

## 7. Severity normalization (Stage C)

```
engine_severity = map( strongest( pri_severity, embedded_severity, mib_severity_hint ) )
```

- **`pri_severity`** — RFC 5424 numeric 0–7 from the syslog PRI (already on the
  Vector syslog source). Traps have none → skip.
- **`embedded_severity`** — the level the body carries: Cisco/Arista/NX-OS the `-N-`
  digit in `%FAC-N-MNEMONIC`; SR Linux the `W:`/`E:`/`C:` char; Junos the PRI in SD;
  FortiOS `level=` (already lifted, `vector.yaml:232`).
- **`mib_severity_hint`** — for traps, from §6.4.
- **`strongest`** = lowest RFC-5424 number wins (emerg < … < debug), i.e. take the
  more-severe of the disagreeing signals (research §1.3). Record the inputs in
  `severity_source` for audit (no silent normalization).

Map to the 4-level engine `Severity` (`signals.py:66`):

| RFC 5424 | engine |
|---|---|
| 0 emerg, 1 alert, 2 crit | `crit` |
| 3 err | `high` |
| 4 warning | `warn` |
| 5 notice, 6 info, 7 debug | `info` |

(`high` for `err` matches the existing producer convention where a down adjacency
is `HIGH`.)

---

## 8. Syslog vendor-parser approach (Stage B, #31)

**Where:** Vector VRL `syslog_normalized` (`vector.yaml:167`), extending the
existing classifier→branch pattern. **Architecture = classify then branch:**

1. **Classify** (have it, `vector.yaml:195`) → `vendor` from signature. Keep the
   ordering rule (distinctive formats before the generic Cisco grammar Arista
   shares).
2. **Branch to a per-vendor parser**, each emitting the *same* normalized fields
   (`subsystem`, `facility`, `event_type`/`native_event`, `fields`,
   `embedded_severity`) and setting `parser_id` + `parser_status`:
   - **cisco / arista / nxos** — one shared parser: regex
     `%(?<facility>[A-Z][A-Z0-9_]+)-(?<sev>[0-7])-(?<mnemonic>[A-Z0-9_]+):\s*(?<text>.*)`;
     `event_type` = normalized(mnemonic); `embedded_severity` = sev. (One grammar
     covers three vendors — they converge.)
   - **srlinux** — split on `:` then `|`:
     `(?<app>\S+):\s*(?<subsys>[^|]+)\|(?<pid>\d+)\|(?<tid>\d+)\|(?<seq>\d+)\|(?<sevchar>[A-Z]):\s*(?<text>.*)`;
     map sev-char {I,N,W,E,C}→severity; `event_type` derived from
     `(subsys, leading-phrase)` via the taxonomy table.
   - **junos** — parse RFC5424 SD: `MESSAGE-ID` token + `[junos@2636.… k="v"]`
     params (`parse_key_value` on the SD body); `event_type` = normalized(MESSAGE-ID).
   - **sros** — numbered-event grammar (`<app>-<sev>-<event>`).
   - **fortinet / paloalto** — keep existing kv parsers (`vector.yaml:217`); add
     PAN comma-CSV parse (already classified at `:198`).
   - **fallthrough** — `parser_status="unparsed"`, body kept raw. Never errors the
     pipeline.
3. **Look up taxonomy** (Stage D-lite) via the enrichment table keyed
   `(vendor, event_type)` → `category/family/normalized_severity/entity_hint`;
   set `classify_status`.

**Adding a vendor without redeploy:** new branch = VRL edit + `vector reload`
(hot-reloadable, §2.2). VRL is **infallible-aware** (memory: firewall VRL
gotchas) — every `parse_*` uses the `, err` form and falls back rather than
aborting the event.

**Why not Go for syslog parsing:** Vector already owns the syslog source and PRI;
moving parse to Go duplicates ingestion and forces a backend deploy per vendor
grammar. Traps are the opposite — the bytes are decoded in Go already, so OID
decode stays there. This asymmetry is deliberate and follows where the data
already lives.

---

## 9. Inventory enrichment (research §5 → design)

**Problem:** the observed sender is often *not* the device — a collector relay, a
NAT egress, or (FortiOS) a source IP with the real name in `devname=`
(`vector.yaml:221`). Our `device_tenant` table keys on a generic `identity`
(hostname / sampler IP) already (`vector.yaml:36`).

**Recommendation — resolve in priority order, emit the resolution state:**

1. **In-body device id** wins (FortiOS `devname`, SR Linux/Cisco RFC5424 hostname
   that survives NAT — memory: "hostname survives NAT in the RFC5424 msg"). Already
   done for FortiOS; generalize: if the parsed body yields a hostname, prefer it.
2. **Source IP → inventory** (mgmt-IP, then any interface IP) — the trap receiver's
   `resolve()` (`snmptrap.go:706`) and the `device_tenant` table.
3. **Unmatched** → `device:""`, `enrichment_status:"unmatched"`, `tenant_id:""`
   (global/platform). **Emit anyway** — never drop. An unmatched event is a
   discovery signal (a device logging that we don't inventory yet).
4. **Ambiguous** (IP→>1 device, classic collector relay) →
   `enrichment_status:"ambiguous"`, pick lowest-confidence + log; surfaces as a
   coverage panel.

Enriched fields (`site`, `role`, `vendor`, `os`) come from the Device model /
NetBox SoT (memory: NetBox = single SoT). Extend the published enrichment CSV from
just `tenant_id` to `tenant_id,device,site,role,vendor,os` keyed by identity — one
table, more columns; correlation re-resolves against the same Device model it
already queries.

---

## 10. Stage-placement summary (the §7 question, answered)

| Stage | Lives in | Why (given stdlib §6 + hot-reload + data locality) |
|---|---|---|
| Trap BER decode | Go receiver (`snmptrap.go`) | bytes arrive there; already done |
| **Trap OID→name/type/enum** | **Go receiver + embedded `oididx.json`** | drop-in at `resolveVarbind`/`trapMeta`; runtime stays stdlib (index is build-time codegen + `go:embed`) — **replaces the curated map** |
| Syslog vendor body parse | **Vector VRL** | text work; Vector owns the syslog source + PRI; hot-reloadable → new vendor without backend deploy |
| Severity reconcile | Vector VRL (syslog) / Go (trap, via hint) | needs PRI (Vector has it) + embedded level (parser has it) |
| Taxonomy lookup (lite) | enrichment table read by VRL **and** Go | one mapping artifact, classified at emit, searchable |
| Inventory enrichment | enrichment table (Vector) + Device model (correlation) | existing `device_tenant` pattern, one SoT |
| event_type→Signal/entity (full RCA) | **correlation `producers.py`** | seam/entity/episode model lives there; now keys off parsed `event_type`, not raw regex — **removes the 3rd curated map** |

---

## 11. Phased implementation plan (maps to tracker #26/#31/#32)

> Each phase: interfaces/contract → impl → tests/fixtures → docs (CLAUDE.md §7,
> §11). Keep WIP uncommitted until validated (memory: research-before-implementing,
> ship-workflow). Every phase clears the standing security + premium-UI bar.

### Phase 0 — Contract freeze (prereq for all three tasks)
- Land the **NormalizedEvent schema** (§3) as a documented contract + a Python
  dataclass/validator alongside `signals.py` and a Go struct alongside `TrapEvent`.
- Land the **taxonomy master file** skeleton in `src/config/` + the loader/validator
  (reuse `catalog.py`'s hash+pydantic discipline) + the `message_key` builder.
- Tests: schema round-trip, message_key determinism, taxonomy load-rejects-malformed.

### Phase #26 — MIB index (the curated-map killer)
1. Vendor the MIB tree (`collectors/mibs/{ietf,iana,vendor/*}`); document sourcing.
2. `make mib-index` (pysmi compile → merge → hash → validate) producing
   `oididx.json` + meta (§6.2). pysmi pinned build-only.
3. Go runtime: `oidindex` loader (`go:embed oididx.json`), `Lookup(oid)` →
   `{name,type,enum,index,mib,severity_hint}`; longest-prefix for columns, exact
   for scalars/notifications.
4. Cut `snmptrap.go` over: `resolveVarbind` (`:153`) and `trapMeta` (`:108`) call
   the index; delete `wellKnownTraps`/`varbindObjects`/`varbindExact`/`genericTrapMeta`
   (keep only the IETF generic-trap fallback for OIDless v1).
5. Tests: resolve-assertions, `snmptranslate` cross-check in CI, regression on the
   existing `snmptrap_test.go` cases (linkDown/BGP still resolve), index-version
   logged at startup.

### Phase #32 — Trap normalization (envelope + classify)
1. Trap receiver emits the **NormalizedEvent envelope** (not just `TrapEvent`):
   fills `subsystem`(MIB module), `event_type`(trap object name→normalized),
   `category/family` via the taxonomy table, `severity` via reconcile+hint,
   `entity_*` from decoded varbinds (reuse the `_trap_interface` logic now in
   `producers.py:410`, moved to emit time), `message_key`, statuses.
2. `producers.py` `trap_control_signal` simplified to read `event_type`/`entity_id`
   from the envelope instead of re-decoding OIDs; unrecognized `event_type` ⇒
   `classify_status=unclassified` + no Signal (guardrail preserved,
   `test_trap_classify.py`).
3. Tests: extend `test_trap_classify.py` for envelope fields + the new enterprise
   OIDs the index now resolves (Arista/Cisco/Juniper/Nokia); ambiguous-source case.

### Phase #31 — Syslog normalization (vendor parsers)
1. Extend `syslog_normalized` VRL: per-vendor parse branches (§8) → normalized
   fields + `parser_status`/`parser_id`; severity reconcile (§7); taxonomy lookup;
   emit envelope. Keep FortiOS/PAN as-is, refactored into the same branch shape.
2. Publish the extended enrichment CSV (taxonomy + inventory columns) from the API;
   document the `vector reload` step (bind-mount reload gotcha, memory).
3. `producers.py` `syslog_control_signal` (`:224`) keys off `event_type` instead of
   re-running regexes; same Signal output, less code, no drift.
4. Tests: VRL unit fixtures per vendor (cisco/arista/nxos/srlinux/junos/sros/forti/
   pan) asserting normalized output; `parser_status=unparsed` fallthrough never
   drops; severity-reconcile table tests; producer parity test (same Signals out).

### Phase #33 (follow-on, optional) — coverage observability
- Board panels for `parser_status`/`classify_status`/`enrichment_status` rates by
  vendor (rising `unparsed`/`unclassified` = a coverage gap). Honest empty states.

---

## 12. Risks & guardrails (zero-trust, CLAUDE.md)

- **§6 dependency law:** pysmi is **build-time only**, never imported at runtime;
  Go runtime adds only stdlib `embed`. The MIB tree + `oididx.json` are checked-in
  artifacts → clean offline build preserved. (Document the pysmi build dep in a
  build-only manifest + the PR justification, but it does **not** enter `go.mod` or
  the API image.)
- **Untrusted input (§3, §8):** v1/v2c traps remain `authenticated:false`
  (spoofable — `snmptrap.go:57`) and parsed bodies are *data, never code* — no eval,
  regex bounded, VRL infallible-form mandatory.
- **No silent failure (§10):** every parse/enrich/classify miss is a *status*, not a
  dropped event or a buried `return None`. Coverage is a metric.
- **Tenancy (memory: engineering-rigor-tenancy):** enrichment still stamps
  `tenant_id` first; unmatched ⇒ global, never another tenant. The added columns
  carry no cross-tenant data.
- **Anti-overclaim:** decoding/classifying an event ≠ confirming a fault. RCA Signal
  creation stays gated by the correlation engine's ≥2-independent-modality rule
  (memory: rca-wording HARD RULE); the normalizer only produces honest evidence.

---

## Sources

- LibreNMS SNMP Trap Handler / MIB usage: <https://docs.librenms.org/Extensions/SNMP-Trap-Handler/> ; developing trap handlers <https://docs.librenms.org/Developing/SNMP-Traps/> ; vendor MIB tree <https://github.com/librenms/librenms/tree/master/mibs> [librenms-trap][librenms-mibs]
- Telegraf `snmp_trap` (gosmi) source: <https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/gosmi.go> ; README <https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/README.md> [tg-gosmi][tg-readme]
- gosmi node model: <https://github.com/sleepinggenius2/gosmi> [gosmi-node]
- pysmi (SNMP SMI compiler, JSON output + index): <https://github.com/etingof/pysmi> ; compile MIBs into JSON <https://docs.lextudio.com/pysmi/examples/download-and-compile-smistar-mibs-into-json> [pysmi][pysmi-json]
- RFC 5424 The Syslog Protocol: <https://www.rfc-editor.org/rfc/rfc5424.html> [rfc5424]
- rsyslog severity property: <https://docs.rsyslog.com/doc/reference/properties/message-syslogseverity.html> [rsyslog-sev] ; Last9 syslog levels <https://last9.io/blog/what-are-syslog-levels/> [last9]
- Cisco IOS-XE System Message Guide: <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/17_xe/syslogs/17-14-x/b-system-message-guide-17-14-x.html> [cisco-iosxe]
- Cisco NX-OS System Message Logging: <https://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/4_2/nx-os/system_management/configuration/guide/sm_nx_os_cli/sm_5syslog.html> [nxos] ; napalm-logs NX-OS model <https://napalm-logs.readthedocs.io/en/latest/syslog/nxos.html>
- Nokia SR Linux logging format: <https://documentation.nokia.com/srlinux/22-3/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-logging.html> ; ELK example <https://learn.srlinux.dev/blog/2023/sr-linux-logging-with-elk/> [srl-log] ; SR OS event logs <https://documentation.nokia.com/sr/25-7/7x50-shared/system-management/event-account-logs.html> [sros-log]
- Junos structured-data syslog: <https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html> [junos-sd]
- Prometheus Alertmanager grouping & deduplication (fingerprint=hash of labels): <https://deepwiki.com/grafana/prometheus-alertmanager/2.2-grouping-and-deduplication> [am-dedup]
- Vector enrichment-table reload limitation: <https://github.com/vectordotdev/vector/issues/20276> [vec-reload] ; <https://github.com/vectordotdev/vector/discussions/19782> [vec-discuss]

<!-- link refs -->
[librenms-trap]: https://docs.librenms.org/Extensions/SNMP-Trap-Handler/
[librenms-mibs]: https://github.com/librenms/librenms/tree/master/mibs
[tg-gosmi]: https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/gosmi.go
[tg-readme]: https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/README.md
[gosmi-node]: https://github.com/sleepinggenius2/gosmi
[pysmi]: https://github.com/etingof/pysmi
[pysmi-json]: https://docs.lextudio.com/pysmi/examples/download-and-compile-smistar-mibs-into-json
[rfc5424]: https://www.rfc-editor.org/rfc/rfc5424.html
[rsyslog-sev]: https://docs.rsyslog.com/doc/reference/properties/message-syslogseverity.html
[last9]: https://last9.io/blog/what-are-syslog-levels/
[cisco-iosxe]: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/17_xe/syslogs/17-14-x/b-system-message-guide-17-14-x.html
[nxos]: https://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/4_2/nx-os/system_management/configuration/guide/sm_nx_os_cli/sm_5syslog.html
[srl-log]: https://documentation.nokia.com/srlinux/22-3/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-logging.html
[sros-log]: https://documentation.nokia.com/sr/25-7/7x50-shared/system-management/event-account-logs.html
[junos-sd]: https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html
[am-dedup]: https://deepwiki.com/grafana/prometheus-alertmanager/2.2-grouping-and-deduplication
[vec-reload]: https://github.com/vectordotdev/vector/issues/20276
[vec-discuss]: https://github.com/vectordotdev/vector/discussions/19782
