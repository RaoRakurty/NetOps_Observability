# MIB registry → embedded OID index (#26)

This directory is the **vendored MIB tree** + the **generated OID index** that
gives the SNMP trap receiver real, MIB-backed OID→name/type/enum decode — replacing
the old hand-curated maps in `snmptrap.go`. Design + rationale:
`docs/design/research/telemetry-normalization-architecture.md` §6.

## How it works (and why it's stdlib-safe)

```
mibs/{ietf,iana,vendor/<vendor>}/*.mib   ──make mib-index──▶   index/oididx.json
                                          (pysmi, BUILD-TIME)        │
                                                                     ▼  go:embed
                                                  collectors/oidindex.go (runtime: pure lookup)
```

The Go **runtime stays stdlib-only** (CLAUDE.md §6): no MIB compiler, no new module.
`oididx.json` is a checked-in build artifact, embedded via `go:embed`. The compiler
(**pysmi**, pure-Python, offline) is **build-time tooling only** — it never enters
`go.mod` or the API image.

`index/oididx.json` is the compiled index of every module in `gen_index.py`:
`DEFAULT_MIBS` through pysmi and the `NETSNMP_ROOTS` subtrees through net-snmp. It
covers the standard MIBs and the enterprise trees of Arista (30065), Cisco (9),
Juniper (2636), Nokia (6527) and Cisco SD-WAN's Viptela OS (41916). An OID in no
compiled module, which means most other enterprises today, stays honestly raw:
`enterpriseSpecific` with its numeric OID.

## Add a vendor's traps (runbook)

1. Pin the vendor's modules in `gen_index.py` `FETCH_PINS`, with the import chain
   the vendored tree lacks: an exact commit in the URL and a sha256. Add the trap
   subtrees to `NETSNMP_ROOTS`. Record source and licence in `vendored/SOURCES.md` and
   `scripts/license-data.json`. Only a module with a redistribution grant may be
   checked in, under `vendored/` (see "What we redistribute" below).
2. `make mib-index` — runs pysmi over the tree → regenerates `index/oididx.json`
   (the diff is reviewable in the PR), recomputes the content-hash `version`, and
   runs the resolve-assertions + `snmptranslate` cross-check.
3. `go build ./...` — `go:embed` picks up the new index; `go test ./collectors/`
   runs `oidindex_test.go` + the trap fixtures.
4. Commit the regenerated `oididx.json`, then write the vendor's trap pack (below).

MIBs change rarely, so a backend rebuild per MIB batch is acceptable (the design
rejects a runtime MIB compiler as a §6 violation). No trap-receiver code changes —
only data.

`gen_index.py` starts from the checked-in index, so a regeneration can add and
correct nodes but never drop one (`CLEAN=1` opts out). Compare the node diff before
committing: an unexpected removal or rename is a finding.

## Trap packs: what a decoded trap means (tracker 387)

The index knows what a MIB states: names, types, enums. `packs/*.json` holds what a
MIB cannot state: which object is the vendor's own severity, which one says whether
the condition raised or cleared, and which text is really a number. The receiver
(`collectors/trap_semantics.go`) names no vendor. **Adding a vendor means adding its
MIB pins and a pack, with no code change.**
`TestTrapSemantics_SecondEnterpriseThroughDataOnly` proves it with an enterprise that
exists nowhere else, and `TestTrapPacks_EmbeddedLoadClean` fails on a pack row whose
OID, name or enum label is not what the index says.

```json
{"schema": 1, "pack": "acme", "source": "where each fact comes from",
 "objects": {
   "<object OID>": {"name": "acmeLevel", "role": "native_severity",
                    "normalized": {"sev-high": "crit", "sev-low": "warning"}},
   "<object OID>": {"name": "acmeNote", "role": "summary", "field": "note", "type": "string"},
   "<object OID>": {"name": "acmeTemp", "field": "temperature_c", "type": "float"}},
 "notifications": {
   "<OID>": {"name": "acmePortChange", "fidelity": "doc_claimed", "category": "data_plane", "family": "ports",
             "state_object": "<object OID>", "raise": ["broken"], "clear": ["healthy"]},
   "<OID>": {"name": "acmeFabricDown", "fidelity": "doc_claimed", "event_state": "raise"},
   "<OID>": {"name": "acmeHeat", "fidelity": "doc_claimed", "text_object": "<object OID>",
             "text": [{"contains": ["cooled"], "state": "clear", "fidelity": "lab_validated"}]}}}
```

Rules a pack follows:

- **Keyed by OID**, with the name beside it as a check. A name is not unique across
  modules; `netconfNotificationSeverity` is defined by five.
- **State needs evidence.** A state object is preferred, then wording, and a value
  or wording outside the row reads `point`. Each wording carries its own fidelity,
  because a captured recovery says nothing about how the raise is worded.
- **Fidelity is honest:** `doc_claimed` until a real capture replays in a fixture.
- **A listed notification needs a typed rule** in `telemetry-catalog/events.yaml` for
  every state it can report. Its normalized severity follows the vendor's, and only
  a typed rule may decide what that opens (`test_every_pack_state_has_a_typed_row`).
  An unlisted notification keeps its `SEVERITY_HINT`, whatever the vendor calls it.

### Semantics: peers, metrics, titles and guidance (tracker 387)

The same packs carry what an operator reads first (`collectors/trap_enrich.go`):

- `objects[*].attr`: the meaning an object carries, from a closed set (`peer_address`,
  `peer_afi`, `peer_as`, `local_address`, `routing_instance`, `bgp_state`,
  `bgp_prev_state`, `bgp_last_error`, `bgp_error_code`/`_subcode`,
  `bgp_last_error_text`, `if_admin_status`, `if_oper_status`). It is read from a
  varbind's value AND from the row index of any varbind whose table indexes by that
  object: `gen_index.py` writes every column's INDEX clause (`index`, `index_oids`,
  `index_syntax`, `index_implied`), so the receiver decodes a suffix with no table
  named in code. A suffix that does not decode exactly is `peer_basis=unparsed`.
- `objects[*].min`/`max`/`unit`: a typed number's legal range. Out of range or
  unparsable → omitted, named in `metrics_invalid`.
- `objects[*].extract`: a number the vendor states in its own text (today only
  `threshold_reported_percent`, which is never presented as a configured threshold).
- `derived`: a metric computed from observed ones (`complement`: base - of), with the
  formula the UI shows.
- `tables`: a vendor's documented deviation from its own MIB's index encoding
  (`bare_address_index`), with its fidelity.
- `title_templates` + `titles`: the wording per notification. `{field}` is required,
  `[ ... ]` is dropped when a field inside is missing, `{field=value}` is a guard. A
  notification with no wording keeps the old summary (`title_basis=fallback`).
- `guidance`: per family (or `family.transition_class`), impact and next checks,
  vendor-neutral, never a diagnosis; `expects` names the fields such an event should
  carry, and the ones missing are listed in `enrichment.unknown`.

Regenerate only the INDEX clauses, leaving every node otherwise untouched:
`INDEX_ONLY=1 python3 gen_index.py`.

A varbind always keeps its numeric OID and `raw_value`; everything else is added
beside them. Fields on the event: `severity_native_text`, `severity_native_code`,
`event_state` (`raise|clear|point`), `event_state_fidelity`, `mib_module`,
`mib_bundle_version` (the index `version`), `device_event_time`, `values` (typed
numbers), and per varbind `type`, `enum_label`, `time`, `num`.

## Cisco SD-WAN: which directory, and which release

`github.com/cisco/cisco-mibs` is pinned at one commit
(`c9ab98c03ee051de74edda72f6d5c43ee65cad91`). It has no directory for the lab's
releases (Viptela OS 20.6.1, IOS XE 17.03), so the arcs were compared across every
directory it does have.

| Platform | Directory | Tree | What the comparison shows |
|---|---|---|---|
| vEdge (Viptela OS) and the controllers | `sdwan/controller/<release>/VIPTELA-TRAPS.mib` | `41916.100` | Every notification and varbind arc is identical from 20.9 to 26.1. 20.12 holds all 123 notifications; a trap captured from a 20.6.1 vEdge matches it. |
| cEdge (IOS XE SD-WAN) | `sdwan/device/<release>/CISCO-SDWAN-*.my` | `9.9.1002`, `1003`, `1006` | Notification arcs are stable from 17.9 to 26.1, as are the OMP and security varbinds. **BFD varbinds move** (17.9, 17.12 and 26.1 differ), so only BFD's notifications are indexed and its varbinds stay numeric until a capture says which layout a device sends. |

A vEdge trap is never decoded through the cEdge tree or the reverse: they are
different OIDs. Each module name has one pinned file, so releases cannot clash, and
`gen_index.py` keys everything by OID because the same symbol recurs across modules.

## Multi-vendor coverage + software-version ↔ MIB matching (#34)

**General, not one trap.** Decode is vendor-agnostic: any OID whose MIB is in the
manifest resolves. Add a vendor by listing its modules in `gen_index.py`
`DEFAULT_MIBS` and ensuring a `--mib-source` reaches them (the LibreNMS mirror
covers Cisco/Juniper/Nokia/Arista/Fortinet). Arista (30065) is proven end-to-end;
Cisco/Juniper/Nokia are the same list-and-`make` step.

**Two compilers (why).** pysmi 2.0 is the primary compiler (fetches from the
mirrors, no local files), but it **cannot parse the SMIv1 `RFC-1212` `OBJECT-TYPE`
macro**, which blocks the entire bridge-MIB family (BRIDGE/P-BRIDGE/Q-BRIDGE +
vendor extensions like ARISTA-BRIDGE-EXT-MIB). For those, the generator runs a
**net-snmp `snmptranslate` pass over the vendored tree in `mibs/vendored/`** (the
real `.mib` files), which parses SMIv1 correctly and is authoritative for its
subtrees (`NETSNMP_ROOTS`). To add an SMIv1-family module: drop it + its IMPORTS
closure into `mibs/vendored/`, add its root to `NETSNMP_ROOTS`, `make mib-index`.
The tiny `STD_OVERLAY` now holds **only** OIDs no compiler can supply — e.g. the
Arista `30065.3.2.0.x` v1-form traps, which carry no `NOTIFICATION-TYPE` in any MIB.

## What we redistribute, and what we fetch (licence audit 2026-09-03)

`mibs/vendored/` is checked in and therefore **ships in the customer source
tarball**, so only redistributable modules may live there. Today that means IETF
RFC modules, which are RFC **Code Components** licensed under the BSD terms of
the IETF Trust Legal Provisions §4.e (https://trustee.ietf.org/license-info).
`SNMPv2-TC` and `SNMPv2-CONF` were Cisco's edited extracts with no licence grant
(audit finding D3) and are now the canonical RFC 2579 / RFC 2580 module text.

**Arista's MIBs are FETCHED at build time and NOT redistributed.**
`ARISTA-SMI-MIB` and `ARISTA-BRIDGE-EXT-MIB` carry *"Copyright (c) 2008 Arista
Networks, Inc. All rights reserved."* with no grant (audit finding D4), so they
were removed from the tree. `gen_index.py`'s `FETCH_PINS` downloads them —
**pinned URL + pinned sha256** — into `mibs/vendored/.fetched/`, which is
gitignored and which the `snmptranslate -M` path includes. Every byte is verified
against the pin *whether it was just downloaded or was already cached*: a moved
upstream, an edited cache file, or a pin with no sum is a **hard error** naming
the file and both sums. See `vendored/SOURCES.md` for the exact pins.

**Air-gapped build host.** The cache is a plain directory, so a build host with
no egress can be pre-populated by hand: drop the two files into
`mibs/vendored/.fetched/` and re-run. They are checked against the same pins on
every run, so a hand-placed file is verified exactly like a downloaded one —
local provenance is not trusted provenance (the same stance
`make-installer.sh`'s `CORRELIX_SOURCE_MIRROR_DIR` takes for the source offer).

**No network.** The only non-fatal degradation is the operator's **explicit**
opt-out, `MIB_FETCH=0`; a fetch that is attempted and fails is fatal, so "I could
not reach the mirror" can never be mistaken for "I chose not to." `MIB_FETCH=0`
prints a warning naming what it costs, and the cost is small and bounded:

- The net-snmp pass loses exactly **8 OIDs** under `1.3.6.1.4.1.30065.3.2`
  (`aristaDot1qTpFdbTable`/`Entry`, its three columns, and the three conformance
  nodes) — measured, not estimated.
- Everything else about an Arista device still decodes: the standard IETF MIBs
  are vendored, so `IF-MIB`, `BRIDGE-MIB`, `Q-BRIDGE-MIB`, `SNMPv2-MIB` varbinds
  resolve as usual.
- The `STD_OVERLAY` entries for `1.3.6.1.4.1.30065.3.2.0.1` and `.0.2`
  (`aristaBridgeExtMacMove`, `severity_hint: warning`) are **hand-anchored in
  `gen_index.py`, not read from any MIB file**, so the Arista v1-form MAC-move
  traps keep their name and their above-the-floor severity with no network at all.
- `main()` starts from the checked-in `index/oididx.json` as a floor, so an
  offline regeneration keeps whatever the committed index already holds
  (including those 8 OIDs) — it cannot shrink. `CLEAN=1` opts out of the floor
  and *would* drop them; that is what `CLEAN=1` is for.

**Offline installs are unaffected — verified, not assumed.** MIB compilation is a
**dev-time** step (`make mib-index`) and nothing in the install or image-build
path invokes it: `scripts/install.py`, `scripts/make-installer.sh`,
`deployment/docker/Dockerfile.backend` and the compose files contain no reference
to `gen_index.py`, `mib-index`, `mibdump`, `snmptranslate` or `mibs/`. The
backend build needs exactly one MIB artifact, `mibs/index/oididx.json`, which is
**checked in** and pulled into the binary by `//go:embed` in
`collectors/oidindex.go`. So `correlix-source-*.tar.gz` (a `git archive HEAD`)
carries the index it needs — and the customer does not even compile: the bundle
also ships `correlix-images-*.tar.zst`, prebuilt images the installer `docker
load`s, so the binary (index already embedded) is produced on the *build* host.
An operator with no network installs and runs with full trap decode either way.
Removing the Arista modules is **not** redistribution by another name: nothing in
the shipped path ever needed the module files.

**Cisco SD-WAN and BFD-STD-MIB follow the same posture** (tracker 387, `vendored/SOURCES.md`).
The trap decode needs only the checked-in index, so CI and offline builds never fetch them.

**Version matching.** MIBs evolve across NOS versions (new OIDs appear; rarely
semantics shift). The rigorous model: a device's `sysObjectID` + `sysDescr` →
vendor + model + **NOS version** → the version-appropriate MIB set. Current stance
(pragmatic, matches LibreNMS/Telegraf): ship the **latest** vendor MIBs — OID→name
decode is overwhelmingly version-stable/backward-compatible, and newer MIBs are a
superset. The next layer (tracked #34): record each MIB's `REVISION`/`LAST-UPDATED`
in the index meta, organize `vendor/<vendor>/<nos-train>/` where a version actually
diverges, and select the MIB set by the device's detected version. Until then,
decode is "best known definition," and an un-vendored OID stays honestly raw.

## Index schema (`index/oididx.json`)

`version` is the content hash of the nodes; the receiver stamps it on every decoded
trap as `mib_bundle_version`.

`nodes[oid] = { name, mib, kind: scalar|column|notification, type?, enum?{val:label},
index?[], severity_hint? }`. Runtime lookup: exact for scalars/notifications,
longest dotted-prefix for table columns (the trailing arcs are the row index).
