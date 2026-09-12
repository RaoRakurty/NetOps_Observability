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

`index/oididx.json` today is a **seed** migrated 1:1 from the former curated maps
(IF-MIB / SNMPv2-MIB / BGP4-MIB / OSPF / ENTITY / Cisco config-change). Enterprise
trees (Arista 30065, Cisco 9, Juniper 2636, Nokia 6527) decode as raw OIDs **until
their MIBs are vendored here** and the index is regenerated.

## Add a vendor's traps (runbook)

1. Drop the vendor's `.mib` files into `mibs/vendor/<vendor>/` (and any IETF/IANA
   imports they need into `mibs/ietf/` / `mibs/iana/`). Note the source + license
   in a `SOURCES.md` per vendor dir (zero-trust provenance).
2. `make mib-index` — runs pysmi over the tree → regenerates `index/oididx.json`
   (the diff is reviewable in the PR), recomputes the content-hash `version`, and
   runs the resolve-assertions + `snmptranslate` cross-check.
3. `go build ./...` — `go:embed` picks up the new index; `go test ./collectors/`
   runs `oidindex_test.go` + the trap fixtures.
4. Commit the `.mib` files **and** the regenerated `oididx.json` together.

MIBs change rarely, so a backend rebuild per MIB batch is acceptable (the design
rejects a runtime MIB compiler as a §6 violation). No trap-receiver code changes —
only data.

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

`nodes[oid] = { name, mib, kind: scalar|column|notification, type?, enum?{val:label},
index?[], severity_hint? }`. Runtime lookup: exact for scalars/notifications,
longest dotted-prefix for table columns (the trailing arcs are the row index).
