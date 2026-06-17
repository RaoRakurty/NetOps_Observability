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

## Index schema (`index/oididx.json`)

`nodes[oid] = { name, mib, kind: scalar|column|notification, type?, enum?{val:label},
index?[], severity_hint? }`. Runtime lookup: exact for scalars/notifications,
longest dotted-prefix for table columns (the trailing arcs are the row index).
