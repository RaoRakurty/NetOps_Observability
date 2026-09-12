# Vendored MIB tree (compiled at build time with net-snmp `snmptranslate`)

Real MIB module files for the modules pysmi 2.0 cannot compile (it fails on the
SMIv1 RFC-1212 `OBJECT-TYPE` macro, which blocks the entire bridge-MIB family).
net-snmp parses SMIv1 correctly, so these are compiled with snmptranslate instead.

Everything in this directory is checked in and therefore **ships in the customer
source tarball**, so everything here must be redistributable. That is the rule
the two sections below implement.

## Vendored here (IETF RFC Code Components, redistributable)

Sources (pulled 2026-06-17): `https://mibs.pysnmp.com/asn1/<MODULE>`

`BRIDGE-MIB`, `P-BRIDGE-MIB`, `Q-BRIDGE-MIB`, `IF-MIB`, `IANAifType-MIB`,
`RMON-MIB`, `RMON2-MIB`, `TOKEN-RING-RMON-MIB`, `RFC1213-MIB`, `RFC1155-SMI`,
`RFC-1212`, `SNMPv2-SMI`, `SNMPv2-TC`, `SNMPv2-CONF`.

MIB modules published in an RFC are **Code Components**: the IETF Trust's Legal
Provisions Relating to IETF Documents licence them under the BSD licence set out
in Section 4.e of those provisions (https://trustee.ietf.org/license-info), so
redistribution is permitted with the notice.

### `SNMPv2-TC` / `SNMPv2-CONF` — re-derived from the RFCs (2026-09-04)

These two were previously **Cisco's** edited extracts (`SNMPv2-TC.my` /
`SNMPv2-CONF.my`, headed *"Copyright (c) 1994,1996 by cisco Systems, Inc. All
rights reserved."*) with no licence grant — licence audit 2026-09-03, finding D3.
They have been replaced with the canonical IETF module text:

| File | RFC | URL | sha256 of the fetched RFC .txt |
|------|-----|-----|--------------------------------|
| `SNMPv2-TC` | RFC 2579 (STD 58), *Textual Conventions for SMIv2*, April 1999 | https://www.rfc-editor.org/rfc/rfc2579.txt | `1bde590451bdd6441af9dc4648ed02529816ea11f5f42b52a5f5d42066ea7440` |
| `SNMPv2-CONF` | RFC 2580 (STD 58), *Conformance Statements for SMIv2*, April 1999 | https://www.rfc-editor.org/rfc/rfc2580.txt | `b5ca6c4466c80125a39d7a5f6274cb7711cd7cffc0b4bf015386ca299f0061d1` |

Each file is the RFC's section-2 module verbatim, from `<MODULE> DEFINITIONS ::=
BEGIN` to the module's own `END`, with only the RFC page headers, footers and
form feeds removed, plus a comment header recording the provenance and the IETF
Trust licence. The extraction was cross-checked against net-snmp's upstream
copies of the same modules
(`https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-{TC,CONF}.txt`):
**identical modulo whitespace runs**.

Two things differ from the Cisco extracts and both are deliberate:

- The Cisco files said *"all macro definitions have been removed because they are
  predefined in the mib compiler"* — `SNMPv2-CONF` was an empty stub. The RFC
  modules **do** define `TEXTUAL-CONVENTION` (2579) and `OBJECT-GROUP`,
  `NOTIFICATION-GROUP`, `MODULE-COMPLIANCE`, `AGENT-CAPABILITIES` (2580). net-snmp
  handles those natively and does **not** complain about redefinition: verified
  empirically, `snmptranslate -M <tree> -m ALL` emits byte-identical `-Tz` output
  and byte-identical stderr before and after the swap, and `gen_index.netsnmp_nodes()`
  returns the same 232 nodes.
- An SMI comment ends at the **second** `--` on a line. The header comments
  therefore carry exactly one `--` per line — an inline `-- https://…` silently
  turns the rest of the line into live tokens and net-snmp then fails to register
  the whole module. Keep it that way if you edit the headers.

## NOT vendored — fetched at build time (`.fetched/`, gitignored)

`ARISTA-SMI-MIB` and `ARISTA-BRIDGE-EXT-MIB` carry *"Copyright (c) 2008 Arista
Networks, Inc. All rights reserved."* with **no licence grant** (licence audit
2026-09-03, finding D4). They are **not redistributed by this repo**: they were
deleted from this directory on 2026-09-04 and are now obtained the same way the
other ~55 vendor MIBs already are — at build time, from a mirror.

`gen_index.py` (`FETCH_PINS`) downloads them into `vendored/.fetched/`, which is
gitignored and which the `snmptranslate -M` search path includes alongside this
directory:

| Module | URL(s), tried in order | sha256 |
|--------|------------------------|--------|
| `ARISTA-SMI-MIB` | https://mibs.pysnmp.com/asn1/ARISTA-SMI-MIB · https://raw.githubusercontent.com/librenms/librenms/master/mibs/arista/ARISTA-SMI-MIB | `0f909eea68ad7144ebc82c3d140653c0faa31e66f6de439921c3e4a4a11ca4e3` |
| `ARISTA-BRIDGE-EXT-MIB` | https://mibs.pysnmp.com/asn1/ARISTA-BRIDGE-EXT-MIB | `9cb0cc8b5cd2cb26179d2eb1e0a7eb1d5e74e099b8459668fc039b9fa355c8ff` |

Both sums are those of the files that used to be vendored here, so the fetch is
a relocation, not a content change.

**Fail closed.** The mirror is untrusted (CLAUDE.md §3): every byte, freshly
downloaded *or already cached*, is checked against the pinned sha256 before the
parser sees it. A missing/short pin, a moved upstream, or an edited cache file is
a **hard error** naming the file, the expected sum and the observed one. The one
non-fatal degradation is the operator's **explicit** opt-out, `MIB_FETCH=0`,
which is announced on stderr — see `README.md`, "No network".

Update: drop the module + its IMPORTS closure here, re-run `make mib-index`.
If the module is not redistributable, add it to `FETCH_PINS` instead.
