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

### CISCO-BGP4-MIB and its imports (2026-11-03)

`CISCO-BGP4-MIB` and `CISCO-SMI` carry *"Copyright (c) ... Cisco Systems, Inc."*
with no redistribution grant, so they follow the Arista posture: fetched, never
vendored. They were already fetched at build time (unpinned, by pysmi) — pysmi
could not compile `CISCO-BGP4-MIB` because it imports the SMIv1 `BGP4-MIB`, so the
module contributed no nodes; the net-snmp pass compiles it from these pinned
files. The three IETF modules it imports are pinned the same way rather than
vendored.

| Module | URL(s), tried in order | sha256 |
|--------|------------------------|--------|
| `CISCO-BGP4-MIB` | https://mibs.pysnmp.com/asn1/CISCO-BGP4-MIB · https://raw.githubusercontent.com/librenms/librenms/master/mibs/cisco/CISCO-BGP4-MIB | `522ba3a3fa0b27be2bfe8902c4f8d74c77d610796b1fee1b5b8f40acbe3cb7a1` |
| `CISCO-SMI` | https://mibs.pysnmp.com/asn1/CISCO-SMI · https://raw.githubusercontent.com/librenms/librenms/master/mibs/cisco/CISCO-SMI | `3ea80f8160af50ba77e7309b7f95b4b6edb3ddc57dbe67eb0ee18ae1b56fd332` |
| `BGP4-MIB` (RFC 4273) | https://mibs.pysnmp.com/asn1/BGP4-MIB | `4dc18e17081988b15fad393bc68b36533a3edf4c8e66c0060d054f6ff6b3909b` |
| `INET-ADDRESS-MIB` (RFC 4001) | https://mibs.pysnmp.com/asn1/INET-ADDRESS-MIB | `59563805ec90609c31a1c512aa627fe58a95dfc6eeed53de12622a1493da27d1` |
| `SNMP-FRAMEWORK-MIB` (RFC 3411) | https://mibs.pysnmp.com/asn1/SNMP-FRAMEWORK-MIB | `bcf1faf35bb6dd9cbc06afb7eaf69e03d7da03893ee14df68ceb9424e23287bc` |

### Tracker 377 modules and their imports (2026-11-07)

`LLDP-MIB`, `RSTP-MIB`, `OLD-CISCO-INTERFACES-MIB` and `TIMETRA-BGP-MIB` sat in
`DEFAULT_MIBS` but pysmi IGNORED all four — each imports SMIv1 `RFC-1212` somewhere
in its chain, which pysmi cannot parse — so they contributed nothing. The net-snmp
pass now compiles them from these pinned files. All 22 are pinned to ONE LibreNMS
commit (an immutable URL), so `TIMETRA-BGP-MIB` comes from the same Nokia release as
the `TIMETRA-*` modules it imports. Nokia and Cisco text carries no redistribution
grant (owner 2026-11-07: extend the Arista posture to Nokia and Juniper) — fetched,
never vendored; the IEEE/IETF/IANA modules are pinned the same way.
`JUNIPER-CHASSIS-DEFINES-MIB` was REMOVED from `DEFAULT_MIBS` instead: it holds only
product-identity OIDs, decodes no trap, and pysmi rejects it (duplicate symbol).

| Module | URL | sha256 |
|--------|-----|--------|
| `ATM-TC-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/ATM-TC-MIB | `279a938f6d73bba203fb36e47cd702c02e3e54dc2f55608c960c4476ce6c5f82` |
| `HCNUM-TC` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/HCNUM-TC | `c8d21522e37294169277cab9a9e6e0dae85ce2a106af3e64429ece8f35b6835c` |
| `IANA-ADDRESS-FAMILY-NUMBERS-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IANA-ADDRESS-FAMILY-NUMBERS-MIB | `2c253fe33eb9266849c36f7aae39b059a910e98832026991f8fdf68260c08568` |
| `IANA-RTPROTO-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IANA-RTPROTO-MIB | `8848bde6c0141fa6b63a16bc78b6484a15b66b55c80d1c76f8c3cff453b98b87` |
| `IEEE8021-PAE-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IEEE8021-PAE-MIB | `cf94698475c0208a95c1697f502c17e0751c04f57f6640d739a8fcea32dd7c3f` |
| `IP-FORWARD-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IP-FORWARD-MIB | `6b55a19e712c0012cd2ac9813c5cddb10c93fdfa01e2e87c2c2fe14c41bd2a04` |
| `IP-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/IP-MIB | `6a6ec284b2de6f21a4d090927dba474a131c777d1c0b5a80a57fe21a7dd4a3d3` |
| `LLDP-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/LLDP-MIB | `f0dac7bac08b6d632d2f2363aba8acf106ee7cf83c15f14823489390c31d6769` |
| `OLD-CISCO-INTERFACES-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/cisco/OLD-CISCO-INTERFACES-MIB | `67bef549d12ee67d01c648346283badb38f49884ac48f83047f746947a7b4342` |
| `RFC-1215` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/RFC-1215 | `dbd38e3a42cb0b391e9dafa606a5ee11ff2dcdd4c6781cb42ae1cd6185bcc4e2` |
| `RSTP-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/RSTP-MIB | `235203e6c465bad9bee34b6c5ad34d5e61a83e37ca0162a694417c2c87bb8409` |
| `SNMPv2-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/SNMPv2-MIB | `b4f8ef130f580b86d2b6bc890564e46100785f589431df76954e878a7b166e11` |
| `TIMETRA-BGP-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-BGP-MIB | `b91f895f0ff3a9a4e597fe912900fc1f69ee72f993d522b39ccb4501ef85a023` |
| `TIMETRA-CHASSIS-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-CHASSIS-MIB | `891e287f4d379d65e498dcc476b8e6afa04c9f82856cb78f1b586a833bbb00b1` |
| `TIMETRA-FILTER-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-FILTER-MIB | `44fce8b1f8e80fb03764ec9566af5dc5067edcacbcff9734a672d5feb281c4bc` |
| `TIMETRA-GLOBAL-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-GLOBAL-MIB | `a3a18503892c9bc6c77a1a4969ac43b9f20f76e6d1dd2d6bcf9d4228a7bd7169` |
| `TIMETRA-PORT-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-PORT-MIB | `0a3368d31d7ee6f95a9c8540be77ff820518c549fb59d9eceb1620a982acc331` |
| `TIMETRA-QOS-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-QOS-MIB | `6091dc29d35807b252cc6ff85d06f5412423ee61eda047d1f3b9e91b1c46ae35` |
| `TIMETRA-SAP-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-SAP-MIB | `9e3c006ae30563a22a2ce4e40ffee811e90bd6fa83022a58d49d9e8cb1eea9ac` |
| `TIMETRA-SERV-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-SERV-MIB | `01fee2cf5adeced4137bd921807b3f7c157c645114fc2abf1b584f61754b2edf` |
| `TIMETRA-TC-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-TC-MIB | `e970f2099fffec00d08b71eca070f11eba4edd8c84123846eaddb5f99314e45a` |
| `TIMETRA-VRTR-MIB` | https://raw.githubusercontent.com/librenms/librenms/a7de98cfe060297622f64c4bffa5f8c5f9d8a8e5/mibs/nokia/TIMETRA-VRTR-MIB | `72729fdd64382e64b255e2c2f64ae9e3167428755c231df1fa01ef763318b424` |

**Fail closed.** The mirror is untrusted (CLAUDE.md §3): every byte, freshly
downloaded *or already cached*, is checked against the pinned sha256 before the
parser sees it. A missing/short pin, a moved upstream, or an edited cache file is
a **hard error** naming the file, the expected sum and the observed one. The one
non-fatal degradation is the operator's **explicit** opt-out, `MIB_FETCH=0`,
which is announced on stderr — see `README.md`, "No network".

Update: drop the module + its IMPORTS closure here, re-run `make mib-index`.
If the module is not redistributable, add it to `FETCH_PINS` instead.
