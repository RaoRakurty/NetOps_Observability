# Vendored MIB tree (compiled at build time with net-snmp `snmptranslate`)

Real MIB module files for the modules pysmi 2.0 cannot compile (it fails on the
SMIv1 RFC-1212 `OBJECT-TYPE` macro, which blocks the entire bridge-MIB family).
net-snmp parses SMIv1 correctly, so these are compiled with snmptranslate instead.

Sources (pulled 2026-06-17):
- IETF / SMIv1 bases + standard MIBs: https://mibs.pysnmp.com/asn1/<MODULE>
- ARISTA-SMI-MIB: https://github.com/librenms/librenms (mibs/arista)
- ARISTA-BRIDGE-EXT-MIB: Arista published module (verified OID assignments)

Update: drop the module + its IMPORTS closure here, re-run `make mib-index`.
