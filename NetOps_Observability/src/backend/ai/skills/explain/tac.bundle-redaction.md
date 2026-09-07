---
topic: tac.bundle-redaction
question: What is masked in the TAC bundle, and what is kept?
keywords: redacted bundle, masked in the bundle, tac bundle redaction, what is removed
---
The server builds the bundle and redacts it before you ever see it. Anything
that authenticates is masked: passwords, pre-shared and private keys, SNMP
community strings, API tokens and bearer credentials. Anything that identifies
the network is kept, because a vendor cannot troubleshoot without it —
hostnames, interface names, IP addresses, prefixes, VRF and AS numbers, and the
command output around them. Redaction happens on the server, so a masked value
never reaches your browser and never reaches the vendor. The plan's own
redaction note carries the exact promise for this platform; hover the line to
read it. Review the bundle before you send it — nothing leaves Correlix until a
person sends it.
