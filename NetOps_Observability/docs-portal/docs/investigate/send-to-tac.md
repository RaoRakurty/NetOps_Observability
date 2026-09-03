---
title: Export a redacted bundle for vendor support
description: Export the shareable TAC text bundle from a protocol-diagnostics run, with secrets masked before the file exists.
page_type: task
sidebar_position: 8
---

# Export a redacted bundle for vendor support

When a routing fault has to go to a vendor's TAC, the useful artefact is the
evidence, not a screenshot. The TAC bundle is a plain-text file with the device
context, the analysis, and every captured command output, run through the
redaction pass on the server before the file exists.

## Before you begin

- `infrastructure:read`. The bundle reveals nothing the caller did not already
  supply or capture.
- A completed analysis for the issue. The bundle is built from the redacted
  capture plus the analysis, so **Send to TAC** before analyzing answers:

  ```text
  Analyze the output first — the TAC bundle is built from the redacted capture plus the analysis.
  ```

- Know what redaction does and does not do. It masks the secret value and keeps
  the surrounding line, so a TAC reader still sees which knob was set. An
  unmatched line passes through unchanged: redaction never drops or rewrites
  evidence.

## Steps

1. Complete a run as in
   [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics),
   including **Analyze**. The no-match case is the one this page exists for and
   works exactly the same.
2. Select **Send to TAC**.
3. The browser saves the server's bundle as
   `tac-bundle-<hostname>-<issue-id>.txt`. Every character outside
   `A-Za-z0-9._-` in the hostname and the issue id collapses to `_`, so a value
   from the wire can never steer a path.
4. Read the file before you send it. It is text, and it is the whole artefact.

## Result

A run where nothing matched produces this bundle. It is the real export from the
no-match analysis on the previous page:

```text
CORRELIX PROTOCOL DIAGNOSTICS — TAC EXPORT (redacted)
=====================================================
Device      : core-rtr-01 ()
Platform    : cisco-iosxe
Vendor      : Cisco IOS-XE (dialect: Cisco IOS-XE)
Protocol    : BGP
Issue       : Session down (Idle/Active/Connect, not Established) [bgp-session-down]
Ruleset     : correlix-protocoldiag-2026-08-27
Collected   : 0001-01-01T00:00:00Z

ANALYSIS
--------
no known signature matched — the raw captured output is attached for TAC

CAPTURED OUTPUT (redacted)
--------------------------
$ show ip bgp neighbors   [0001-01-01T00:00:00Z]
# neighbor detail: last reset reason, transport
BGP neighbor is 10.0.0.2,  remote AS 65002, external link
  BGP state = Active
  Last reset 00:02:11, due to BGP Notification sent, hold time expired
```

The header names the ruleset version, so a vendor can tell which rules applied. `Collected` carries the zero timestamp when the output was pasted
rather than captured from a device. Where signatures did fire, the ANALYSIS
section carries the verdict, the cause, the remediation and the evidence line
instead of the no-match sentence.

### What the redaction pass masks

Each match is replaced with `[REDACTED]`, keeping the rest of the line:

- Local user passwords and `enable secret` / `enable password` values.
- SNMP community strings.
- Routing and keychain material: `md5`, `authentication-key`, `key-string`,
  `message-digest-key`.
- IPsec and IKE pre-shared keys, `crypto isakmp key`, keyring keys.
- PEM private-key blocks, including one-line forms. Certificate blocks are
  deliberately left intact, because public certificate material is often the
  evidence.

The same pass runs at capture time, so what an operator reads on screen is
already masked. See
[Collect diagnostics from a device](/investigate/collect-from-a-device).

:::caution
The bundle is intended to leave the platform, and producing one is audited as a
sensitive action. Redaction targets credentials, not topology: device names,
addresses, AS numbers and prefixes are the evidence and stay in the file. Read
it before sending it to a third party.
:::

## Related

- [Diagnose a BGP, OSPF or IS-IS issue](/investigate/protocol-diagnostics)
- [Collect diagnostics from a device](/investigate/collect-from-a-device)
- [Security overview](/security/overview)
