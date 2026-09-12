---
title: Diagnose a BGP, OSPF or IS-IS issue
description: Choose one of 15 catalogued routing issues, capture or paste the read-only show output, and read the verdict or the honest no-match.
page_type: task
sidebar_position: 6
---

# Diagnose a BGP, OSPF or IS-IS issue

Protocol diagnostics turns "the session is down" into a named issue, a curated
read-only command bundle, and a verdict from hand-authored failure signatures.
When no signature fires it says so and keeps the raw output for a human, which
is the outcome this feature exists for as much as a match is.

## Before you begin

- `infrastructure:read` for the catalog, the analysis and the export.
  Capturing from a device additionally needs `infrastructure:write`. See
  [Collect diagnostics from a device](/investigate/collect-from-a-device).
- The issue you are chasing. The matrix carries five issues per protocol, and
  picking the wrong one scores your output under the wrong signatures.
- Command output, either captured by Correlix or pasted from your own session.
  Both paths analyze identically.

## Steps

1. Go to **Investigate → Troubleshooting** and select **Protocol diagnostics**,
   or open the **Protocol diagnostics** button inside the **Device and protocol
   health** lane of an investigation.
2. Select the protocol tab: **BGP**, **OSPF** or **IS-IS**.
3. Select the issue that matches your symptoms. Each issue lists the symptoms it
   covers, its identifier, and every command in its bundle with the purpose of
   that command.
4. Optionally select a device. The catalog is refetched for that device, so the
   commands on screen are the ones that device understands. Interface, peer,
   prefix and VRF are optional and scope the rendered commands.
5. Select **Collect** to capture the bundle from the device, or paste each
   command's output into the box under it. A command you leave empty is not
   analyzed, which is different from a command that returned nothing.
6. Select **Analyze**.

Changing the protocol or the issue clears the evidence on purpose: a capture
taken for one issue must never be read under another issue's signatures.

### The issue matrix

Ruleset `correlix-protocoldiag-2026-08-27`. Every issue carries authored
symptoms, per-vendor dialect coverage for `cisco-iosxe`, `juniper` and `nokia`,
and a read-only bundle. The first command of each bundle is shown here in the
Cisco IOS-XE dialect:

| Issue id | Title | First command | Commands |
|---|---|---|---|
| `bgp-session-down` | Session down (Idle/Active/Connect, not Established) | `show ip bgp summary` | 7 |
| `bgp-prefix-not-exchanged` | Prefix not advertised / not received | `show ip bgp neighbors advertised-routes` | 7 |
| `bgp-route-not-best` | Route not installed / best-path | `show ip bgp` | 6 |
| `bgp-flapping` | Flapping session / dampening | `show ip bgp neighbors` | 7 |
| `bgp-wrong-path` | Wrong path / policy | `show ip bgp` | 6 |
| `ospf-neighbor-stuck` | Neighbor stuck (EXSTART/EXCHANGE/INIT, not FULL) | `show ip ospf neighbor` | 6 |
| `ospf-adjacency-nonform` | Adjacency won't form | `show ip ospf interface` | 6 |
| `ospf-routes-missing` | Routes missing / not installed | `show ip ospf database` | 7 |
| `ospf-flapping` | Flapping neighbor | `show ip ospf neighbor` | 6 |
| `ospf-suboptimal` | Suboptimal path / wrong metric | `show ip ospf interface` | 7 |
| `isis-adjacency-down` | Adjacency down | `show isis neighbors` | 7 |
| `isis-adjacency-init` | Adjacency stuck (INIT) | `show clns neighbors detail` | 6 |
| `isis-routes-missing` | Routes missing | `show isis database` | 6 |
| `isis-flapping` | Flapping | `show isis neighbors` | 6 |
| `isis-overload-suboptimal` | Overload / suboptimal | `show isis database detail` | 6 |

The same bundle renders in the device's own dialect. `bgp-session-down` opens
with `show ip bgp summary` on Cisco IOS-XE and `show bgp summary` on Juniper
Junos; `isis-adjacency-down` opens with `show router isis adjacency` on Nokia
SR OS. A vendor the issue does not claim still renders, by falling back to the
Cisco IOS-XE dialect, and is not listed as covered.

Read the catalog directly:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/troubleshoot/protocol-diagnostics/catalog?vendor=cisco-iosxe"
```

## What you see

### A signature matched

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"issue_id":"bgp-session-down","device":{"hostname":"core-rtr-01","platform":"cisco-iosxe"},"outputs":[{"spec_id":"bgp-summary","output":"…"}]}' \
  http://localhost:8000/api/troubleshoot/protocol-diagnostics/analyze
```

```json
{
  "findings": [
    {
      "signature_id": "bgp-tcp-blocked",
      "verdict": "BGP peer is reachable but the session stays in Active/Connect",
      "cause": "there IS a route to the peer, yet TCP/179 never establishes — a firewall/ACL is blocking TCP 179, or the peer is not configured/listening",
      "remediation": "Permit TCP/179 both directions between the peers, and confirm the neighbor is configured on the far end.",
      "confidence": "high",
      "evidence": {
        "command": "show ip bgp summary",
        "spec_id": "bgp-summary",
        "line": "10.0.0.2        4        65002       0       0        0    0    0 00:00:00 Active"
      }
    }
  ],
  "issue_id": "bgp-session-down",
  "issue_title": "Session down (Idle/Active/Connect, not Established)",
  "matched": true,
  "protocol": "bgp",
  "ruleset_version": "correlix-protocoldiag-2026-08-27",
  "unmatched": ""
}
```

The panel renders the verdict, the confidence, the likely cause, the
remediation, and the exact output line the signature fired on, with the command
it came from. Confidence is a triage hint, not a verdict.

### Nothing matched

```json
{
  "findings": [],
  "issue_id": "bgp-session-down",
  "issue_title": "Session down (Idle/Active/Connect, not Established)",
  "matched": false,
  "protocol": "bgp",
  "ruleset_version": "correlix-protocoldiag-2026-08-27",
  "unmatched": "no known signature matched — the raw captured output is attached for TAC"
}
```

The panel prints **No signature matched** and repeats the server's own sentence.
This is a first-class outcome, not a failure: the raw output is kept and can go
straight to a vendor TAC. See
[Export a redacted bundle for vendor support](/investigate/send-to-tac).

Analyze and export are stateless computations over the text you supplied. They
touch no device, persist nothing, and reject any output keyed to a command that
is not part of the selected issue. The request body is capped at 2 MiB, with at
most 64 command outputs of at most 256 KiB each.

## Related

- [Collect diagnostics from a device](/investigate/collect-from-a-device)
- [Export a redacted bundle for vendor support](/investigate/send-to-tac)
- [Investigate a symptom](/investigate/investigate-a-symptom)
- [Check OSPF and IS-IS adjacency health](/investigate/igp-health)
