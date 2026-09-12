---
title: Enable a detection rule
description: Read the detection catalog, turn a rule on or off for your tenant, and understand what fidelity and seam-awareness mean.
page_type: task
sidebar_position: 8
---

# Enable a detection rule

The detection catalog is every check Correlix ships: hardening rules, seam
exposure probes, device-log and behavioural detections, and vendor advisory
providers. Enablement is per tenant, so turning a rule off silences it for your
tenant only.

## Before you begin

- A role with `administration:write`. The gate is deliberately the per-tenant
  administration gate rather than a platform gate: which detections a tenant
  runs is that tenant's own configuration.
- A tenant selected. The cross-tenant view is refused with a `400`, because
  there is no single tenant to stamp as the owner of the change.
- Read access alone is enough to view the catalog.

## Steps

1. Go to **Security → Configuration → Detection Rules**.
2. Find the rule by its **Rule** id, or sort by **Family**, **Fidelity** or
   **Seam-aware**.
3. Tick or untick **Enabled** on each rule you want to change.
4. Select **Save N changes**. Select **Discard changes** to abandon them.

## Result

The status line reads `N rules updated`, then the table reloads from the server
with the stored state. The count under the toolbar reads `N of M rules
enabled`.

The console sends only `{rule_id, enabled}` for the rules that actually
changed. Family, fidelity, MITRE tags and seam-awareness are server-owned
facts; echoing them back would let a client assert properties it does not own.

A refusal surfaces as a message rather than a silently reverted toggle, so you
always know whether the change took.

## The catalog

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/rules
```

```json
[
  {"rule_id": "cisco-openvuln", "family": "advisory", "enabled": true, "fidelity": "high", "seam_aware": false},
  {"rule_id": "offline-feed", "family": "advisory", "enabled": true, "fidelity": "high", "seam_aware": false},
  {"rule_id": "exposure-http", "family": "exposure", "enabled": true, "fidelity": "high", "seam_aware": true},
  {"rule_id": "exposure-snmp", "family": "exposure", "enabled": true, "fidelity": "high", "seam_aware": true},
  {"rule_id": "exposure-ssh", "family": "exposure", "enabled": true, "fidelity": "high", "seam_aware": true},
  {"rule_id": "exposure-telnet", "family": "exposure", "enabled": true, "fidelity": "high", "seam_aware": true},
  {"rule_id": "bootp-server", "family": "hardening", "enabled": true, "fidelity": "high", "seam_aware": false},
  {"rule_id": "cdp-run-global", "family": "hardening", "enabled": true, "fidelity": "high", "seam_aware": false},
  {"rule_id": "finger-service", "family": "hardening", "enabled": true, "fidelity": "high", "seam_aware": false},
  {"rule_id": "ftp-server-enabled", "family": "hardening", "enabled": true, "fidelity": "high", "seam_aware": false}
]
```

### Families

| Family | What it contains |
|---|---|
| `hardening` | 27 configuration-posture rules read against a device's captured running configuration |
| `exposure` | 4 seam-aware probes for reachable management services: `exposure-telnet`, `exposure-ssh`, `exposure-snmp`, `exposure-http` |
| `threat` | Device-log and flow-behavioural detections, carrying MITRE ATT&CK technique ids in `mitre` |
| `advisory` | Vendor advisory providers: `offline-feed` and `cisco-openvuln` |

### Fidelity

Fidelity is a property of the detection, not a tunable. It is the rule author's
confidence in a match, not the severity of what the rule finds.

| Fidelity | What produces it |
|---|---|
| `high` | A deterministic match on a configuration line or a vendor mnemonic |
| `medium` | A statistical or behavioural verdict over flow history, which carries a base rate |

### Seam-aware

`seam_aware: true` means the rule reasons about where the estate meets an
untrusted network, so its finding can name a seam and therefore an owner. The
four exposure probes are seam-aware; the hardening rules reason about the
configuration alone.

## The default is on

Every catalog entry ships enabled, and a rule with no stored row for your
tenant reads as enabled. That default is deliberate: if "no row" meant "not
assessed", an operator reading a clean page would have no way to tell the
difference between nothing being wrong and nothing having run.

## What turning a rule off does

Disabling a rule silences its evidence everywhere, including the
[exposure stories](/security/exposure-stories) it grounds. It does not mark
past findings as resolved; it stops new ones being produced.

An empty detections list on a tenant with every rule disabled means "not looked
at", not "nothing found". The console states that on the empty view.

## The write contract

`PUT /api/security/rules` takes a non-empty array:

```json
[{"rule_id": "exposure-telnet", "enabled": false}]
```

`enabled` is required on every entry. An unknown `rule_id`, a duplicate id, a
missing `enabled`, or more than 500 entries is a `400`. The vocabulary is
closed: an unknown id would create a row nothing reads and let a caller grow
the table without bound. The change is recorded in the audit trail as
`security_rules_update`.

## Related

- [Run a security scan](/security/run-a-scan)
- [Review threat detections](/security/threat-detection)
- [Review exposures](/security/exposures)
- [Administration overview](/administration/overview)
