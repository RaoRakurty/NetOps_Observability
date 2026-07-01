---
title: Compliance Monitoring
sidebar_label: Compliance Monitoring
sidebar_position: 4
description: Intent-drift checks against your Source of Truth plus management-plane policy baselines — SNMP security, fleet OS baseline, and known-exploited CVE exposure.
---

# Compliance Monitoring

Compliance Monitoring compares **what's running against what's intended** — all agentlessly, from data the platform already holds. It runs two classes of checks:

- **Drift** — differences between the inventory declared in your external **Source of Truth** and what is actually observed on the network (registration, name, management IP, serial, platform).
- **Policy** — management‑plane baselines that need no source of truth: community‑based SNMP in use, weak SNMPv3 parameters, OS versions off the fleet baseline, and known‑exploited CVEs present.

Every finding carries an **Observed** vs **Intended** pair and a framework tag, so it maps directly onto audit evidence.

## Before you begin

- **Devices onboarded** — add them under <kbd>Infrastructure → Devices</kbd>, point a static inventory file at the stack, or connect the Source of Truth. With an empty inventory the board shows *"No devices in the inventory yet"* — there is no posture to assess. See [onboarding devices](/onboard-devices/overview).
- **A role with read access to Infrastructure** to view the board.
- Optionally, to activate each check family (see [Activate inactive checks](#activate-inactive-checks) below):
  - an **external Source of Truth** connected in read or two‑way mode ([Automation & Source of Truth](/automation/overview)) — for the drift checks;
  - **SNMP credential profiles assigned to devices** ([SNMP profiles & credentials](/onboard-devices/snmp-profiles)) — for the SNMP policy checks;
  - the **vulnerability advisory feed** provisioned ([Vulnerability Management](/security/vulnerability-management)) — for the known‑exploited check.

## The checks

| Check | Class | Finding severity | Framework | What triggers a finding |
| --- | --- | --- | --- | --- |
| Device registered in Source of Truth | drift | medium | NIST CSF ID.AM‑1 | A device exists on the network but has no Source of Truth record |
| Name matches Source of Truth | drift | low | NIST CSF ID.AM‑1 | Observed device name differs from the declared name |
| Management IP matches Source of Truth | drift | high | NIST CSF ID.AM‑1 | Observed management IP differs from the declared one |
| Serial matches Source of Truth | drift | high | NIST CSF ID.AM‑1 | Serial mismatch on the same management identity — usually hardware swapped without updating the record |
| Running OS matches intended platform | drift | medium | NIST CSF ID.AM‑2 | The OS actually running differs from the platform declared in the record |
| No community‑based SNMP (v1/v2c) | policy | medium | CIS · NIST 800‑53 IA‑5 | A device authenticates with a cleartext community string instead of SNMPv3 |
| SNMPv3 uses authPriv with strong ciphers | policy | low | CIS · NIST 800‑53 SC‑8 | SNMPv3 without authPriv, or using MD5 authentication or DES privacy |
| OS version matches fleet baseline | policy | low | Internal golden baseline | A device's OS version is off the strict‑majority version of its platform group (needs ≥3 devices on the same vendor + platform) |
| No known‑exploited vulnerabilities | policy | high | CISA BOD 22‑01 | The running OS matches a CVE in the CISA Known Exploited Vulnerabilities catalog |

Devices are paired to their Source of Truth record by management IP first, then serial, then name — the same identity chain discovery uses to de‑duplicate.

## Read the board

Go to <kbd>Security → Compliance Monitoring</kbd>. The board refreshes every 60 seconds. The **Posture** group leads with a summary strip:

| Tile | Meaning |
| --- | --- |
| **Devices** | Physical devices assessed |
| **Compliant** | Devices with zero findings on the active checks |
| **With findings** | Devices with at least one finding |
| **Findings** | Total findings |
| **Drift** / **Policy** | Findings by class |
| **High severity** | Findings rated high |
| **Checks active** | Active checks out of total (e.g. `4/9`) — amber whenever some checks can't run |

### The findings table

Findings sort worst‑first (severity, then drift before policy). Use the **"Filter by device, check, framework…"** box to narrow by device name, check title, framework, or an observed/intended value.

| Column | Contents |
| --- | --- |
| **Severity** | high (red) / medium (amber) / low |
| **Class** | drift or policy |
| **Check** | The check title — hover for the remediation detail (e.g. which credential profile to migrate) |
| **Device** | The affected device |
| **Observed** | What is actually running/configured |
| **Intended** | What the Source of Truth or the baseline says it should be |
| **Framework** | The control the check maps to |

### The checks table

The **Checks** group lists every check with its status — **pass**, **N findings**, or **inactive** — plus a **"Why inactive"** column.

:::warning An inactive check is "cannot assess", not "compliant"
A check whose data source isn't connected did not run. A green‑looking board with `4/9` checks active is a 4‑check board — read the inactive reasons before reporting posture.
:::

## Activate inactive checks

Each inactive reason names its fix:

1. **Drift checks inactive** — *"No declared inventory to compare against — the internal Source of Truth is itself the authority."* By default the platform's own discovered inventory is the authority, so there is no separate declared intent to diff. Connect an external Source of Truth under <kbd>Automation → Source of Truth</kbd> in **read or two‑way mode**; drift checks activate once declared records are read in.
2. **SNMP checks inactive** — *"no devices reference an SNMP credential profile."* Assign credential profiles to devices under the SNMP Profile Manager ([how‑to](/onboard-devices/snmp-profiles)); the version/strength checks then judge each device's assigned profile.
3. **OS baseline inactive** — *"needs ≥3 devices on the same platform with a parseable OS version."* The golden version is the strict‑majority version within a vendor + platform group of at least three devices; smaller groups can't establish a defensible baseline. This activates on its own as your fleet grows.
4. **Known‑exploited check inactive** — *"vulnerability feed not provisioned — see Security → Vulnerability Management."* Follow the [feed provisioning procedure](/security/vulnerability-management); this check activates with the same feed.

## Fix a finding

1. Go to <kbd>Security → Compliance Monitoring</kbd> and sort/read the findings worst‑first (the default order).
2. For **drift** findings, decide which side is right, then fix that side: update the stale Source of Truth entry, or correct the device to match the declared intent. For *"Device not registered in Source of Truth"*, register it — or enable two‑way sync under <kbd>Automation → Source of Truth</kbd> so discovered devices are pushed there. Treat **serial** mismatches seriously: they usually mean hardware was swapped without a record update.
3. For **policy** findings:
   - *Community‑based SNMP in use* — migrate the device to an SNMPv3 profile; the finding's detail names the offending profile.
   - *Weak SNMPv3 parameters* — the Observed column lists exactly what's weak (security level, MD5, DES); move the profile to **authPriv with SHA‑2 + AES**.
   - *OS version off fleet baseline* — the detail shows the consensus (e.g. *"5 of 7 cisco devices run 17.9.4"*); schedule the outlier's upgrade.
   - *Known‑exploited vulnerability present* — the detail lists the CVE ids; the full advisories are on the [Vulnerability Management](/security/vulnerability-management) board. Patch first.
4. Findings clear automatically once the corrected state is observed on the next refresh/poll — there is no manual acknowledgment.

## Coverage gaps

If some checks had to be skipped on specific devices, a **Coverage gaps** group lists them with the reason — for example a credential reference matching no profile, no SNMP credential assigned, an unknown vendor, or no OS version in the device's system description. As on the other boards: a skipped check on a device means *unknown*, not *compliant*.

## Verify it worked

1. **Checks active** reads `9/9` (or you can explain each inactive one).
2. The findings panel shows either real findings or *"No drift or policy violations across N devices on the active checks."*
3. The **Coverage gaps** group is absent, or every listed device has a known cause you're fixing.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Board says "No devices in the inventory yet" | Nothing is onboarded — add devices under <kbd>Infrastructure → Devices</kbd> or via [discovery](/onboard-devices/snmp-discovery). |
| All drift checks inactive despite NetBox connected | The connection must read declared records back into the platform — set the Source of Truth sync to read or two‑way mode under <kbd>Automation → Source of Truth</kbd>. |
| SNMP checks inactive but devices are polling | Devices must *reference a credential profile* — ad‑hoc credentials don't count. Assign profiles in the [SNMP Profile Manager](/onboard-devices/snmp-profiles). |
| A fixed finding still shows | State is re‑read on the device's normal polling cycle and the board refreshes every 60 s — allow one cycle. |
