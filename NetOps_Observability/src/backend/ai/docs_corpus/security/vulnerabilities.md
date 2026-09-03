---
title: Review vendor advisories
description: Prepare the offline advisory feed, read the fleet's CVE exposure, and close the coverage gaps that keep devices out of the assessment.
page_type: task
sidebar_position: 10
---

# Review vendor advisories

The Vulnerabilities page matches each device's running OS against an advisory
dataset you provide, and flags the CVEs that are being exploited in the wild.
The match is agentless: the vendor comes from the device's SNMP identity and
the product and version are parsed from the system description it reports.

Nothing is bundled and nothing is downloaded automatically, so the deployment
keeps working fully offline and you control exactly what advisory data it uses.

## Before you begin

- A role with `infrastructure:read`.
- Devices onboarded over SNMP, with a recognised vendor and a parseable OS
  version.
- Shell access to the Correlix host, once and then periodically, to prepare the
  feed.
- The source files, downloaded on any machine with internet access:
  - One or more NVD yearly feeds, `nvdcve-2.0-<YEAR>.json.gz`, from
    `nvd.nist.gov/feeds/json/cve/2.0/`. Start with the last three to five
    years.
  - Optionally the CISA Known Exploited Vulnerabilities catalog,
    `known_exploited_vulnerabilities.json`, which flags the CVEs under active
    exploitation.

## Steps

### Step 1 — Check the current state

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/vulns
```

On a deployment with no feed:

```json
{"vuln_enabled":false}
```

**Security → Vulnerabilities** then renders the provisioning steps instead of
an empty findings table. An absent feed is "cannot assess", never "no
findings".

### Step 2 — Prepare the feed

Copy the downloaded files to the Correlix host, then run the preparation script
from the install directory:

```bash
python3 scripts/vuln-feed-prepare.py nvdcve-2.0-*.json.gz \
  --kev known_exploited_vulnerabilities.json
```

The script keeps only network-OS applicability rows for the vendors Correlix
identifies over SNMP, so the full NVD corpus reduces to a few megabytes. It
writes `data/vuln/advisories.csv`, which is mounted read-only into the API at
`/data/vuln/advisories.csv`. Set `VULN_FEED_PATH` to move it.

### Step 3 — Confirm it loaded

Go to **Security → Vulnerabilities**. The feed hot-reloads on the file's
modification time, so the page lights up on its next refresh, which happens
every 60 seconds. No restart is needed.

### Step 4 — Work the findings

1. Sort by **Exploited** so the KEV entries rise to the top.
2. Sort by **CVSS** within them.
3. Select a **CVE** link to read the advisory on `nvd.nist.gov` and confirm the
   affected version range applies to your build.
4. Read the **OS / version** column: the finding names the exact version that
   matched, so the fix is an upgrade or the vendor workaround in the advisory.
5. Filter with the **Filter by CVE, device, vendor…** box to see everything
   affecting one device, or every device one CVE touches.

## Result

The **Fleet exposure** strip reports six numbers: **Devices**, **Assessed**,
**Affected devices**, **Findings**, **Critical** and **Known exploited**. The
feed line beneath states how many advisory rows loaded, how many are
known-exploited, and when the file was last updated.

**Assessed** turning amber below **Devices** is the number to read first. It
means part of the fleet was not matched at all.

After you upgrade a device, its findings disappear on the next SNMP read of its
OS version. There is no manual acknowledgement step.

## Coverage gaps

When some devices could not be matched, a **Coverage gaps** group appears with
a **Devices that can't be assessed** table naming the reason for each:

| Reason | What to fix |
|---|---|
| `vendor unknown (SNMP unreachable or unrecognized sysObjectID)` | Reachability, or the SNMP credentials assigned to the device |
| `OS version not present in sysDescr` | The device answered, but its system description carries no parseable version |

Devices listed there are invisible to CVE matching. Absence of findings on an
unassessed device means unknown, not safe.

## Provisioned and clear against unavailable

The distinction runs through the whole advisory path, and the two cases are
never rendered alike:

- A feed that is **provisioned and matches nothing** is a genuine assessment.
  No finding is emitted for the device, and the page states the assessment
  coverage: `No advisories match the assessed fleet (N of M devices had a
  parseable OS version)`.
- A feed that is **unavailable** is unassessed, never a false clear. The
  security lane emits an explicit finding with the control
  `advisory-unassessed`, the title `Vendor advisory exposure not assessed`,
  status `Unknown`, and a detail naming the reason. It is silence that would be
  dishonest, because a console renders silence as clear.

The same holds for the vendor providers in the detection catalog. `offline-feed`
returns "not provisioned" when the CSV is absent. `cisco-openvuln` returns "not
configured" until its credentials are provisioned, and both cases produce an
unassessed verdict rather than a pass.

## Related

- [Investigate a security finding](/security/investigate-a-finding)
- [Enable a detection rule](/security/detection-rules)
- [Check compliance against a framework](/security/compliance)
- [Security section overview](/security/overview)
