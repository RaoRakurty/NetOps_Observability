---
title: Check compliance against a framework
description: Choose which frameworks your tenant is assessed against, read the scorecards, and separate a passing score from a control nobody evaluated.
page_type: task
sidebar_position: 7
---

# Check compliance against a framework

Compliance is scoped per tenant. You turn on the frameworks your organisation
is actually subject to, and Correlix scores each one independently by
projecting your current findings onto that framework's requirements. Nothing is
assessed against a framework nobody asked for.

## Before you begin

- A role with `infrastructure:read` to view the scorecards, and
  `administration:write` to change the selection. Without the write
  permission the picker is read-only and the page says so.
- A tenant selected. The cross-tenant platform view is refused on the write
  with a `400`: compliance scope is per-tenant, and there is no single tenant to
  stamp as owner.
- At least one completed scan, so there are current findings to project.

## Steps

1. Go to **Security → Compliance**. The section opens on **Control set**.
2. Read **Frameworks this tenant is assessed against**. Two ship on by default:
   `NIST SP 800-53 Rev5` and `CIS Controls v8.1`.
3. Select **Add framework…** to see what else is available: `NIST CSF 2.0`,
   `HIPAA Security Rule` and `PCI DSS v4.0.1`.
4. Tick the frameworks the organisation is subject to.
5. Select **Save selection**.
6. Read **Score by framework**, then select a card to open its control table.
7. Read **Controls that reached no verdict, and why** underneath.
8. Select **Drift & baselines** for the source-of-truth drift and
   management-plane baseline board.

## Result

Each enabled framework gets one card carrying its own score, its own coverage
and its own control table. Selecting a card opens the rows: the control id, the
framework requirements it satisfies, the verdict, the finding count, and the
published CIS benchmark section the check cites.

The five frameworks are:

| Framework | Id | Version | Default |
|---|---|---|---|
| NIST SP 800-53 Rev5 | `nist-800-53-r5` | Rev 5 (Release 5.2.0) | On |
| CIS Controls v8.1 | `cis-controls-v8` | 8.1 | On |
| HIPAA Security Rule | `hipaa-security-rule` | 45 CFR 164.312 | Off |
| NIST CSF 2.0 | `nist-csf-2.0` | 2.0 | Off |
| PCI DSS v4.0.1 | `pci-dss-v4` | 4.0.1 | Off |

The three that are off describe a regulatory position an organisation either
has or does not. Rendering a HIPAA scorecard for a company that handles no
protected health information is noise at best, and an implied compliance claim
at worst.

## Reading a score honestly

Four numbers appear on every card, and they answer different questions.

| Field | What it measures |
|---|---|
| `score_percent` | Passing controls over **assessed** controls. `null`, never `0 %`, when nothing in the framework's scope was assessed |
| `coverage_percent` | How much of the framework's own scope Correlix can evidence at all |
| `assessed` | In-scope controls that received at least one projected finding |
| `unassessed` | In-scope controls Correlix can evidence that got no finding this run |

**`score_percent` is null, not zero.** The denominator is passing plus warning
plus failing controls. A control assessed only as `Unknown`, `NotApplicable` or
`Error` counts toward `assessed` but toward none of the three score buckets, so
it can never become a pass. When the denominator is zero the card shows a
sentence instead of a percentage: `0 %` reads as total failure and `100 %`
reads as a clean bill, and neither is supported by the data.

**`coverage_percent` is a capability, not a verdict.** The denominator is the
controls the framework expects of a device configuration, and the numerator is
the ones Correlix can actually evidence. Two controls in every framework's
scope, `AC-3` (Access Enforcement) and `SI-7` (Software, Firmware and
Information Integrity), cannot be evidenced from a configuration audit at all.
Coverage is therefore deliberately below 100 %, and a design that hid those
controls to reach 100 % would be lying about what was checked.

**An Unknown or Not-applicable verdict is unassessed, never a pass.** The
console counts these in no passing share, and says so under the unassessed
panel.

**`configured:false` means the tenant has not chosen.** It does not mean
everything is off. In that case the shipped default set is shown and the
response carries a note saying why. Saving a selection writes a row for every
known framework, on and off alike, so "chose nothing" and "chose nothing on"
never render identically.

A framework store that errors is reported as a `502`, never folded into "not
configured". A tenant whose HIPAA selection failed to load must not be told it
is running the defaults as though it had chosen them.

## The API contract

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/security/frameworks
```

`GET /api/security/frameworks` returns `frameworks`, `benchmarks`,
`benchmark_citations`, `configured` and `notes`. Each framework entry carries
`id`, `name`, `version`, `source`, `scope`, `default_on` and `enabled`.
`source` is `base` for NIST 800-53 and `projection-of-800-53` for the other
four.

`PUT /api/security/frameworks` takes a non-empty array over the closed
framework vocabulary and needs `administration:write`:

```json
[{"framework_id": "hipaa-security-rule", "enabled": true}]
```

`enabled` is required on every entry. An unknown `framework_id`, a duplicate
id, a missing `enabled`, or more than 64 entries is a `400`. An unknown JSON
field is a `400`, so a `tenant_id` in the body is refused rather than honoured;
the owner is stamped from the token. A deployment with no framework store
answers `503` rather than accepting a write it cannot persist.

`GET /api/security/compliance` returns one scorecard per enabled framework:
`frameworks`, `enabled`, `configured`, `assessed_findings`, `current_findings`,
an optional `truncated`, and `notes`. Each scorecard carries `framework`,
`version`, `controls_in_scope`, `controls_with_check`, `coverage_percent`,
`assessed`, `passed`, `warned`, `failed`, `unassessed`, `verdict_id`,
`verdict`, `score_percent`, `controls`, `caption` and an optional `note`.

The route always scores current verdicts, whatever the caller asked for.
Scoring every historical verdict would count one control that failed in thirty
scans as thirty failures. It accepts the standard findings filters plus
`as_tenant`; it has no framework selector and no `window` parameter, and the
`framework` parameter there filters findings by standards tag rather than
choosing which scorecards are produced.

These are the notes the route emits, verbatim from the source:

```text
score:    score_percent is passing controls over ASSESSED controls and is null
          when nothing in the framework's scope was assessed — an unassessed
          control is unknown, never a pass.
coverage: coverage_percent is how much of the framework's own scope this
          platform can evidence at all. It is a capability, not a verdict, and
          it is deliberately below 100%.
default:  This tenant has not chosen its frameworks yet, so the shipped default
          set was scored.
empty:    No framework is enabled for this tenant, so nothing is scored.
```

And the sentence a card carries when nothing in its scope was assessed:

```text
No assessed control maps to this framework yet — this is an absence of
assessment, not a passing or failing result.
```

Every card also carries this caption:

```text
Audit-ready control evidence mapped to framework controls — not certified
compliance. Coverage reflects the technical controls a configuration audit can
evidence.
```

## Benchmark citations

A CIS device benchmark is a citation on a control row, not a framework of its
own. The **Benchmark reference** column names the published benchmark, its
version and the section heading, for example
`CIS Cisco IOS XE 17.x Benchmark v2.2.1 §1.5 SNMP Rules`. Five benchmarks are
registered, covering Cisco IOS 17, Cisco IOS-XE 17, Cisco NX-OS, Juniper OS and
Arista EOS. A benchmark whose section taxonomy could not be read from a
published document is listed and cites nothing, rather than citing an invented
section number.

## Related

- [Investigate a security finding](/security/investigate-a-finding)
- [Review exposures](/security/exposures)
- [Review configuration drift](/security/config-drift)
- [Continuous threat and exposure management](/security/ctem)
