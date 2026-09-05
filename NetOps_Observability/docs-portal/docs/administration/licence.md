---
title: Apply a licence
sidebar_label: Licence
description: Install a signed licence file, read the ceilings and usage it carries, and verify the file offline before you install it.
page_type: task
sidebar_position: 13
---

# Apply a licence

A Correlix licence is one signed JSON file. Correlix verifies it offline, against a public key built into the product, so installing a licence needs no connection to Correlix and no activation server. A deployment with no licence file runs at the Community ceilings, which is a supported state rather than a fault.

**Administration → Licence** shows the licence in force and where you stand against every ceiling. A platform administrator also gets the controls that install or remove one.

## Before you begin

- **Permission:** any administrator to read, platform administrator to install or remove. `GET /api/system/licence` calls `requireAdmin` and answers each caller in its own scope. A platform administrator receives the full licence. A tenant or organization administrator receives a projection of it: the tier, the entitled features, the same ceilings measured against that tenant's own usage, the expiry and grace state, and who manages the licence. The projection carries no customer name, no licence id, no support terms and no signing keys. `PUT` and `DELETE` call `requirePlatformAdmin`, so a tenant administrator reads the page and does not see the install controls. There is one licence file per installation and it covers every tenant on it.
- Have the licence file Correlix issued you. It is a `.json` file of about one kilobyte.
- To place the file by hand instead of uploading it, have shell access to the deployment host and write access to the api data volume.
- To verify the file before installing it, have the `correlix-licence` command. Build it from the Correlix source tree with `go build -o correlix-licence ./src/backend/cmd/correlix-licence`. The installer bundle does not carry it.

## Steps

### Get a licence

Contact Correlix with the deployment's device count and the capabilities you need. Correlix signs a file that names your organization, the tier, an expiry date, the ceilings and the commercial capabilities it grants, and returns the file to you. Nothing about the request happens inside the product, and the product never reports usage to Correlix on its own.

A trial is the same mechanism: a Team or Enterprise file with a short expiry date — 30 days from issue, 7 days of grace, marked as an evaluation licence so the page can say so. No card, and it works offline like any other licence.

### Install the licence on the Licence page {#install-on-the-page}

1. Open **Administration → Licence**.
2. Go to **Install a licence**.
3. Select the file under **Licence file**, or paste the document into **Or paste the licence document**.
4. Select **Install licence**.

Correlix verifies the signature before it writes anything. A file it refuses never reaches the disk, so a bad upload cannot displace the licence already in force, and the tier you have keeps working. A refusal is shown in the platform's own words, unchanged, under **The platform refused that licence.**

Both outcomes are recorded in the audit log: an accepted install records the licence id, the customer, the tier, the expiry and the signing key id, and a refusal records the reason.

### Place the licence file by hand

The licence lives at one path, and writing the file there has the same effect as uploading it.

```bash
install -m 0600 acme-networks.json data/api/licence.json
```

Inside the api container that path is `/data/api/licence.json`. The page shows the path in force at the bottom of **Install a licence**, and `LICENCE_FILE` overrides it.

Correlix re-reads the file within five seconds of a change, so a licence placed by hand takes effect without a restart. The boot log records the licence in force on every start.

### Read the ceilings and the usage bars

**Current usage** lists the seven ceilings the licence file carries. Read each row on three facts: the limit, whether anything enforces it, and whether Correlix measured the current value.

| Ceiling | Community limit | Enforced |
| --- | --- | --- |
| `devices` | 25 **monitored** devices | Yes: turning monitoring on for a device, and `POST /api/devices` |
| `watched_prefixes` | 5 | Yes: adding a prefix to the BGP watchlist |
| `tenants` | 1 | No |
| `orgs` | 1 | No |
| `retention_days` | 7 | No |
| `skills` | 0 | No |
| `provider_tokens_per_day` | 0 | No |

**Carried, not enforced** is on a row whose limit nothing in the product gates on. The limit is in the licence file so that an issued file is complete and stays valid as the product grows, and the page labels it rather than drawing a bar that looks like a live gate. A row marked this way never refuses anything today.

**Not measured** is different from zero, and the page never collapses the two. A ceiling Correlix counted shows the count, including a genuine `0`. A ceiling Correlix did not count shows `not measured` and the reason, such as `carried in the licence but not enforced by this build` or `the BGP watchlist is not available`. Zero devices in use is a measurement. A blank is silence, and it is written as silence.

An unlimited ceiling, written `-1` in the file, has no percentage. A bar drawn against no limit would be an invented number, so the row shows the count in use and the word unlimited.

### What the device ceiling counts

The Community tier supports up to **25 monitored devices**. A device consumes one entitlement when at least one supported monitoring or collector configuration is enabled for that device. Devices discovered or retained in the inventory without active monitoring configuration do not consume the monitored-device allowance.

Three consequences follow, and each is deliberate:

- **Discovery is free.** A subnet scan that finds five hundred devices creates five hundred inventory records and uses none of the allowance. Nothing about discovery, the inventory, the topology or a device's history is limited by the licence — only collection is.
- **Multiple enabled telemetry methods on the same device consume one monitored-device entitlement.** SNMP polling, a gNMI subscription and a configuration capture on one box are one monitored device, not three.
- **Temporary device or collector unreachability does not release the entitlement while monitoring remains configured.** The ceiling tracks what Correlix is configured to collect from, not what is answering today; freeing a licence during an outage would hand a customer capacity exactly when their network is broken.

Turn monitoring on or off per device on **Infrastructure → Inventory & Devices**, in the Monitoring column, or through `PUT /api/devices/{id}/monitoring`. A device an operator adds by hand, an operator-authored devices file declares, or the source of truth supplies is monitored from the start — adding it is asking for it to be collected from. A device found only by the subnet scan is not, until somebody says so.

When the ceiling is full and a source reports another device that would be monitored, the device still enters the inventory and its collection is withheld. The Licence page says how many are in that state beside the usage bar, and the log names each one once. Raising the licence, or turning monitoring off elsewhere, starts collecting from them without any further action.

### Read the over-ceiling list

When usage exceeds an enforced ceiling, the row turns red and the ceiling appears in the over-ceiling list with the number that is over and the tier that covers it. Everything in that list is still present. Correlix admits no new item above the ceiling, and it deletes nothing, hides nothing and stops collecting from nothing that is already there.

A refusal at a ceiling returns HTTP `402` and names the ceiling, the current value, the limit and the tier that raises it, so the console shows an upgrade card instead of an error. A `403` still means the caller lacks permission. The two answers stay distinct.

### Verify a licence offline {#verify-offline}

`correlix-licence verify` runs the same verification code the product runs, so a file that verifies on your host installs on your host.

```bash
correlix-licence verify acme-networks.json
```

```
VERIFIED  acme-networks.json
  acme-networks-20260904, tier=team, customer="Acme Networks", expires=2026-12-31T00:00:00Z, ceilings=250 devices/100 watched prefixes, features=security_findings
  ceilings:
    devices                  250
    watched_prefixes         100
    tenants                  5  (carried, not enforced)
    orgs                     1  (carried, not enforced)
    retention_days           30  (carried, not enforced)
    skills                   10  (carried, not enforced)
    provider_tokens_per_day  0  (carried, not enforced)
  features:
    security_findings        security findings
```

To verify without trusting the copy of the command you were given, pass the published public key. The **Verification** section of the Licence page shows the same key with a copy button, so a platform administrator can read it from the running deployment:

```bash
correlix-licence verify --pubkey <published public key> acme-networks.json
```

Flags come before the file name. The command stops reading flags at the first
argument that is not a flag, so `verify acme-networks.json --pubkey …` is
refused with `verify: exactly one licence file is required`.

The exit status is `0` only when the file authenticated. Four refusals are possible, and each one names a different problem:

| Refusal | What it means |
| --- | --- |
| `unknown signing key` | The file is signed by a key this build does not carry. The signature was not checked at all. Ask Correlix to reissue under the current key. |
| `signature does not verify` | The key is trusted and the content does not match the signature. The file was edited after it was issued. Reformatting cannot cause this, because the signature covers a canonical form: only a change to the content does. |
| `malformed document` | The bytes are not a well-formed licence: not JSON, a truncated download, or a field the schema does not have. |
| `value outside the closed vocabulary` | The file names a tier or a capability that does not exist. Correlix refuses it rather than granting an approximation. |

To read a file that will not verify, use `correlix-licence show`. It prints the contents and states on the first line that it authenticated nothing.

### Remove a licence

1. Go to **Install a licence** and select **Remove licence…**.
2. Type the licence id shown in the confirmation box.
3. Select **Remove licence**.

The deployment returns to the Community ceilings. No data is deleted and no collection stops. Anything over a Community ceiling stays where it is and is listed as over-ceiling.

## What you see

The top of the page names the customer, the tier in force, the licence id, the expiry date, the grace period and the support entitlement, with a state chip beside the headline reading **Community**, **Valid · expires in N days**, **Evaluation licence · N days left**, **In grace · N days left** or **Past grace**. **Current usage** shows a bar for each measured, enforced ceiling and the honest label for every other row; a bar colours at 80 %, again at 90 %, and again once it is at or past the allowance, and a soft allowance is labelled *soft — recorded, not blocked* so nobody reads a full bar as a device that stopped. **Features** lists the seven commercial capabilities, whether this licence grants each one, and the lowest tier that includes it.

Two gauges carry the same state into monitoring. `netops_licence_days_to_expiry` counts whole days and reports the sentinel `36500` when no licence is installed, so a deployment with nothing to expire cannot trip an expiry alert. `netops_licence_state{tier,degraded,in_grace}` reports `1` on the combination in force and `0` on the others, on every scrape.

Three alert rules watch those gauges: `LicenceExpiringSoon` at 14 days, `LicenceInGrace`, and `LicenceExpired`. All three are warnings. None of them pages, because a lapsed licence lowers commercial ceilings and does not interrupt service.

Four more series carry usage: `netops_licence_ceiling{ceiling,unit}` (the limit; `-1` means unlimited), `netops_licence_usage{ceiling,unit}` (present only for a ceiling this deployment actually measures), `netops_licence_ceiling_soft{ceiling}` (`1` where going over is recorded rather than refused) and `netops_licence_overage_devices`. Three more warning rules divide them — `LicenceCeilingApproaching` at 80 %, `LicenceCeilingReached` at 90 %, and `LicenceOverage` past 100 % — and every one of them joins on the soft flag, so a Community deployment fires none of them however full its fleet is.

## Usage

The **Usage** section answers a different question from **Current usage** above it. That one says where you stand against your ceilings right now; this one says what the installation actually consumed over a period, and gives you a document you can check without trusting this page.

Usage is recorded as its own data, kept apart from the licence on purpose: the licence says what you are allowed to do, and usage says what you used. Nothing in the product gates on a usage number — no device, query or permission depends on it — so a metering problem can lose you precision in a report and can never refuse anything.

**Monitored devices are counted from configuration**, never from recent traffic: a device with at least one collector enabled counts, whether or not it answered in the last hour. A device that stopped responding during an incident still counts, and discovery does not consume your monitoring allowance. The section leads with that line — *Monitoring: N / 25 Community monitored devices. Discovery does not consume your monitoring allowance.*

Samples are taken hourly and rolled up by UTC day, so today's row grows through the day and the last hour may not be in it yet. The page says when the numbers were last recorded rather than implying they are live. Thirteen months of daily rows are kept.

Meters are shown in two groups, and the split is the point:

- **Entitlement meters** are the numbers a renewal or a true-up conversation uses: unique and peak monitored devices, watched prefixes, tenant and organisation counts, and the retention windows you have configured.
- **Diagnostic meters** are recorded because they are useful, not because anything is charged for them — metric samples and series, log and flow records accepted after your processors ran, experience checks, AI tokens, and the ratio of what left the pipeline to what entered it. **Telemetry you run yourself is not metered for money.** Correlix does not pay for your disks, network or compute.

A meter this installation has no counter for reads **not measured — \<reason\>**, never a zero. A zero means we counted and found none; a blank means nobody counted, and the two are different facts.

A platform administrator also sees a **by tenant** breakdown, with the installation's own line named as such. That line counts every monitored device on the installation, including any that belong to no tenant, so the tenant lines below it can add up to less. A tenant administrator sees their own tenant only: no other tenant's numbers, no installation totals, no customer name and no licence id.

### Download a signed usage report

Pick a period and select **Download signed usage report**. The file is JSON and carries:

- the **daily rows**, not just the totals, so the arithmetic can be redone by hand;
- the **meter definitions**, so the document explains its own columns years later;
- an **ed25519 signature** over its canonical bytes, made by a key this installation generated the first time a report was produced and has never sent anywhere.

That key is **not** the key Correlix signs licences with, and that key does not exist on your host. The two answer different questions: whether Correlix issued a licence, and whether this installation produced a report.

Check a report offline, with nothing but the file:

```bash
correlix-licence usage-verify correlix-usage-2026-08-01_2026-08-31.json
```

It runs two independent checks. The signature says the file is exactly what the installation produced and has not been edited. Then it **re-derives the period totals from the daily rows in the file** and compares them: a report whose summary does not follow from its own detail is refused, naming the meter that disagrees. Add `--pubkey <base64>` to confirm *which* installation produced it against a key you hold separately.

Nothing in any of this is sent to Correlix. There is no phone-home, opt-in or otherwise. If we need your numbers, you send us the file.

Four series carry the recorder's own health: `netops_metering_snapshot_timestamp_seconds` (`0` means none yet, which is a value rather than a gap), `netops_metering_daily_rows`, `netops_metering_snapshot_failures_total` and `netops_metering_pruned_rows_total`. Three warning rules watch them — `MeteringSnapshotStale` at 3 hours, `MeteringNeverRecorded`, and `MeteringSnapshotsFailing` — and none of them pages, because a stopped recorder costs a report some precision and nothing else.

## What happens at expiry

Correlix settled this on 5 September 2026, and the page states it on every visit.

| State | When | What changes |
| --- | --- | --- |
| Valid | Before the expiry date | Nothing |
| In grace | After expiry, inside the grace period the licence file names | **Nothing at all.** The licensed tier, ceilings and capabilities are still in force. The page shows how many days are left and the `LicenceInGrace` alert warns |
| Past grace | After the grace period ends | Creating and configuring paid capability is refused. Everything already here stays visible and exportable, everything over a ceiling is listed, and nothing is disabled or deleted. The licensed tier is remembered, so the page reports that a Team licence expired rather than pretending the deployment was always Community |

Licences are issued with **30 days of grace**; an evaluation licence is issued with **7**. The number is written into the file itself rather than assumed by the product, so a licence you were issued before this policy existed keeps exactly the terms it was issued with — a file that carries no `grace_days` value has no grace and moves straight from valid to past grace on its expiry date.

### After grace: what stops, and what does not

**Refused** — anything that creates or configures paid capability:

- switching monitoring on for a device beyond the Community allowance of 25 monitored devices;
- creating a second tenant or a second organisation (the first of each is normal single-tenant operation and is never licensed);
- configuring a licensed capability: writing a SAML connection, saving or testing an LDAP configuration, installing a dialect, creating a SIEM export.

Each of those answers `402` with a machine-readable body that now includes `licence_state: "post_grace"`, so the screen can tell you the remedy is a **renewal** rather than an upgrade.

**Unchanged** — anything that reads or exports what you already have:

- security findings, their facets and their trend, including exporting them;
- the LDAP configuration as it stands;
- the tenant and organisation lists;
- every device that was already being monitored. None is switched off.

Correlix never picks which devices a licence covers. When you are over an allowance the page lists the devices beyond it, most recently enabled first, purely so you can see the size and shape of the overage — and says so beside the list. Every one of them is still being collected from.

## Evaluation licences

A trial is an ordinary signed licence with a short life: 30 days from issue, Team or Enterprise, 7 days of grace, no card and no phone-home. The page shows **Evaluation licence · N days left**. A trial grants exactly what its tier, ceilings and capabilities say — nothing about it is a reduced version of the product — and Community keeps working alongside it.

## Going over the monitored-device allowance

On **Team and Enterprise** the monitored-device allowance does not block. Enabling monitoring past it succeeds, the excess is recorded, and the Licence and Devices pages show it. Correlix will not stop you adding a device during an incident because of a number on an order form. The overage is settled as a **true-up** with your account team; the product records when it started and how large it is, and deliberately states no deadline of its own — that is a commercial term, not a product one.

On **Community** the allowance is a hard limit: the 26th activation is refused, with the usual upgrade card. 25 monitored devices is the published free ceiling. Discovery is unlimited and free in every case — discovery does not consume your monitoring allowance.

The same is true after grace: the Community allowance is the one in force, so a **new** activation past 25 is refused. Nothing already monitored is affected.

### What never changes

Four things are the same in every state above, and none of them is a licensed capability:

- **Tenant isolation and data separation.** Every scoping rule, every FORCE-RLS policy and every per-store filter is unaffected.
- **Permissions.** Every authorization check answers exactly as before.
- **Sign-in.** Local accounts and OIDC single sign-on are core and always available.
- **Your data.** Nothing is deleted, nothing is hidden, and no device leaves the inventory.

This is structural rather than a policy choice. The isolation and authentication paths do not consult the entitlement service at all, and tests in the source tree fail the build if any of them ever does — including one that asserts every authorization decision is identical with no licence, a live licence, one in grace and one past grace.

## Related

- [Licensing](/reference/licensing) for which parts of Correlix are Apache-2.0 and which are commercial add-ons.
- [Administration overview](/administration/overview) for the difference between per-tenant data and platform-global configuration.
- [Read the audit log](/administration/audit-log) to see an installed or refused licence recorded.
- [Honest states](/reference/honest-states) for how Correlix distinguishes not measured from measured as zero.
- [Alert rules](/reference/alert-rules) for the licence alert group.
