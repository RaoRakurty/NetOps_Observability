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

A trial is the same mechanism: a Team or Enterprise file with a short expiry date.

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
| `devices` | 25 | Yes: discovery admission and `POST /api/devices` |
| `watched_prefixes` | 5 | Yes: adding a prefix to the BGP watchlist |
| `tenants` | 1 | No |
| `orgs` | 1 | No |
| `retention_days` | 7 | No |
| `skills` | 0 | No |
| `provider_tokens_per_day` | 0 | No |

**Carried, not enforced** is on a row whose limit nothing in the product gates on. The limit is in the licence file so that an issued file is complete and stays valid as the product grows, and the page labels it rather than drawing a bar that looks like a live gate. A row marked this way never refuses anything today.

**Not measured** is different from zero, and the page never collapses the two. A ceiling Correlix counted shows the count, including a genuine `0`. A ceiling Correlix did not count shows `not measured` and the reason, such as `carried in the licence but not enforced by this build` or `the BGP watchlist is not available`. Zero devices in use is a measurement. A blank is silence, and it is written as silence.

An unlimited ceiling, written `-1` in the file, has no percentage. A bar drawn against no limit would be an invented number, so the row shows the count in use and the word unlimited.

The device count includes devices that discovery found and withheld at the ceiling, not only the ones admitted. A network of forty devices under a limit of 25 therefore reads 40 against 25, rather than reporting 25 of 25 and looking full but healthy.

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

The top of the page names the customer, the tier in force, the licence id, the expiry date, the grace period and the support entitlement. **Current usage** shows a bar for each measured, enforced ceiling and the honest label for every other row. **Features** lists the seven commercial capabilities, whether this licence grants each one, and the lowest tier that includes it.

Two gauges carry the same state into monitoring. `netops_licence_days_to_expiry` counts whole days and reports the sentinel `36500` when no licence is installed, so a deployment with nothing to expire cannot trip an expiry alert. `netops_licence_state{tier,degraded,in_grace}` reports `1` on the combination in force and `0` on the others, on every scrape.

Three alert rules watch those gauges: `LicenceExpiringSoon` at 14 days, `LicenceInGrace`, and `LicenceDegraded`. All three are warnings. None of them pages, because a lapsed licence lowers commercial ceilings and does not interrupt service.

## What happens at expiry

The mechanism is fixed, and the page states it on every visit. Correlix has not settled the commercial policy around it, and the product does not pretend otherwise.

| State | When | What changes |
| --- | --- | --- |
| Live | Before the expiry date | Nothing |
| In grace | After expiry, inside the grace period the licence file names | Nothing yet. The licensed tier and its capabilities are still in force, with a banner and the `LicenceInGrace` alert |
| Degraded | After the grace period ends | The ceilings and capabilities fall back to Community. The licensed tier is remembered, so the page reports that a Team licence expired rather than pretending the deployment was always Community. Everything over a ceiling is listed |

The grace period is set by the issuer, in the file, and there is no built-in default. A licence that carries no `grace_days` value has no grace: it moves from live to degraded on its expiry date.

Four things never change, in any of the three states, and none of them is a licensed capability:

- **Tenant isolation and data separation.** Every scoping rule, every FORCE-RLS policy and every per-store filter is unaffected.
- **Permissions.** Every authorization check answers exactly as before.
- **Sign-in.** Local accounts and OIDC single sign-on are core and always available.
- **Your data.** Nothing is deleted, nothing is hidden, and no device leaves the inventory.

This is structural rather than a policy choice. The isolation and authentication paths do not consult the entitlement service at all, and a test in the source tree fails the build if any of them ever does.

## Related

- [Licensing](/reference/licensing) for which parts of Correlix are Apache-2.0 and which are commercial add-ons.
- [Administration overview](/administration/overview) for the difference between per-tenant data and platform-global configuration.
- [Read the audit log](/administration/audit-log) to see an installed or refused licence recorded.
- [Honest states](/reference/honest-states) for how Correlix distinguishes not measured from measured as zero.
- [Alert rules](/reference/alert-rules) for the licence alert group.
