---
title: Licensing
description: Which parts of Correlix are Apache-2.0 open source, which are commercial add-on modules, and how to tell from a file or a container image.
page_type: reference
sidebar_position: 5
---

# Licensing

Correlix core is licensed under the Apache License, Version 2.0. Commercial add-on modules are licensed under the Correlix Enterprise License (LicenseRef-Correlix-Enterprise) — see LICENSING.md.

Correlix is open core. You get the engine, the pipeline and the isolation model
under Apache-2.0, and you may run them in production, modify them and
redistribute them. A named set of add-on modules carries a separate commercial
licence.

## The two licences

| SPDX identifier | Text in the source tree | What it permits |
|---|---|---|
| `Apache-2.0` | `LICENSES/Apache-2.0.txt` | Use, modification, redistribution and production use, under the terms of the Apache License, Version 2.0. |
| `LicenseRef-Correlix-Enterprise` | `LICENSES/Correlix-Enterprise.txt` | Inspection, development and evaluation. Production use requires a commercial licence from Correlix. Redistribution and hosting as a service are not permitted. |

:::caution The Correlix Enterprise License text is not drafted yet
`LICENSES/Correlix-Enterprise.txt` is a placeholder as of 2026-09-04. Files
marked with that identifier carry a licence that has no terms, so no rights in
them are granted, and Correlix does not ship a release in this state. The
release gate refuses the build while the placeholder is present.
:::

## What is Apache-2.0

The parts of Correlix a network engineer runs every day are core and stay core:

- Device discovery, collection and multi-protocol telemetry ingestion.
- The telemetry pipeline, the event bus and the storage bootstraps.
- The correlation engine and root-cause analysis: verdicts, causality paths,
  seams and evidence classes.
- The investigation and troubleshooting surface, including protocol diagnostics.
- Topology, IGP and VRF depth, and interface intelligence.
- BGP views built on public data: the looking glass, RPKI, the AS-path graph
  and geofeed.
- Local user accounts and OIDC single sign-on.
- The licence mechanism itself, so you can read exactly what limits your tier.

### Tenant isolation is core in every edition

Tenant and organisation isolation is Apache-2.0 and is never a commercial
add-on. Every edition gets the same default-closed scoping, the same
FORCE-RLS policies in Postgres and the same per-store filters. A cross-tenant
leak is a defect in every edition, so the code that prevents one belongs to
everybody.

Managing many tenants as one account is a different thing, and that management
surface is commercial. Being isolated from another tenant is not.

## What is commercial

The owner has locked exactly this set. A capability outside it is not gated,
whatever a draft tiering document proposes.

| Entitlement | Tier | What it covers |
|---|---|---|
| `security_findings` | Team | The security-findings lane: normalized findings, exposures, the findings API and its retention. |
| `security_dialects` | Enterprise | Device-hardening dialects beyond the default set, and compliance frameworks beyond the default two. |
| `siem_export` | Enterprise | Export of findings and evidence to an external SIEM. |
| `msp_management` | Enterprise | MSP and organisation-hierarchy management of many tenants. |
| `saml` | Enterprise | SAML single sign-on. |
| `scim` | Enterprise | SCIM user and group provisioning. |
| `ldap` | Enterprise | LDAP and Active Directory authentication. |

`docs/design/TIERING_PLAN_2026-09-03.md` in the source tree records the ceilings
each tier carries.

## How to tell which licence a file is under

Check three places, in this order.

1. **The file header.** A source file may declare its own licence on its first
   comment line:

   ```go
   // SPDX-License-Identifier: Apache-2.0
   ```

   ```go
   // SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
   ```

2. **A `LICENSE` file in the directory.** Every commercial directory carries
   one naming its identifier, so you learn the terms without leaving the
   directory.

3. **The default.** A file with no header, in a directory with no Enterprise
   notice file, is Apache-2.0. Nothing becomes commercial by omission.

`LICENSING.md` at the root of the source tree maps every directory to one of
the two licences. It is generated from `licensing-policy.json`, so it cannot
drift from what the build enforces.

### Some directories still mix the two

A few packages contain core code and commercial code together, because the
commercial part has not been separated into its own package yet. Those
directories stay Apache-2.0 in full until the separation lands: the
conservative direction is the open one. `LICENSING.md` names each of them under
"Still mixed".

## How to tell which licence an image is under

Every Correlix container image declares its licence in OCI metadata:

```bash
docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' \
  ghcr.io/correlix/netops-api:latest
```

Images that only repackage third-party software, such as the trimmed OpenSearch
image and the Vector router, carry no Correlix licence label. Labelling
somebody else's software with the Correlix licence would be a false claim.

## Third-party components

The split above covers Correlix's own code. Software that Correlix
redistributes keeps its own licence and its own obligations. The product serves
the full inventory at `/licenses/` on the same port as the console, and the
source tree carries it in `NOTICE` and `docs/THIRD_PARTY_LICENSES.md`.

## Related

- [Third-party components](../deploy/third-party-components.md)
- [Feature flags](feature-flags.md)
