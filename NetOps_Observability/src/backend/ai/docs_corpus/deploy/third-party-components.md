---
title: Third-party components and licences
description: Every third-party component a Correlix deployment receives, the licence it carries, and where its notices and source live.
page_type: reference
sidebar_position: 13
---

# Third-party components and licences

Correlix is built on open-source software. This page lists the third-party
components a deployment receives, the licence each one carries, and where to
find the full notices. It covers the components whose licence places an
obligation on Correlix or on you. The complete inventory of every distributed
component, including the permissively licensed ones, ships with the product.

Where to read the full notices:

| Location | What is there |
|---|---|
| `https://<your-host>:8000/licenses/` | The running product serves the full inventory and every licence text. Reach it from the account menu, under **Third-party licences**. |
| `LICENSES.md` in the offline bundle | The same inventory, in the bundle you installed from. |
| `source-offer/` in the offline bundle | The corresponding source for the copyleft components, as archives. |
| `docs/THIRD_PARTY_LICENSES.md` in the source tree | The generated inventory. It is produced from the tree by `scripts/license-audit.py`, so it cannot drift from what the product contains. |

## Components with a licence obligation

Sorted by component name.

| Component | Version | Licence | Where it runs | What this means for you |
|---|---|---|---|---|
| certifi | 2026.5.20 | MPL-2.0 | Inside the correlation container | Correlix modifies nothing in it. The notice and the source pointer ship with the product. |
| elkjs | 0.11.1 | EPL-2.0 | Bundled into the web interface | Correlix modifies nothing in it. The licence text and the source pointer ship at `/licenses/elkjs/`. |
| Grafana | 11.2.0 | AGPL-3.0-only | Its own container, in the optional `self-monitoring` add-on only | See [Grafana and the AGPL](#grafana-and-the-agpl) below. |
| Inter, IBM Plex Mono, Space Grotesk, Manrope | — | OFL-1.1 | Font files in the web interface | The fonts ship unmodified with their licences at `/licenses/fonts/`. |
| Keycloak | 25.0 | Apache-2.0, on a Red Hat Universal Base Image | Its own container, in the default `sso` profile | See [Keycloak and the Red Hat UBI EULA](#keycloak-and-the-red-hat-ubi-eula) below. |
| syslog-ng OSE | 4.7.1 | LGPL-2.1-or-later (core) and GPL-2.0-or-later (modules) | Its own container | See [syslog-ng and the GPL](#syslog-ng-and-the-gpl) below. |
| Vector | 0.40.0 | MPL-2.0 | Its own container | Correlix modifies nothing in it. The `vector.yaml` and VRL transforms are configuration, not modifications. |

Correlix's own source code carries no disclosure, relicensing or network-use
obligation from any component above. Nothing under a copyleft licence is linked
into or bundled into a binary Correlix builds.

## syslog-ng and the GPL

Correlix redistributes syslog-ng OSE 4.7.1 as the unmodified upstream container
image. Its licensing is split: the core is LGPL-2.1-or-later and the modules and
SCL are GPL-2.0-or-later. There is no OpenSSL linking exception.

The GPL requires that anyone who receives the binary can also get the source it
was built from. Correlix ships that source rather than offering to send it
later. Every offline bundle contains:

```
source-offer/syslog-ng-4.7.1.tar.gz
source-offer/README
```

The archive is the complete, unmodified upstream release. Its checksum is
recorded in the bundle's `SHA256SUMS`, so you can confirm that yourself:

```bash
cd correlix-<version>
sha256sum -c SHA256SUMS 2>/dev/null | grep source-offer
```

You may use, study, modify and redistribute syslog-ng under its own licence,
independently of Correlix.

## Grafana and the AGPL

Grafana is licensed under the GNU Affero General Public License, version 3. A
Correlix deployment receives it only if you enable the optional
`self-monitoring` add-on:

```bash
./install-correlix.sh enable self-monitoring
```

A deployment that never enables that add-on contains no AGPL-licensed software.

Correlix ships the stock upstream image, pinned by digest. Correlix does not
rebuild it, patch it, layer anything onto it, or alter the interface it serves,
including its branding. It is configured only through Grafana's own `GF_`
environment variables and its read-only provisioning directory.

AGPL-3.0 section 13 binds the operator of a **modified** version to offer that
version's source to its network users. Correlix runs Grafana unmodified, as a
separate process, on its own route. Correlix's own source is not subject to the
AGPL. Grafana's source for the version shipped is at
`https://github.com/grafana/grafana`, tag `v11.2.0`.

## Keycloak and the Red Hat UBI EULA

Keycloak itself is Apache-2.0. Its container image is built on Red Hat's
Universal Base Image 9, which is governed by the Red Hat Universal Base Image
End User Licence Agreement rather than by an open-source licence.

Correlix has read and accepts that agreement, and redistributes the image under
it. The image ships exactly as the Keycloak project publishes it: a
digest-pinned upstream reference, with no Correlix rebuild and no Correlix layer
on top.

The `sso` profile is on by default, so a default installation receives this
image. Installing Correlix means you receive it and are bound by the same
agreement with respect to it. Red Hat provides no support or warranty for the
image, and nothing in Correlix's packaging implies a Red Hat endorsement,
certification or support relationship.

Read the agreement at
[redhat.com/licenses](https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI).
If it is not acceptable in your environment, run Correlix against an external
identity provider instead. Contact Correlix before you deploy.

## Components that never ship

Two components appear in the source tree but reach no deployment. They are
listed here so that an audit of the repository does not read their presence as
distribution.

| Component | Profile | Why it does not ship |
|---|---|---|
| Gotenberg | `pdf` | The image bundles PDFtk (GPL-2.0-or-later), a proprietary Microsoft font package with redistribution restrictions, and Google Chrome. The bundle build fails if this image ever enters an image set. |
| NetBox | `netbox` | Apache-2.0, and a development and laboratory profile only. It is excluded from every customer bundle by construction. |

## Related

- [Install from an offline bundle](/deploy/install-air-gapped)
- [Turn on an optional module](/deploy/optional-modules)
