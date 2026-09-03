---
title: Install without internet access
description: Build the offline Correlix bundle on a connected host, verify its checksums on the target, and install with no registry, no PyPI and no npm access.
page_type: task
sidebar_position: 6
---

# Install without internet access

An air-gapped install needs nothing on the target host except Docker, the Compose v2 plugin and `zstd`. Every container image, the source tree, the installer and the documentation ship inside one bundle directory that you build on a connected machine and carry across.

Use this when the target host has no egress. For a host that can reach a registry, [Install Correlix on a Linux host](/deploy/install-linux) is shorter.

## Before you begin

- A **build host** with internet access, Docker and the Compose v2 plugin, `zstd`, `git`, and Node with npm. The build compiles the frontend and the documentation portal into the images.
- A **target host** that meets [the deployment requirements](/deploy/requirements), with `zstd` installed. The bundle installer refuses to unpack the image archive without it.
- A transfer path for the bundle directory: removable media, an internal artifact store, or `scp` from a jump host.
- The signing key fingerprint, if your organisation signs bundles. A bundle built without `CORRELIX_SIGNING_KEY` is checksum-only and carries no `SHA256SUMS.asc`.

## Steps

1. On the build host, build the bundle.

   ```bash
   scripts/make-installer.sh
   ```

   Use `--core` for the smallest possible bundle, which is the base appliance with no add-on packs. Use `--out DIR` to write somewhere other than `dist/`.

2. Check what was produced. The bundle directory is self-contained.

   | File | What it is |
   |---|---|
   | `install-correlix.sh` | The customer entry point. |
   | `prepare-host.sh` | Host preparation, run once with `sudo`. |
   | `correlix-source-<version>.tar.gz` | The source tree: compose files, configurations, installer. |
   | `correlix-images-core-<version>.tar.zst` | The base appliance images. |
   | `correlix-addon-<name>-<version>.tar.zst` | One archive per optional add-on pack. |
   | `SHA256SUMS` | The integrity manifest covering every file above. |
   | `MANIFEST` | Version, git sha, profile and image list. |
   | `README.md`, `ADVANCED.md`, `TROUBLESHOOTING.md`, `LICENSES.md` | Customer quickstart, advanced settings, fixes, third-party notices. |

3. Transfer the whole bundle directory to the target host and extract it there.

4. Verify integrity before running anything. The manifest covers every archive, every document, `MANIFEST`, and the three executable scripts, so nothing in the bundle is an unverified execution path.

   ```bash
   sha256sum -c SHA256SUMS
   ```

   If the bundle is signed, verify the signature first:

   ```bash
   gpg --verify SHA256SUMS.asc SHA256SUMS
   ```

5. Prepare the target host, then log out and back in.

   ```bash
   sudo ./prepare-host.sh
   ```

6. Install. With no arguments in an interactive terminal this opens a numbered setup console; in a script it installs directly.

   ```bash
   ./install-correlix.sh
   ```

   To pin the console port, name it:

   ```bash
   ./install-correlix.sh install --ui-port 9443
   ```

   The installer checks the host, verifies the bundle, loads the images, generates credentials, starts every service, waits until the stack is healthy, and prints the console URL and the generated sign-in.

7. Qualify the deployment before you call it done.

   ```bash
   bash scripts/deploy-qualify.sh
   ```

## Result

The installer prints the console URL and the generated credentials. Nothing was pulled and nothing was built: every image came from the archive you carried in.

Day-to-day operation uses the same script:

| Command | What it does |
|---|---|
| `./install-correlix.sh status` | Service health. |
| `./install-correlix.sh logs [service]` | Recent logs, for one service or all. |
| `./install-correlix.sh stop` | Stop the stack. Data is kept. |
| `./install-correlix.sh start` | Start it again. |
| `./install-correlix.sh uninstall` | Remove the stack. Add `--purge` to delete the data too. |
| `./install-correlix.sh reset-demo-data` | Return to fresh evaluation state with the same sign-in. |
| `./install-correlix.sh support-bundle` | Collect a redacted diagnostic archive to send to support. |
| `./install-correlix.sh enable <add-on>` | Turn on an add-on pack: `log-search-ui` or `self-monitoring`. |
| `./install-correlix.sh disable <add-on>` | Turn one off again. |

:::caution `uninstall --purge` deletes the data
Without `--purge` the stack is removed and `data/` survives, so a reinstall finds the stores intact. With `--purge` the stores go too, and nothing recovers them but a backup.
:::

## Installing offline from a source checkout

If you already have the source tree on the target host and only need the images carried in, drive `install.py` directly. `--bundle` implies `--offline`.

```bash
python3 scripts/install.py --bundle correlix-images-core-<version>.tar.zst
```

`--offline` on its own installs from images that are already loaded into the local Docker daemon, and never builds or pulls.

## Collecting diagnostics from an air-gapped host

`support-bundle` is the supported way to get evidence off a disconnected host. It writes one `.tar.zst` at mode `0600` and redacts in two independent passes: by key name, and by literal value taken from the stack's own `.env`, so a secret is masked even where it appears inside a log line with no key name beside it. `.env` itself ships as key names only, with no value at all.

```bash
./install-correlix.sh support-bundle --since 24h
```

Over-redaction is deliberate. A non-secret setting whose key name contains `KEY` is masked too; tell support the value directly if it matters. Read the bundle's `MANIFEST` before sending it.

## Related

- [Deployment requirements](/deploy/requirements)
- [Verify a deployment is doing work](/deploy/verify-deployment)
- [Upgrade a deployment](/deploy/upgrade)
