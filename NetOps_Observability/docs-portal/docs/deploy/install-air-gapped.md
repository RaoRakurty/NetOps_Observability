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
   | `README.txt` | Start here. Plain text, one page, no markdown to read past. |
   | `install-correlix.sh` | The customer entry point. |
   | `prepare-host.sh` | Host preparation, run once with `sudo`. |
   | `correlix-source-<version>.tar.gz` | The source tree: compose files, configurations, installer. |
   | `correlix-images-core-<version>.tar.zst` | The base appliance images. |
   | `correlix-addon-<name>-<version>.tar.zst` | One archive per optional add-on pack. |
   | `SHA256SUMS`, `CHECKSUMS.sha256` | The integrity manifest, under both names. The second is a symlink to the first. |
   | `MANIFEST` | Version, git sha, profile and image list. |
   | `README.md`, `ADVANCED.md`, `TROUBLESHOOTING.md` | Quickstart, advanced settings, fixes. |
   | `OPERATIONS.md` | Requirements, workload sizing, upgrade, rollback, backup, uninstall. |
   | `SUPPORT.txt` | What to try first, and exactly what to send when you contact support. |
   | `RELEASE-NOTES.md` | What changed in this version, generated from the commit log. |
   | `docs/index.html` | The full documentation portal, built static. Readable with no network. |
   | `LICENSES.md`, `LICENSE`, `LICENSING.md`, `LICENSES/`, `NOTICE` | Third-party notices and the project's own licence. |
   | `source-offer/` | Corresponding source for the GPL/LGPL components Correlix redistributes. |
   | `correlix-setup`, `correlix-debug`, `correlix-licence` | The graphical installer, the pipeline debugger, the offline licence verifier. |

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

6. Install. With no arguments in an interactive terminal, the first question is how you want to install — graphical or terminal. In a script it installs directly, with no questions.

   ```bash
   ./install-correlix.sh
   ```

   **Graphical.** The installer lists this host's management addresses, defaults to the first non-loopback interface, and asks which to serve the wizard on. HTTPS is the default: a certificate is generated at launch and its SHA-256 fingerprint is printed in the terminal so you can compare it in the browser's warning screen. A one-time access token is printed with the URL. HTTP is available but has to be chosen and then confirmed by typing `http`; in that mode host preparation stays disabled, because the sudo password is only ever accepted over TLS.

   The wizard walks readiness, host preparation, deployment options, discovery, sizing, settings, review, install and done. Nothing on the host changes until you press **Install** on the review screen, and the review screen exports the configuration as a profile you can replay on any other host.

   **Terminal.** The same install as a numbered console menu. Both paths drive the same installer.

   Skip the question and go straight to one path:

   ```bash
   ./install-correlix.sh gui         # graphical
   ./install-correlix.sh console     # terminal menu
   ./install-correlix.sh install     # non-interactive
   ./install-correlix.sh install --config profile.json   # replay an exported profile
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
