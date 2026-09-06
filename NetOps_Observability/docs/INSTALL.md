# Installing Correlix

Everything below happens on **your** server. Correlix needs no internet access
to install or to run, and it never contacts us.

This page is the customer-facing summary. The bundle itself carries the same
instructions in `README.txt` (plain text), plus `OPERATIONS.md`,
`TROUBLESHOOTING.md`, `SUPPORT.txt` and the full documentation portal under
`docs/index.html`.

---

## 1. What you need

| | Evaluation | Production (recommended) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB | 100 GB+ |
| OS | Ubuntu 22.04+ / Debian 12, x86_64 | same |

You need `sudo` on that server. You do **not** need Docker beforehand —
`prepare-host.sh` installs it.

## 2. Unpack and verify

```bash
tar -xzf correlix-<version>.tar.gz
cd correlix-<version>
sha256sum -c CHECKSUMS.sha256
```

`CHECKSUMS.sha256` and `SHA256SUMS` are the same manifest under two names. If a
`SHA256SUMS.asc` is present, the bundle is signed and the installer verifies the
signature itself before it loads anything.

## 3. Prepare the host (once)

```bash
sudo ./prepare-host.sh
```

Installs Docker Engine and Compose v2, sets the kernel parameters the log store
needs, and adds you to the `docker` group. **Log out and back in afterwards.**
Already have Docker? Skip it — the installer checks either way and refuses to
install on an unready host.

Read-only audit, changing nothing: `sudo ./prepare-host.sh --check`.

## 4. Install

```bash
./install-correlix.sh
```

The first question is how you want to install:

**Graphical.** The installer asks which of the host's addresses to serve the
wizard on (it lists them; the first non-loopback interface is the default) and
whether to use HTTPS or HTTP. HTTPS is the default: a certificate is generated
on the spot and its SHA-256 fingerprint is printed in the terminal so you can
compare it in the browser's warning screen. A one-time access token is printed
with the URL — it is not a password you set, and it works once.

Then a five-part wizard: readiness → host preparation → deployment options →
discovery and sizing → settings → install → done. Every step states its default
and why. Nothing on the host changes until you press **Install** on the review
screen.

**Terminal.** The same install as a numbered menu, in the terminal you are
already in. Both paths run the same installer, so neither can do anything the
other cannot.

Non-interactive (CI, scripted rollout):

```bash
./install-correlix.sh install
./install-correlix.sh install --config profile.json   # exported from the wizard
```

## 5. Sign in

The installer prints the dashboard URL and the administrator password when it
finishes, and verifies that credential actually works before printing it. The
password is shown once; it is also in
`NetOps_Observability/deployment/docker/.env`, which you should treat as a
secret. Change it in Settings after your first sign-in.

---

## Afterwards

```bash
./install-correlix.sh status              service health
./install-correlix.sh logs [service]      recent logs
./install-correlix.sh stop | start        stop/start, data kept
./install-correlix.sh enable log-search-ui        optional add-on
./install-correlix.sh enable self-monitoring      optional add-on
./install-correlix.sh support-bundle      redacted diagnostics for support
./install-correlix.sh uninstall           remove (--purge also deletes data)
```

Sizing, upgrade, rollback, backup and uninstall are in the bundle's
`OPERATIONS.md`. Advanced settings — external Kafka, a different UI port, the
licence file, the pipeline debugger — are in `ADVANCED.md`.

## If something goes wrong

1. `./install-correlix.sh status` — which service is unhappy?
2. `TROUBLESHOOTING.md` in the bundle.
3. `./install-correlix.sh support-bundle`, then send it with the bundle's
   `MANIFEST`. Secrets are stripped; read the bundle's own MANIFEST first.

---

## For maintainers: building the bundle

`scripts/make-installer.sh` builds `dist/correlix-<version>/`. There is a
`make bundle` target, but `make` is not installed everywhere — the direct call
is the reliable one:

```bash
bash scripts/make-installer.sh              # base + add-on packs
bash scripts/make-installer.sh --core       # smallest evaluation bundle
bash scripts/bundle-staleness.sh            # is the newest bundle current?
```

The build needs Docker, ~20 GB of free disk and a `docs-portal/build` and
`src/frontend/dist` that are current (it rebuilds the frontend unless
`REBUILD_FRONTEND=0`). On a host whose egress re-signs TLS, pass
`APK_REPO_SCHEME=http`; to mirror the GPL/LGPL corresponding source from a local
copy rather than fetching it, pass
`CORRELIX_SOURCE_MIRROR_DIR=compliance/corresponding-sources`.
