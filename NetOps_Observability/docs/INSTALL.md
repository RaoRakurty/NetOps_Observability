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

### Which URL, and why `:8000` stops answering

The transport question you answered during setup decides the address:

| Transport | Dashboard | API | What `http://<host>:8000` does |
|---|---|---|---|
| **TLS/mTLS** (the default) | `https://<host>/` | `https://<host>/api/` | **nothing — the connection is refused** |
| Plaintext (evaluation) | `http://<host>:8000` | `http://<host>:8000/api/` | serves the dashboard |

On a TLS install the ingress moves to **443** and the plaintext port is
published to **loopback only** (`127.0.0.1:8000`). That is deliberate: an
appliance that advertises a full TLS mesh must not also hand the whole
dashboard — and `POST /api/auth/login`, carrying the administrator password —
to anything that can reach the host, in the clear. If you have an old bookmark
on `:8000`, replace it with `https://<host>/`; from the server itself
`curl http://localhost:8000/` still answers, because that is where the
appliance's own health, qualification and watchdog probes run.

### Per-tenant sign-in URLs

Every tenant also has its own sign-in link under the same address:

| Link | Example |
|---|---|
| Tenant path | `https://<host>/t/<tenant-slug>` |
| Organization path (rename-proof) | `https://<host>/org/<org-id>` |

Nothing extra is deployed for them. The SPA is still one static bundle: nginx
already falls back to `index.html` for an unknown path, so `/t/<slug>` serves
the ordinary sign-in page, which then asks the api
`GET /api/auth/locator?path=/t/<slug>` to resolve the slug to the tenant's
permanent identifier and to arm a signed, HttpOnly candidate cookie. The slug is
never trusted for anything but deciding which sign-in doors to show.

A tenant link signs in **that tenant's accounts only**. An account in another
tenant, in the `global` tenant, or in no tenant is refused there, so your own
platform-administrator account does not sign in at `/t/<slug>`. Use the
installation's own address, `https://<host>/`, and a provider no tenant owns
(or `GET /api/auth/sso/login?idp=<alias>` directly).

The SSO sub-paths are the exception and DO reach the api: an identity provider
redirects the browser to `/t/<slug>/sso/<provider>/callback`, so
`deployment/docker/nginx/default.conf` carries one narrow regex location that
proxies `/t/…/sso/…/callback` and `/t/…/sso/…/login` (and their `/org/`
twins) to the api. Keep that
block in step across `default.conf`, `default-mtls.conf` and the Helm copy — it
is the only route the three files need for this feature. Per-tenant URLs are
otherwise self-configuring: a provider bound to a tenant shows its own redirect
URI to copy in **Administration → Authentication → Single Sign-On**.

Custom subdomains (`acme.<host>`) and customer domains are reserved in the
design and **deferred** — they need a DNS and TLS plane a self-hosted
single-port deployment does not have.

The certificate a fresh install generates is **self-signed**, so a browser
warns once. Replace `deployment/docker/nginx/certs/fullchain.pem` and
`privkey.pem` with a certificate from your own issuer (same filenames), then
`cd deployment/docker && docker compose restart nginx`.

---

## Afterwards

```bash
./install-correlix.sh status              service health
./install-correlix.sh logs [service]      recent logs
./install-correlix.sh stop | start        stop/start, data kept
./install-correlix.sh enable log-search-ui        optional add-on
./install-correlix.sh enable self-monitoring      optional add-on
./install-correlix.sh enable sso                  optional add-on
./install-correlix.sh support-bundle      redacted diagnostics for support
./install-correlix.sh uninstall           remove (--purge also deletes data)
```

### Optional add-ons ship as separate files

The bundle is deliberately split. The **base appliance** — discovery, every
collector, the bus, all four stores, correlation, the API and the dashboard —
is one archive, `correlix-images-core-<version>.tar.zst`, and it is everything
Correlix needs to watch your network. Anything optional is its own file
alongside it:

| Add-on | File | What it adds |
|---|---|---|
| `log-search-ui` | `correlix-addon-log-search-ui-<version>.tar.zst` | OpenSearch Dashboards for power-user log forensics |
| `self-monitoring` | `correlix-addon-self-monitoring-<version>.tar.zst` | Grafana + container/host metrics for the stack itself |
| `sso` | `correlix-addon-sso-<version>.tar.zst` | Keycloak, brokering SAML / LDAP / OIDC identity providers |

Nothing you do not enable is ever loaded, and no add-on starts by itself. You
can choose them up front — the graphical installer's **Deployment** step and
the terminal setup console both list all three — or run
`./install-correlix.sh enable <name>` at any time afterwards.

If you enable an add-on whose file is not next to the installer, the installer
**names the missing pack and stops**. It never reaches for the internet: an
appliance installs air-gapped, so a silent pull would only fail later and less
clearly. Copy the pack next to `install-correlix.sh` and run the command again.

> **SSO note.** `sso` is off by default and its file may not be in your
> download. Correlix's own username/password and API tokens work without it;
> Keycloak is only needed to broker an external identity provider.

### Where the rest is documented

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
