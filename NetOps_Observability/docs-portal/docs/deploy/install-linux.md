---
title: Install Correlix on a Linux host
description: Prepare an Ubuntu or Debian host, run scripts/install.py from a source checkout, and finish with a signed-in console and a qualified pipeline.
page_type: task
sidebar_position: 5
---

# Install Correlix on a Linux host

This is the standard install for a host that can reach a container registry. It takes a prepared Ubuntu 22.04 or Debian 12 server from nothing to a running console with generated credentials. Budget about 30 minutes on a clean virtual machine.

If the host has no internet access, use [Install without internet access](/deploy/install-air-gapped) instead. Both paths produce the same stack.

## Before you begin

- A host that meets [the deployment requirements](/deploy/requirements): x86_64, Ubuntu 22.04 or Debian 12 or newer, 4 vCPU, 16 GB RAM, 100 GB free on the Docker root filesystem.
- Root or `sudo` for host preparation. The stack itself runs as a member of the `docker` group.
- The Correlix source tree, staged on the host.
- A workload declaration if you are sizing for production. See [Plan host resources](/deploy/sizing).
- Decide before you start whether this deployment uses TLS. The installer asks once, and an interactive run defaults to yes. See [Enable TLS and mTLS](/deploy/enable-tls).

## Steps

1. Prepare the host. This installs Docker Engine and the Compose v2 plugin from Docker's official repository, sets the kernel parameters, creates the `correlix` service account, and enables unattended security upgrades. It is idempotent.

   ```bash
   sudo bash scripts/prepare-host.sh
   ```

   Log out and back in afterwards so your `docker` group membership takes effect.

2. Confirm the host is ready. The audit changes nothing and exits non-zero if any item still needs fixing.

   ```bash
   sudo bash scripts/prepare-host.sh --check
   docker compose version
   ```

   The legacy `docker-compose` binary is not supported. If `docker compose version` fails, install the Compose v2 plugin before going further.

3. Stage the source tree where the deployment will live. Copy or clone it into place, then work from that directory for the rest of this procedure.

   ```bash
   sudo mkdir -p /opt/netops
   sudo chown $USER:$USER /opt/netops
   # copy or clone the source tree to /opt/netops/NetOps_Observability
   cd /opt/netops/NetOps_Observability
   ```

4. Open the host ports the deployment needs. Correlix publishes the console on TCP 8000 and the ingest ports for syslog, traps and flows.

   ```bash
   sudo ufw allow 8000/tcp
   sudo ufw allow 514/udp
   sudo ufw allow 514/tcp
   sudo ufw allow 2055/udp
   sudo ufw allow 4739/udp
   sudo ufw allow 6343/udp
   ```

   Docker publishes container ports through iptables and bypasses UFW. Restrict access to the console and the ingest ports with an upstream network ACL too.

5. Run the installer.

   ```bash
   python3 scripts/install.py
   ```

   It verifies the prerequisites, validates the scaffold, generates `deployment/docker/.env` with random secrets at mode `0600`, creates the `data/` directories, plans resources, builds and starts the stack, applies the Kafka authorization matrix, and applies the OpenSearch index templates.

6. Answer the transport-security question when it appears.

   ```
   Enable TLS/mTLS transport security? [Y/n]
   ```

   Answering yes runs the two-phase enablement described in [Enable TLS and mTLS](/deploy/enable-tls) and moves the console to 443. A non-interactive run without `--tls` keeps the plaintext baseline.

7. Read the admin password out of `.env`. The installer prints where it is; the value is `ADMIN_INITIAL_PASSWORD` and the user is `admin`.

   ```bash
   grep '^ADMIN_INITIAL_PASSWORD=' deployment/docker/.env
   ```

8. Install the systemd unit so the stack starts at boot.

   ```bash
   sudo cp scripts/netops.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now netops
   ```

9. Qualify the deployment. A clean `docker compose ps` is not evidence that the pipeline is doing work.

   ```bash
   bash scripts/deploy-qualify.sh
   ```

   See [Verify a deployment is doing work](/deploy/verify-deployment) for what each check proves and what the exit codes mean.

10. Sign in to the console and change the admin password.

## Result

The console answers on the port you installed it on, and the health route returns a JSON status:

```bash
curl -fs http://localhost:8000/admin/health
```

```json
{"status":"healthy"}
```

Signing in with `admin` and `ADMIN_INITIAL_PASSWORD` reaches the console. The device inventory is empty until you onboard devices, which is the next task: see [Onboard devices](/onboard-devices/overview).

Every run also writes `data/install-timing.json` with one row per installer stage, on a failed run as much as on a successful one. `--time-report` prints the same table at the end of the run. Which stage a host gets stuck on is the useful number; no reference figures are published, because they depend on host CPU, disk, image pull against offline bundle, and whether TLS was enabled. Measure your own baseline on the first install and treat later runs as deltas against it.

## Installer flags worth knowing

| Flag | What it does |
|---|---|
| `--port PORT` | Host port for the console. Default `8000`. |
| `--tls {yes,no}` | Answer the transport-security question non-interactively. The flag wins over the prompt. |
| `--plan-resources [PROFILE]` | Generate host-derived and workload-derived limits into the managed `.env` block. `demo`, `small`, `medium`, `large`, `custom`, or `auto`. |
| `--no-plan-resources` | Skip resource planning and keep the static compose defaults. |
| `--sizing-file YAML` | The `correlix-sizing.yaml` workload inputs for `--plan-resources`. |
| `--replan` | Regenerate only the resource-plan block in an existing `.env`, then exit. |
| `--rollback-plan` | Restore `.env` and the plan artifacts from the pre-replan backup, then exit. |
| `--retention-profile {lab,demo,production,extended}` | Correlation history retention written to `.env`. Default `production`. |
| `--profiles CSV` | Compose profiles to activate. Default `embedded-bus,prober,osd,self-monitoring,sso`. |
| `--broker-urls HOST:PORT[,...]` | Point every service at an external Kafka-compatible broker and disable the embedded bus. |
| `--snmp-discovery CIDR[,CIDR]` | Enable SNMP discovery scoped to these ranges. Absent, discovery stays off. |
| `--offline` | Air-gapped install: start from pre-loaded images, never build or pull. |
| `--bundle IMAGES.tar.zst` | Load an image archive first. Implies `--offline`. |
| `--reset-env` | Rotate secrets. On a never-started install this regenerates `.env` wholesale. |
| `--rotate-app-secrets` | Rotate only the secrets that can be rotated safely against the live stores, then exit. |
| `--bootstrap-docker {yes,no}` | Answer the Ubuntu and Debian Docker-bootstrap prompt non-interactively. |
| `--no-start` | Generate configuration without running `docker compose up`. |
| `--progress-json` | Emit machine-readable progress markers alongside the human output. |
| `--time-report` | Print the per-stage wall-clock table when the run ends. |

## After the install

Work through these before the deployment carries real traffic.

- Change the admin password from the generated one.
- Terminate HTTPS in front of the console, or enable the built-in TLS mesh.
- Narrow SNMP discovery. The shipped default scope is `10.0.0.0/8`, which is wider than most real management networks.
- Configure a daily backup with an off-host destination. See [Back up and restore](/deploy/back-up-and-restore).
- Restrict the console and the ingest ports to known device ranges at the network layer.
- Review retention: the correlation retention profile, the ClickHouse table TTLs, and the OpenSearch index policies.

## Related

- [Verify a deployment is doing work](/deploy/verify-deployment)
- [Enable TLS and mTLS](/deploy/enable-tls)
- [Turn on an optional module](/deploy/optional-modules)
- [Onboard devices](/onboard-devices/overview)
