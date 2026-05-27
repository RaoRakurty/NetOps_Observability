# Linux server deployment

This is the recommended way to run NetOps Observability in production.
Estimated time: 30 minutes from a clean Ubuntu 22.04 / Debian 12 VM.

## Sizing

| Devices monitored | CPU      | RAM   | Disk        |
|-------------------|----------|-------|-------------|
| < 50              | 4 vCPU   | 8 GB  | 100 GB SSD  |
| 50–500            | 8 vCPU   | 16 GB | 250 GB SSD  |
| 500–5000          | 16 vCPU  | 32 GB | 1 TB SSD    |

OpenSearch is the heaviest single service — bump its JVM heap in
`docker-compose.yml` (`OPENSEARCH_JAVA_OPTS`) when devices grow.

## 1. Install Docker + Compose v2

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify
docker --version
docker compose version
```

Add yourself to the docker group so you don't need sudo for every
`compose` call:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## 2. Stage the project

```bash
sudo mkdir -p /opt/netops
sudo chown $USER:$USER /opt/netops
git clone <your-repo-url> /opt/netops/NetOps_Observability
cd /opt/netops/NetOps_Observability
```

…or `scp -r` from your dev box.

## 3. Set host kernel parameters for OpenSearch

OpenSearch refuses to start if `vm.max_map_count` is too low:

```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-opensearch.conf
sudo sysctl --system
```

## 4. Open firewall ports

| Port  | Proto    | What                                    |
|------:|----------|-----------------------------------------|
| 8000  | TCP      | Dashboard (HTTP — front with HTTPS LB)  |
| 514   | UDP/TCP  | Syslog from devices                     |
| 2055  | UDP      | NetFlow v5/v9                           |
| 4739  | UDP      | IPFIX                                   |
| 6343  | UDP      | sFlow                                   |

UFW example:

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
sudo ufw allow 2055/udp
sudo ufw allow 4739/udp
sudo ufw allow 6343/udp
```

If you want devices to send to the standard 514 port instead of 5514,
set `SYSLOG_PORT=514` in `.env` before the first `docker compose up`.

## 5. Run the installer

```bash
cd /opt/netops/NetOps_Observability
python3 scripts/install.py
```

The installer:

* Verifies Docker + Compose v2 are available.
* Validates the scaffold.
* Generates random secrets in `deployment/docker/.env` (mode 0600).
* Creates `data/*` directories.
* Builds and starts the stack.

Note the admin password printed at the end — that's also written to
`.env` as `ADMIN_INITIAL_PASSWORD`.

After the first start, run the OpenSearch index-template bootstrap:

```bash
scripts/bootstrap-opensearch.sh
```

## 6. Install the systemd unit

```bash
sudo cp scripts/netops.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netops
sudo systemctl status netops
```

The unit calls `docker compose up -d --remove-orphans` at boot and
`docker compose down` at stop. The stack already has
`restart: unless-stopped` on every service — systemd just gates the
"start at boot" behaviour and gives you a single `systemctl` interface.

## 7. HTTPS

The scaffold serves plain HTTP on :8000. **Do not expose that publicly.**
Two recommended patterns:

### A. Cloud load balancer in front (preferred)

AWS ALB / GCP HTTPS LB / Azure Application Gateway — terminate TLS,
forward to the host on :8000. The simplest path; no cert management on
the host.

### B. Caddy in front (single-host)

```bash
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile <<'EOF'
netops.example.com {
    reverse_proxy localhost:8000
}
EOF
sudo systemctl reload caddy
```

Caddy auto-provisions Let's Encrypt certs and renews them.

### C. nginx + certbot

Replace `/opt/netops/NetOps_Observability/deployment/docker/nginx/default.conf`
with a TLS-aware config and bind-mount your certs into the nginx
container. The repository's nginx is intentionally minimal because we
expect terminators in front.

## 8. Back up data

The whole `data/` directory is what you back up. Postgres, Redis,
VictoriaMetrics, OpenSearch, ClickHouse, Redpanda, and the user store
all persist there. `scripts/backup.sh` wraps the right `docker compose
exec ... pg_dump` / `clickhouse-backup` / file-copy commands; cron
`backup.sh` nightly and rsync the output off-host.

```bash
0 3 * * * /opt/netops/NetOps_Observability/scripts/backup.sh \
  /var/backups/netops/$(date +\%F).tar.zst
```

## 9. Verify

```bash
curl -fs http://localhost:8000/admin/health
curl -fs http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<from .env>"}'
```

Browse to `https://<your-cert-domain>/`, sign in, change the admin
password.

## 10. Operational checklist

- [ ] HTTPS terminating in front of nginx
- [ ] Admin password changed from initial
- [ ] OpenSearch index templates applied
- [ ] Daily backup cron entry
- [ ] Off-host backup destination configured
- [ ] System monitoring of the host (CPU, disk, memory) — separate from this stack
- [ ] Log retention reviewed in compose: `VICTORIA_RETENTION`, `LOKI_RETENTION_PERIOD` (deprecated), ClickHouse TTL, OpenSearch ILM
- [ ] Network ACL: management ports (8000, 514, 2055, 4739, 6343) restricted to known device ranges
- [ ] `JWT_SECRET` is not the installer-generated default if you've forked the repo
- [ ] OpenSearch `DISABLE_SECURITY_PLUGIN` flipped to `false` and TLS + auth configured
- [ ] Redpanda SASL configured for any remote producers
