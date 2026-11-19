# Quick reference

All commands assume you're in the `deployment/docker` directory unless
noted otherwise.

## Lifecycle

```
docker compose up -d --build      # start (or rebuild and start)
docker compose ps                 # status
docker compose logs -f            # tail everything
docker compose logs -f api        # tail just the API
docker compose restart api        # restart one service
docker compose down               # stop (all state stays on disk)
```

State lives in **bind mounts under `data/`**, not named volumes, so
`docker compose down -v` does not wipe it (and must not be relied on to). Never
`rm -rf` `data/opensearch-snapshots` (the backup repository). Use `scripts/deploy.sh` (see `docs/runbooks/deploy.md`) to
rebuild and recreate services rather than a bare `up -d --build`, and prove the
result with `scripts/deploy-qualify.sh`.

## Health checks

```
curl -fs http://localhost:8000/admin/health | jq      # public
curl -fs http://localhost:8000/admin/version          # public
```

With TLS (the interactive default) use `https://<host>` — `:8000` is then
loopback-only. Every `/api/*` route needs a Bearer token
(`POST /api/auth/login`); `/admin/health` and `/admin/version` are the public
probes.

## Rotating secrets

From the project root:

```
python3 scripts/install.py --rotate-app-secrets
cd deployment/docker && docker compose up -d --force-recreate
```

This rotates every secret that can be rotated **for real** on a running install:
the application secrets (`JWT_SECRET`, `INGEST_TOKEN`, …) plus the store
credentials it can reconcile against the live store and verify (`DB_PASSWORD`,
`CLICKHOUSE_PASSWORD`, `NETBOX_DB_PASSWORD`, `GRAFANA_CH_PASSWORD`). Operator
edits in `.env` are preserved; the previous file is kept as `.env.rotate.bak`.

`--reset-env` is still the "rotate everything" switch, but on a **started**
install it refuses (exit 2, `.env` untouched) for anything it cannot honour —
`KAFKA_CLUSTER_ID` is immutable once the broker's volume is formatted, and the
Grafana/Keycloak/NetBox/dashboard admin passwords are seeded into their stores on
first boot only. `docker compose restart` does **not** pick up a new `.env`; use
`up -d --force-recreate`.

Full matrix and the per-secret manual paths: `docs/runbooks/secret-rotation.md`.

## Something is "healthy" but nothing is happening

`docker compose ps` proves a container is running, not that it is doing work —
on 2026-09-02 the correlation engine consumed nothing for three hours with
every healthcheck green. Start here:

* `docs/runbooks/engine-not-consuming.md` — triage, the ACL/topic bootstrap,
  and how to tell "joined but stuck" from "never joined".
* `docs/runbooks/engine-liveness-matrix.md` — what proves each service is
  working, per service.
* `scripts/deploy-qualify.sh` — run after every `compose up`; it asserts the
  engines are actually consuming instead of trusting exit code 0.

## Adding a device manually

With a Bearer token (`-H "Authorization: Bearer $TOKEN"`):

```
curl -X POST http://localhost:8000/api/devices \
  -H 'Content-Type: application/json' \
  -d '{"id":"router-01","name":"router-01","address":"10.0.0.1"}'
```

Or use the Devices tab in the dashboard.

## Adding an alert rule

```
curl -X POST http://localhost:8000/api/rules \
  -H 'Content-Type: application/json' \
  -d '{"name":"HighCPU","expr":"cpu_usage > 90","for":300000000000,"severity":"warning"}'
```

The `for` field is a Go duration in nanoseconds when sent over JSON.
The Rules UI tab handles this for you.

## Database

```
docker compose exec postgres pg_dump -U netops netops > backup.sql
docker compose exec -i postgres psql -U netops netops < backup.sql
```

## Configuring the Source of Truth (external inventory)

Configure it in the UI: **Automation → Source of Truth → Set up** — pick the
bundled inventory (auto-wired) or point at an external instance (URL + API
token, stored encrypted). No restart needed; the collector picks up changes
on its next poll.

Legacy env-based setup still works as a fallback:

1. Edit `deployment/docker/.env`:
   ```
   NETBOX_URL=https://inventory.example.com
   NETBOX_TOKEN=...
   ```
2. `docker compose up -d` (recreates the api container with the new env).

## Configuring SNMP discovery range

Set it in the UI: **Administration → Discovery → Network Scan**
(`#/admin/discovery`). Discovery is off until you scope and enable it. It has no
community of its own: it tries the platform-owned profiles in **Administration →
Discovery → SNMP Profiles**; `SNMP_COMMUNITY` is not used by the sweep.
`ENABLE_SNMP_DISCOVERY` / `SNMP_CIDR_RANGES` in `.env` are only the bootstrap
default when nothing has been saved in the UI (the installer writes discovery off
with no range).

## Configuring alert channels

Configure channels in the UI: **Administration → Notifications** (stored
encrypted; no restart). All channels are off by default. The `FEATURE_*` and
credential lines below are the legacy `.env` wiring: they only **seed** the
stored configuration on the very first boot, when nothing has been saved yet —
after that the Notifications page is the one place to change them.

### Slack

```
FEATURE_SLACK_NOTIFICATIONS=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### PagerDuty (incl. voice escalation on paid tiers)

```
FEATURE_PAGERDUTY_NOTIFICATIONS=true
PAGERDUTY_KEY=...   # Events v2 integration key
```

### Email (any SMTP server — Gmail app password, SES, SendGrid, etc.)

```
FEATURE_EMAIL_NOTIFICATIONS=true
SMTP_HOST=smtp.example.com:587
SMTP_FROM=monitoring@example.com
SMTP_USER=...
SMTP_PASS=...
SMTP_TO=oncall@example.com,backup@example.com
```

### SMS via Twilio (E.164 numbers)

```
FEATURE_TWILIO_NOTIFICATIONS=true
TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=+15551234567
TWILIO_TO_NUMBERS=+15557654321,+15559998888
```

### SMS via AWS SNS

```
FEATURE_SNS_NOTIFICATIONS=true
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
SNS_PHONE_NUMBERS=+15557654321
# Or publish to a topic instead — SNS will fan out to subscribed
# emails, SMS numbers, SQS queues, Lambda, etc.
SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:netops-alerts
```

The Settings tab in the dashboard shows which integrations the API
sees as configured — useful for sanity-checking after editing `.env`.

## Cloud connector runtime (Wave 4 #13)

```
# Platform OIDC issuer for KEYLESS cloud federation. Set to the public
# https URL customers' clouds reach this appliance at; the backend then
# serves /.well-known/openid-configuration + /.well-known/jwks.json and
# the Identity Broker MINTS a short-lived per-connector assertion for
# every federated exchange (AWS AssumeRoleWithWebIdentity, Azure Entra
# WIF, GCP STS). Unset = dormant: the broker falls back to a projected
# token (CLOUD_CONNECTOR_WORKLOAD_JWT[_FILE]). Signing key is generated
# on first boot and Vault-sealed.
CLOUD_WORKLOAD_ISSUER_URL=https://correlix.example.com

# cloud-ingest poller self-metrics (/metrics, Prometheus text): per-
# provider credential-exchange counters + latency. "off" disables.
CLOUD_INGEST_METRICS_PORT=9109
```

## Optional modules

All three are off by default and the modules are inert until switched on
(full preconditions in `docs/DEPLOY_LINUX.md` §5c). Switch them on the
**Features** page (Platform → Configuration → Features); a saved switch wins over
`.env`, and a restart-class switch says so on the page.

| Env var | Default | What it does |
|---------|---------|--------------|
| `FEATURE_SECURITY_LANE` | `false` | Security evidence producer: hardening + advisory + threat findings onto the security topic |
| `SECURITY_SCAN_INTERVAL` | `15m` | Jittered scan cadence (Go duration) |
| `SECURITY_MAX_FINDINGS_PER_TENANT` | `5000` | Per-tenant per-run emission cap; the excess is counted, not dropped silently |
| `FEATURE_CONFIG_BACKUP` | `false` | Scheduled read-only SSH config capture + drift verdicts. Needs an active `SEAL_PROVIDER` and a capture credential |
| `CONFIG_BACKUP_INTERVAL` | `24h` | Capture cadence (Go duration) |
| `CONFIG_BACKUP_KEEP_VERSIONS` | `30` | Per-device retention depth in the sealed blob store |
| `CONFIG_BACKUP_SSH_USER` | *(empty)* | Least-privilege read-only capture account |
| `CONFIG_BACKUP_SSH_PASSWORD` | *(empty)* | Capture password — vault ciphertext or plaintext; never logged |
| `CONFIG_BACKUP_SSH_KEY` | *(empty)* | Capture private key — alternative to the password |
| `CONFIG_BACKUP_SSH_PORT` | `22` | Device SSH port override |
| `FEATURE_PACKET_CAPTURE` | `false` | On-demand bounded `tcpdump` over the read-only SSH gateway, sealed at rest. Same preconditions as config backup |
| `PCAP_KEEP` | `20` | Captures kept per device (duration/size ceilings are hard caps in code, not env knobs) |
| `PCAP_SSH_USER` / `PCAP_SSH_PASSWORD` / `PCAP_SSH_KEY` / `PCAP_SSH_PORT` | *(empty)* / `22` | Capture identity, same shape as the config-backup account |
| `FEATURE_PROTOCOL_DIAG_COLLECT` | `false` | Live BGP/OSPF/IS-IS collect on the Troubleshooting page: runs the curated read-only `show` bundle on a device over the same SSH gateway. Off = the collect endpoint returns 503; the catalog and paste-your-own-output analysis are unaffected |
| `PROTOCOL_DIAG_SSH_USER` / `PROTOCOL_DIAG_SSH_PASSWORD` / `PROTOCOL_DIAG_SSH_KEY` / `PROTOCOL_DIAG_SSH_PORT` | *(empty)* / `22` | Dedicated least-privilege read-only diagnostics identity. All three unset ⇒ falls back to the `CONFIG_BACKUP_SSH_*` capture account; a partially set identity (user with no secret) is a hard error, never a silent fallback |
| `PARSERCOV_MAX_LINES` | `200000` | Cap on one parser-coverage mining scan; a truncated run reports itself partial |
| `CORRELATION_REPLICA_URLS` | *(empty)* | Explicit correlation replica base URLs to sum per-process parser counters over; empty = the single-replica default |
| `CORR_SYSLOG_TOPIC` | `netops.syslog` | Point the syslog lane at a pre-screened topic instead of the raw one |
| `CORR_FIDELITY_WEIGHTING` | `0` | Weigh evidence by parser/source fidelity tier |
| `CORR_EVIDENCE_TOPICS` | *(unset)* | Evidence-class lanes to subscribe to. **Unset = all registered classes; empty = none.** Not written to `.env` for that reason |

The sealed blobs live in `data/config-backups` and `data/pcap` (mode `0700`,
owned by the api's runtime uid). `scripts/install.py` creates them;
`sudo bash scripts/fix-permissions.sh` repairs the ownership if it drifts.

## RCA document promotion (#113)

Every correlation case is fully analyzed and visible in Correlations —
but the formal RCA **document** (`?format=html|pdf`) renders only for a
PROMOTED real outage: auto (production + confirmed verdict + confirmed
user/app impact + duration ≥ 2 min) or an audited manual decision:

```
# promote (note optional, ≤500 chars) / inspect / revoke
curl -X POST   .../api/correlations/<id>/rca-promotion -d '{"note":"mgmt request"}'
curl           .../api/correlations/<id>/rca-promotion
curl -X DELETE .../api/correlations/<id>/rca-promotion
```

## Receiving device telemetry

syslog-ng (syslog), the trap receiver and goflow2 (flows) listen for
device-side traffic on these host ports:

| Protocol | Default host port | Env var |
|----------|------------------:|---------|
| Syslog UDP/TCP | 5514 **and** 514 | `SYSLOG_PORT` (the 514 mapping is always published) |
| NetFlow v5/v9  | 2055 | `NETFLOW_PORT` |
| IPFIX          | 4739 | `IPFIX_PORT` |
| sFlow          | 6343 | `SFLOW_PORT` |

Set the device's collector address to the Docker host's IP and these
ports. Cisco / Juniper / Arista / rsyslog config snippets are in
`docs/INGESTION.md`.

Once flowing, syslog and traps appear in the **Logs** tab and flows on the
**Flows** page. `scripts/deploy-qualify.sh` check Q11 proves each monitored
source is reporting on polling, syslog, traps and flows.

## Searching logs

The **Logs** tab searches device syslog and SNMP traps stored in OpenSearch,
scoped to your workspace. Routine management sessions (controller and monitoring
polls) are left out by default and counted; tick **Show routine management
sessions** to include them.

From the CLI (Bearer token required):

```
curl -G 'http://localhost:8000/api/logs/search' \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'query=severity:error AND host:router-01' \
  --data-urlencode 'signal=syslog' \
  --data-urlencode 'from=2026-11-19T10:00:00Z' \
  --data-urlencode 'to=2026-11-19T11:00:00Z' \
  --data-urlencode 'size=200' | jq
```

Parameters: `query` (search text), `signal` (`syslog`, `traps`, …), `from` /
`to` (RFC 3339), `size`, `offset`, `include_routine_mgmt=true|false`. `POST` with
the same fields as JSON also works. Related routes: `/api/logs/indices`,
`/api/logs/retention`, `/api/logs/severity-counts`, `/api/logs/export`. There is
no Loki — it was removed from the stack.

## Troubleshooting

| Symptom                              | First thing to check                                              |
|--------------------------------------|-------------------------------------------------------------------|
| `localhost:8000` won't load          | `docker compose ps` — is nginx Up?                                |
| Health endpoint returns 502          | `docker compose logs api`                                         |
| "Disconnected" banner in dashboard   | API container crash or env mismatch — check logs                  |
| Self-Monitoring 404s under /grafana/ | `GF_SERVER_SERVE_FROM_SUB_PATH=true` must be set (it is, by default); the self-monitoring add-on must be enabled |
| Self-metrics missing (ScrapeTargetDown) | VictoriaMetrics scrapes them itself — check the `vmscrape.yml` mount and `docker compose logs victoria` |
| Port 8000 already in use             | Edit `BASE_PORT` in `.env`, then `up -d`                          |
