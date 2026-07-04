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
docker compose down               # stop, keep volumes
docker compose down -v            # stop and wipe volumes
```

## Health checks

```
curl -fs http://localhost:8000/admin/health | jq
curl -fs http://localhost:8000/api/devices | jq
curl -fs http://localhost:8000/api/collectors | jq
curl -fs http://localhost:8000/admin/version
```

## Rotating secrets

From the project root:

```
python3 scripts/install.py --reset-env
docker compose -f deployment/docker/docker-compose.yml up -d
```

`--reset-env` overwrites `deployment/docker/.env` with a fresh set of
random values. The next `up` rolls every service that consumes them.

## Adding a device manually

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

Edit `SNMP_CIDR_RANGES` in `.env`. Multiple ranges are comma-separated.
Default is `10.0.0.0/8` — narrow it before scanning production.

## Configuring alert channels

All channels are off by default. Flip the `FEATURE_*` flag in `.env`,
fill in the credentials, and `docker compose up -d` to apply.

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

## Receiving device telemetry

Vector and goflow2 listen for device-side traffic on these host ports
(adjustable via `.env`):

| Protocol | Default host port | Env var |
|----------|------------------:|---------|
| Syslog UDP/TCP | 5514 | `SYSLOG_PORT` |
| NetFlow v5/v9  | 2055 | `NETFLOW_PORT` |
| IPFIX          | 4739 | `IPFIX_PORT` |
| sFlow          | 6343 | `SFLOW_PORT` |

Set the device's collector address to the Docker host's IP and these
ports. Cisco / Juniper / Arista / rsyslog config snippets are in
`docs/INGESTION.md`.

Once flowing, you'll see streams in the Logs tab tagged
`job=syslog` and `job=netflow`. From the CLI:

```
curl -G 'http://localhost:8000/api/logs/search' \
  --data-urlencode 'query={job="syslog"}' \
  --data-urlencode 'limit=20' | jq
```

## Searching logs

The Logs tab in the dashboard runs LogQL queries through Loki. Examples:

```logql
# Everything from the API container in the last 15 min
{compose_service="api"}

# Just errors
{compose_service="api"} |= "error"

# Parse the API's JSON logs and filter by structured level
{compose_service="api"} | json | level="error"

# Anything mentioning a specific device
{compose_project="netops"} |~ "device_id=\"router-01\""
```

From the CLI:

```
curl -G 'http://localhost:8000/api/logs/search' \
  --data-urlencode 'query={compose_service="api"} |= "error"' \
  --data-urlencode 'start=2026-05-27T10:00:00Z' \
  --data-urlencode 'end=2026-05-27T11:00:00Z' \
  --data-urlencode 'limit=200' | jq
```

Or hit Loki's labels endpoint directly to see what's indexed:

```
curl http://localhost:8000/api/logs/labels | jq
curl http://localhost:8000/loki/loki/api/v1/labels | jq
```

## Troubleshooting

| Symptom                              | First thing to check                                              |
|--------------------------------------|-------------------------------------------------------------------|
| `localhost:8000` won't load          | `docker compose ps` — is nginx Up?                                |
| Health endpoint returns 502          | `docker compose logs api`                                         |
| "Disconnected" banner in dashboard   | API container crash or env mismatch — check logs                  |
| Self-Monitoring 404s under /grafana/ | `GF_SERVER_SERVE_FROM_SUB_PATH=true` must be set (it is, by default); the self-monitoring add-on must be enabled |
| Self-metrics missing (ScrapeTargetDown) | VictoriaMetrics scrapes them itself — check the `vmscrape.yml` mount and `docker compose logs victoria` |
| Port 8000 already in use             | Edit `BASE_PORT` in `.env`, then `up -d`                          |
