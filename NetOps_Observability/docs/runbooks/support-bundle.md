# Support bundle — send diagnostics back without sending secrets

When a Correlix install misbehaves, one command collects everything support
needs into a single redacted archive:

```bash
./install-correlix.sh support-bundle             # customer bundle install
python3 scripts/support-bundle.sh                # source checkout
```

Output: `correlix-support-<host>-<UTCstamp>.tar.zst`, written `0600` into the
current directory (or `--out DIR`). It is typically a few MB with logs, well
under a MB with `--no-logs`.

```
Flags:
  --out DIR     where to write the archive (default: the current directory)
  --since 24h   how far back to read container logs (default 24h; 30m, 7d, or
                an RFC3339 timestamp all work)
  --no-logs     skip container logs entirely (smallest, fastest bundle)
```

## What is inside

| Path | What it is | How it is collected |
|------|------------|---------------------|
| `MANIFEST` | sha256 of every file, one status row per collector, redaction summary | written last |
| `compose/ps.txt` | every service and its state | `docker compose ps -a` |
| `compose/config.redacted.yml` | the RESOLVED compose configuration | `docker compose config`, then redacted |
| `compose/env-keys.txt` | the **key names** in `.env` | never a value — see below |
| `docker/stats.txt` | live CPU/memory per container | `docker stats --no-stream` |
| `host/df.txt`, `free.txt`, `uname.txt`, `nproc.txt` | host disk, memory, kernel, cores | plain host commands |
| `api/admin-version.json` | the running build (git sha) | `GET /admin/version` through nginx |
| `api/health.json`, `api/health-score.json` | app health + health score | `GET /api/health`, `/api/health/score` |
| `bus/kafka-consumer-lag.txt` | correlation consumer-group lag | `kafka-consumer-groups.sh --describe` (READ-ONLY) |
| `store/clickhouse-parts.tsv` | per-table rows, on-disk size, part count | one bounded `system.parts` query |
| `store/clickhouse-corr-rows.tsv` | row counts for `corr_signals`/`corr_current`/`corr_objects`/`corr_edges` | one bounded query, 20 s execution ceiling |
| `store/opensearch-cluster-health.json`, `opensearch-indices.txt` | cluster status + index sizes | `_cluster/health`, `_cat/indices` |
| `alerts/vmalert-alerts.json` | active alerts | vmalert `/api/v1/alerts`, falling back to the VictoriaMetrics `ALERTS` series |
| `watchdog/watchdog-log.txt` | last 200 lines of the stack watchdog log | `/var/log/correlix-watchdog.log` |
| `logs/<container>.log` | per-container logs | `docker logs --since <since> --tail 20000` |

Nothing in the bundle **changes** the stack: every collector is a read.
`kafka-consumer-groups.sh --describe` reports lag; it never commits, resets or
deletes an offset. The store queries carry an execution-time ceiling so a
degraded ClickHouse cannot turn the bundle into a long-running query.

## What is redacted

Two independent passes run over **every** collected file before it is packed:

1. **Key pattern** — any `KEY=value` or `KEY: value` whose key name contains
   `PASSWORD`, `PASSWD`, `SECRET`, `KEY`, `TOKEN` or `DSN` loses its value,
   plus URL userinfo credentials (`postgres://user:pw@host` →
   `postgres://user:***REDACTED***@host`).
2. **Literal value** — every secret-shaped value in the stack's own `.env` is
   replaced **wherever it appears**, in any file, including inside a log line
   or a JSON body where no key name would have given it away. This is the pass
   that makes the guarantee hold for values we would not otherwise recognise.

If the redaction pass itself fails for a file, that file's content is
**withheld** (replaced with a notice) and the failure is recorded — the bundle
never ships content that was not redacted.

`.env` itself is included as **key names only**. No value ships, redacted or
otherwise, so there is not even a length or shape to infer.

Over-redaction is possible and deliberate: a non-secret setting whose key
happens to contain `KEY` (say `SSH_KEY_PATH`) will also be masked. Tell support
the value directly if it matters.

**Still your call.** The bundle carries operational detail — hostnames, device
IPs, index names, log lines your services emit. Read the `MANIFEST` and skim
`logs/` before sending it outside your organisation. `--no-logs` produces a
bundle with the state and store summaries but no log content at all.

## Exit codes — a partial bundle is never silent

| Code | Meaning |
|------|---------|
| `0` | every collector produced output (or was legitimately skipped) |
| `1` | no bundle was produced: bad flags, unwritable `--out`, or `tar`/`zstd`/`sha256sum` missing |
| `2` | the bundle **was** written but at least one collector FAILED |

Exit `2` is the normal outcome on a broken install — which is exactly when you
want the bundle. Every failure is named in the `MANIFEST` `STATUS` block with
its reason, and the collector's own file carries a `### COLLECTOR FAILED`
marker. A bundle is never quietly short of a section.

Status values in the `MANIFEST`:

- `ok` — collected.
- `note` — collected, with something worth reading (e.g. `/api/health`
  answering `HTTP 401`, which is the expected posture without a token).
- `skip` — deliberately not collected (`--no-logs`, or no watchdog installed).
- `FAILED` — the collector could not run; the reason follows.

## Verifying a bundle you received

```bash
zstd -d correlix-support-<host>-<stamp>.tar.zst
tar xf correlix-support-<host>-<stamp>.tar
cd correlix-support-<host>-<stamp>
sed -n '/^SHA256/,$p' MANIFEST | tail -n +2 | sha256sum -c -   # integrity
sed -n '/^STATUS/,/^SHA256/p' MANIFEST                         # what is missing
```

## Options for a fuller view

| Variable | Effect |
|----------|--------|
| `SUPPORT_API_TOKEN` | bearer token for the authenticated `/api/*` routes — without it `api/health.json` and `api/health-score.json` capture the `401`, which still proves the ingress and the api process are answering. The token is never written into the bundle. |
| `APP_URL` | dashboard base URL (default `http://localhost:<BASE_PORT>`) |
| `APP_CACERT` | PEM used to **verify** a TLS ingress (never `-k`) |
| `COMPOSE_PROJECT` | compose project name if it is not `netops` |
| `WATCHDOG_LOG_FILE` | watchdog log path (default `/var/log/correlix-watchdog.log`) |

## How to send it

Attach the `.tar.zst` to your support ticket, or hand it to your Correlix
contact through whatever channel your organisation already approves for
diagnostic data. Do not paste it into a public issue tracker — it is
secret-free, not detail-free.

## See also

- `docs/DEPLOY_LINUX.md` § "Measuring time-to-first-value" — the install-timing
  instrument (`data/install-timing.json`), the other half of the deployment
  friction picture.
- `scripts/stack-watchdog.sh` — the continuous health watch whose log the
  bundle carries the tail of.
