# Pipeline Processors — per-tenant ingest shaping (item 121)

**Shipped 2026-07-30** as the third leg of tracker item 121 (the #53 remnants),
alongside maintenance windows and audit/change feed sources.

## What it is

A tenant admin can declare structured shaping rules — redact a pattern or a
field, drop a field, set a field — that apply to their tenant's telemetry
**before it is stored**. No shell access, no shared-YAML editing, no restart.

- UI: **Administration ▸ Data Collection ▸ Processors** (list + editor +
  server-side preview).
- API: `GET|POST /api/pipeline/processors`, `GET|PUT|DELETE
  /api/pipeline/processors/{id}`, `POST /api/pipeline/processors/preview`
  (`administration:admin`, tenant-scoped, cross-tenant id → 404).
- Storage: `pipeline_processors` (migration 0032, `tenant_iso` FORCE-RLS) or
  the tenant-filtered file store on the file backend.
- Feature flag: `FEATURE_PROCESSORS` (UI visibility via `/api/features`;
  compose defaults it on and carries the mounts).

## How it reaches the pipeline

```
rules (PG/file, per tenant)
  → api config writer (src/backend/telemetry_enrichment.go)
      GenerateRouterConfig(): processors.yaml — pure, deterministic
  → data/api/processors/router/processors.yaml   (atomic temp+rename, 0644)
  → vector-router:  --config conf/vector.yaml
                    --config processors/processors.yaml   --watch-config
```

The router's base config routes **every storage sink** through five generated
hook transforms (`applogs_rules`, `syslog_rules`, `snmptrap_rules`,
`cloudlogs_rules`, `flows_rules`), each consuming its lane's post-attribution
transform. A lane with no rules is an explicit no-op remap — the hooks must
always exist, so:

- `deployment/docker/vector-router/processors-default.yaml` is the checked-in
  zero-rule output of the generator (`tests/test_ingest_contract.py` pins the
  wiring);
- `install.py` seeds it into the data dir before the router first boots;
- `preflight-configs.sh` boots the router config together with the default
  file, with the real Vector binary.

Rule changes hot-apply: the writer regenerates on every mutation (plus a 60s
safety ticker, `PROCESSORS_INTERVAL`) and only rewrites the file when content
changed; `--watch-config` reloads, and Vector keeps the OLD topology if a
generated config ever fails validation — a bad generate cannot take the lane
down.

## Zero-trust posture

- **No free-form VRL, no free-form regex.** Patterns are built-ins (`email`,
  `ipv4`, `mac` — fixed constants) or literal text. User input is embedded
  ONLY as escaped VRL string literals (`processors/generate.go`; injection
  tests in `generate_test.go`).
- **Tenant guard generated around every action** from the server-stamped
  `TenantID` (§3a.2 — the token, never the body). One tenant's rule can never
  touch another tenant's events (`processors_isolation_test.go`, HTTP + RLS).
- **Protected fields**: `tenant_id`, `tenant_seg`, `tenant_attribution`,
  `log_index_base`, `ts`/`ts_source`/`timestamp`, `topic` cannot be targeted —
  shaping can never break tenancy routing or the time axis. The attribution
  metric stays wired to the PRE-hook transforms.
- **Preview is simulation, not execution**: `processors.Simulate` mirrors the
  generator's semantics in Go against a caller-supplied sample; nothing is
  stored or executed.

## Known v1 limitations (deliberate scope, do not re-file as bugs)

1. **Correlation lane is not shaped.** The Python correlation engine consumes
   the Kafka topics *upstream* of the router, so `corr_signals` attrs derived
   from syslog/flows/traps are not redacted by these rules. v2 options: apply
   the same generated hooks in the aggregator for lanes whose tenant is known
   there, or an attrs-side redaction in the correlation service.
2. **Metrics (VictoriaMetrics full-sample path) and probe/cloud
   correlation-only lanes** never pass a storage hook (they don't traverse the
   router), so they are out of scope by construction.
3. **No drop-EVENT rule type.** Dropping whole events interacts with the
   dead-letter contract (`test_every_dropping_transform_reroutes`); v1 keeps
   field-level actions only.

## Related

- Maintenance windows (same item): `src/backend/maintenance/`, migration 0031,
  suppression seam in `alert_episodes.go`, timeintel `maintenance` stamp.
- Audit → feed bridge (same item): `audit.go` (`auditSignalBridge`),
  `source='audit'=13` on the corr_signals enum, `events_feed.go` admissions +
  `class=changes` widening. **On-prem deploy events remain deferred**: the
  platform has no on-prem deploy/config-push producer to record; cloud change
  events (`cloud_change`, `cloud_audit`, `security_policy_change`) cover the
  cloud half via the now-admitted `cloud` source.
