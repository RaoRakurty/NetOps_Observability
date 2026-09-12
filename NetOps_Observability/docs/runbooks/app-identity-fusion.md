# Runbook — Application Identity Fusion lane (#81 P4–P7)

The fusion lane turns upstream application classification (firewall App-ID, NBAR2/
IPFIX, IP/CIDR + operator catalogs, cloud tags) into **explainable evidence** that
the correlation engine uses to NAME the applications an incident affects. Identity is
**enrichment, never a fault** — it attaches to objects real faults already formed, can
never seed an object, and can never confirm a verdict on its own.

```
vendor logs ─► OpenSearch ─► fusion_worker (Go) ─► CH app_observations/app_identities
                                   │  (best-effort)
                                   ▼
                    netops.app.identities.v1 (Kafka, via Vector bus bridge)
                                   ▼
              correlation handle_app_identity ─► corr_signals(source=app_identity)
                                   ▼
              engine run_window ─► app_impact projection on corr_objects
                                   ▼
              GET /api/correlations/{id}/rca-path-view  ·  RCA "Application impact" UI
```

## Enable (opt-in, default-off)

- **Fusion worker** (vendor logs → observations → identities → CH + topic):
  `FUSION_WORKER_ENABLED=true` on the `api` service. Tunables: `FUSION_INTERVAL_S`
  (default 120), `BUS_BRIDGE_URL` (default `http://vector-aggregator:8692`).
- The **consumer** (`netops.app.identities.v1` → engine) is always on in the
  correlation service; it is harmless when the topic is empty.
- Status / metrics: `GET /api/appid/fusion/status` (auth `infrastructure:read`) —
  cycles, observations, identities, by_vendor, by_band, emitted, emit_errors.
- Consumer health: correlation `/healthz` → `ingest.app_identity_received /
  _signals / _dropped`.

## Validate end-to-end (no vendor device needed)

Produce a cloud app object + a matching identity (they share the app token):

```bash
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker exec -i netops-kafka-1 /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 --topic netops.cloud <<EOF
{"tenant_id":"acme","kind":"database_metric","app":"demo","resource_id":"demo-db","account":"123","region":"us-east-1","severity":"high","metric_name":"cpu","value":97,"baseline":30,"ts":"$TS"}
{"tenant_id":"acme","kind":"cloud_health","app":"demo","account":"123","region":"us-east-1","severity":"high","ts":"$TS"}
EOF
docker exec -i netops-kafka-1 /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 --topic netops.app.identities.v1 <<EOF
{"tenant_id":"acme","app":"demo","band":"authoritative","state":"fused","evidence_score":92,"sources":["ngfw_app_id","cloud_tag"],"fusion_version":"appfuse-1","ts":"$TS"}
EOF
# wait ~30s for the engine cycle, then:
docker exec netops-clickhouse-1 clickhouse-client -q \
  "SELECT app_impact FROM netops.corr_objects WHERE app_impact LIKE '%demo%' ORDER BY version DESC LIMIT 1 SETTINGS tenant_scope='__all__'"
```

API check (admin token via `POST /api/auth/login` → field `token`):
`GET /api/correlations/{id}/rca-path-view` → `app_impact.apps[]`.

Cleanup: `ALTER TABLE netops.corr_objects DELETE WHERE app_impact LIKE '%demo%'
SETTINGS tenant_scope='__all__'` (and corr_signals / corr_evidence likewise).

## Guarantees (tested)

- **No-seed:** identity is excluded from `build_nodes` → an identity-only window
  forms NO object. (`test_app_impact.py`)
- **No churn:** `app_impact` is a projection (not in `content_hash`) → objects with
  no matched identity are byte-identical to pre-P5; replay is deterministic.
- **Tenancy (§3a):** untenanted identity events are DROPPED + counted
  (default-closed); a mixed-tenant window is rejected, never partitioned;
  `corr_signals` RLS scopes reads. (`test_app_identity_intake.py`, `test_app_impact.py`)
- **Honest unknown:** an impactable node with no admissible identity records
  `evidence_missing` — never a guessed app name.

## Troubleshoot

| Symptom | Cause / fix |
|---|---|
| `app_identity` rows rejected, CH 691 "Unknown element 'app_identity'/'app'" | enum not widened — restart `api` (corr_schema self-heal `MODIFY COLUMN`). Source enum needs `app_identity`=10; `corr_evidence.subject_kind` needs `app`=3. |
| api crash-loops on `migrate: must be owner of table <t>` | a table was created out-of-band by the `netops` superuser; realign: `ALTER TABLE <t> OWNER TO netops_app;` then restart. Fresh installs are unaffected (one consistent migration role). |
| identity consumed but no app named | the identity shares no `entity_token` with the object's nodes — by design (unknown stays first-class). Ensure the identity carries the dst/flow/app token the fault node also has. |
| emit_errors climbing on `/api/appid/fusion/status` | bus bridge unreachable — check `BUS_BRIDGE_URL` (vector-aggregator :8692); emit is best-effort (CH persist still holds), so RCA naming via the topic pauses but data is not lost. |
| `vector validate` passes but syslog pipeline drops | not this lane — see the E651 gotcha in CLAUDE.md / app-identity-engine memory. |
