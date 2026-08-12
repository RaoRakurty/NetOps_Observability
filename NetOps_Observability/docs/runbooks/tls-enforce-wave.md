# TLS enforce wave — SEC-007.2 flip · SEC-006.3 drop 9092 · plaintext-listener drops · lane-token narrowing

**Gate: the Kafka ACL soak must be QUIET over a full business cycle (earliest
2026-08-08 evening).** Go/no-go = zero unexplained authorizer denials since the
2026-08-06 13:17 broker recreate, all lanes consuming, no Kafka alerts.
Everything in this runbook is policy flips and listener removals — every
mechanism (identities, admin plane, controller TLS, healthchecks) shipped
before it. Run top to bottom; each step has a verification gate — do not
proceed past a red gate.

Authority: tracker #151 + `docs/security/CORRELIX_SECURITY_IMPLEMENTATION_BACKLOG.md`.
The lab override (`deployment/docker/docker-compose.override.yml`) is where lab
flips happen; the shipped variant is `deployment/docker/compose.tls.yml`
(keep both in sync where they overlap).

## 0. Pre-flight (before touching anything)

- [ ] Soak review: `bash scripts/soak-go-no-go.sh` → GO (exit 0). NOTE its
      window is the broker's RETAINED log (json-file 50m×3) — if the broker
      restarted recently, corroborate the earlier window from any denial
      alerts/notes before treating GO as full-cycle.
- [ ] `bash scripts/preflight-configs.sh` green.
- [ ] Boot posture fatal=0; tlsprobe 9/9 (`netops_tls_peer_probe_ok`).
- [ ] All consumer groups healthy (per-lane consume-rate > 0 where lanes have
      traffic; `kafka_consumergroup_lag` flat).
- [ ] `git status` clean; note the current commit for rollback reference.
- [ ] RCA canary green (`scripts/rca-canary.sh` state).

## 1. SEC-007.2 — authorizer default-deny

Lab override, kafka environment:
```
KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND: "false"
```
`docker compose up -d kafka` (recreate — config change; plain `restart` will
NOT apply env).

**Remember:** `allow.everyone.if.no.acl.found` was only ever reachable for
resources with NO ACLs; the 49-entry matrix already enforced on ACL'd topics
(lesson i). The flip closes the *unlisted*-resource gap — consumer-group and
cluster resources are the likely friction points, not topics.

Verify (gate):
- [ ] Broker healthy; Raft leader elected (controller log).
- [ ] EVERY lane consuming: correlation (aiokafka log "Successfully synced"),
      vector-router per-lane consume-rate > 0, goflow2 producing (flows lane),
      cloud-ingest producing.
- [ ] kafka-exporter still scraping (its group Describe needs an ACL — watch
      for denials naming `kafka-exporter`).
- [ ] Authorizer log: any NEW denial → add the missing grant to
      `scripts/apply-acls.sh` (tracked), re-apply, re-verify. Do NOT widen
      with wildcards.
- [ ] Admin plane: `kafka-topics.sh --bootstrap-server kafka:9094
      --command-config /tmp/kafka-tls/admin.properties --list` works
      (super-user bypasses ACLs — if THIS fails the problem is TLS, not ACLs).
- [ ] ANONYMOUS on 9095 can still produce netops.flows (goflow2's declared
      lane): flows offsets advancing.

## 2. SEC-006.3 — drop the 9092 plaintext listener

Nothing may still ride 9092. Sweep first:
```
docker logs since the flip for port-9092 connection attempts; then
grep -rn "9092" deployment/docker/docker-compose.override.yml  # expect: only the listener defs
```
Lab override, kafka environment — remove PLAINTEXT from all three:
```
KAFKA_LISTENERS: "CONTROLLER://0.0.0.0:9093,MTLS://0.0.0.0:9094,FLOWS://0.0.0.0:9095"
KAFKA_ADVERTISED_LISTENERS: "MTLS://kafka:9094,FLOWS://kafka:9095"
KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "CONTROLLER:SSL,MTLS:SSL,FLOWS:SSL"
KAFKA_INTER_BROKER_LISTENER_NAME: "MTLS"   # was PLAINTEXT — must move
```
(Verified 2026-08-06 on the running broker: `inter.broker.listener.name =
null` → it defaults to the PLAINTEXT security protocol, i.e. 9092. The
`KAFKA_INTER_BROKER_LISTENER_NAME: "MTLS"` line above is therefore
MANDATORY in the same edit that removes 9092, or the broker will not start.)

`docker compose up -d kafka`, then verify (gate):
- [ ] Broker healthy on the 9094 healthcheck (already migrated).
- [ ] Full lane sweep as in step 1.
- [ ] `nc -z kafka 9092` from any container FAILS (listener actually gone).
- [ ] kafka-init one-shot still works: `docker compose run --rm kafka-init`.

## 3. Store plaintext-listener drops (one store at a time, verify between)

| Store | Change | Who still reads plaintext (verify none before drop) |
|---|---|---|
| ClickHouse 8123 | remove port/listener from override tls.xml / compose | vector-router CH sink and api are on https already; grep override for 8123 |
| victoria 8428 direct | stop publishing 8428; ALL reads via vmauth | vmalert + "vmauth-backhaul" read it — both carry vmauth URLs in the override already; confirm no residual direct URL |
| valkey 6379 | drop plaintext port; TLS 6380 only | **netbox still rides 6379** — move netbox to 6380+TLS first or leave 6379 bound to localhost-only as an explicit declared exception |
| api host 8080 | remove the host-published 8080 (nginx fronts everything) | stack-watchdog probes :8000; nothing external needs 8080 |
| nginx 8000 | plaintext ingress off; 443/8443 only | browser bookmarks + stack-watchdog probe URL must move to https |

Each drop: edit override → `docker compose up -d <svc>` → verify the
service's clients still function (lane/data movement, not just "it's up") →
next store. Update `scripts/stack-watchdog.env` probe URL when nginx 8000
goes.

## 4. Lane-token narrowing

Drop the shared `INGEST_TOKEN` fallback: collectors/vector lanes accept ONLY
their per-lane token (`INGEST_TOKEN_TRAPS/PROBES/METRICS/BUS`). This is a
backend env/config change (see SEC-013 notes in the memory/backlog). Verify:
every lane still ingests + a shared-token request now 401s (the
metrics-token-on-bus test class).

## 5. Post-wave

- [ ] `python3 scripts/audit_metric_contract.py` + full Go/frontend suites.
- [ ] Update `docs/security/transport-inventory.yaml`: the dropped listeners'
      edges move current → their security_profile state; preflight green.
- [ ] Update INVARIANTS §8 tiers (SEC-001.3) for the removed plaintext hops.
- [ ] Boot validator: expect fatal=0 AND the plaintext-related warns to clear.
- [ ] Run `scripts/rotate-tls-services.sh --check` (wire==disk 9/9).
- [ ] Kafka soak posture stays: authorizer at INFO, denials-only log review
      for 24h post-flip.
- [ ] Delete the shipped rows from `docs/TRACKER.md` #151 step-1 scope; update
      the tls-completion-programme memory.

## Rollback

Every step is an env/listener edit in the override: revert the line,
`docker compose up -d <svc>`. Kafka data and ACLs are unaffected by listener
changes. If the 007.2 flip strands a client, the immediate rollback is
`KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND: "true"` + recreate — then add the
missing grant properly and re-flip.
