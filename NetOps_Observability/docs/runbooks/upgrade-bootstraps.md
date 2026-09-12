# Runbook — bootstraps an UPGRADED stack must re-run

**Symptom class:** the upgrade succeeded, every container is `healthy`, and one
lane produces nothing. No error is visible anywhere an operator normally looks.

**Read this whenever a deploy ADDS A LANE** (a new Kafka topic + vector-router
sink + index template), or when a lane that worked before an upgrade is silent
after it. For a lane that is silent with no recent deploy, start at
[`engine-not-consuming.md`](engine-not-consuming.md) instead.

---

## 1. Why this file exists (2026-09-03)

The P3-L1 security-findings lane shipped complete — Kafka topic, ACL entry,
router sink, index template, ISM retention pattern — and wrote **nothing**. The
one file it did *not* update was `deployment/docker/opensearch/security/roles.yml`:
`netops-secfindings-*` was missing from the `netops_writer` role, so every bulk
write from `svc_router` came back

```
no permissions for [indices:admin/create] and User [name=svc_router, ...]
```

Vector classifies a 403 as **non-retriable** and **drops the batch**. Result: no
index, no consumer lag, no rejected-docs counter, no red healthcheck. The CTEM
funnel was simply empty, which is indistinguishable from "no findings yet".

The same deploy exposed a second blind spot: `scripts/bootstrap-opensearch.sh`
curled `http://localhost:9200`, but a TLS install serves **https on 9200 with
the security plugin on**, so all nine index templates reported "was NOT
applied" — the stack was running with zero declared mappings and every lane
100% dynamically mapped.

**The lesson:** a lane is defined across FOUR files applied by FOUR different
mechanisms, and `docker compose up` exiting 0 proves none of them.

---

## 2. The full bootstrap list

Run these **in this order** after any deploy that adds or changes a lane. All
are idempotent; all are safe to re-run on a healthy stack.

| # | Bootstrap | What it applies | How to run | Skipped when |
|---|---|---|---|---|
| 1 | **Kafka ACL matrix** | `deployment/docker/kafka/apply-acls.sh` — per-principal topic/group ACLs (SEC-007) | piped into the running broker: `docker compose exec -T kafka bash -s < deployment/docker/kafka/apply-acls.sh` | plaintext broker (no authorizer) or an external broker — then it is the broker owner's job |
| 2 | **Kafka topics** | the canonical topic list, partitions, retention | one-shot: `docker compose --profile embedded-bus up kafka-init` | external broker |
| 3 | **OpenSearch security config** | `opensearch/security/{internal_users,roles,roles_mapping}.yml` → users, **roles**, mappings | one-shot: `docker compose --profile security up opensearch-security-init` | non-TLS / pre-SEC-008 installs |
| 4 | **Index templates** | `opensearch/index-templates.json` → the per-lane field contract | `bash scripts/bootstrap-opensearch.sh` | never — always run it |
| 5 | **ISM + snapshots** | retention policy patterns, replica posture, snapshot repo + SM policy, the `security-auditlog` template | one-shot: `docker compose up opensearch-init` (runs `opensearch/apply-ism.sh`) | never — always run it |

`scripts/deploy-qualify.sh` runs 1, 2, 5 (as B1/B2/B3) and then **audits** 3+4
read-only as **B4**. `scripts/install.py` and `scripts/update.sh` run 4 by
calling `scripts/bootstrap-opensearch.sh` — which is the **single owner** of
index-template application. Do not re-implement that PUT loop anywhere else;
the copies drifted once and that drift is defect 2 above.

### Ownership split, so nothing is applied twice

* `scripts/bootstrap-opensearch.sh` → **everything in `index-templates.json`**
  (the `netops-*` log-lane field contract).
* `deployment/docker/opensearch/apply-ism.sh` (the `opensearch-init` one-shot) →
  ISM retention policies, the snapshot repository + `netops-daily` SM policy,
  the replica posture, and the **settings-only `security-auditlog` template**,
  which is deliberately kept OUT of `index-templates.json`.

---

## 3. Checklist for a deploy that adds a lane

Five files, and a lane is dead if any one is missed:

1. `deployment/docker/docker-compose.yml` — the topic in `kafka-init`.
2. `deployment/docker/kafka/apply-acls.sh` — producer/consumer ACLs for the topic.
3. `deployment/docker/vector-router/vector.yaml` — source, route and sink.
4. `deployment/docker/opensearch/index-templates.json` — the mapping template.
5. **`deployment/docker/opensearch/security/roles.yml` — the index pattern in
   `netops_writer` (write) and, if the api reads the lane, in `netops_api`.**
   *This is the one that gets forgotten.* `tests/test_upgrade_bootstraps.py`
   now fails the build if it is.

Plus `deployment/docker/opensearch/apply-ism.sh` if the lane needs retention
(it always does — a lane matching no `ism_template` grows forever, F-53).

---

## 4. Verifying, without changing anything

```bash
# Read-only: is every router sink lane writable by svc_router, and does every
# declared template exist in the LIVE cluster?  Writes nothing.
bash scripts/bootstrap-opensearch.sh --verify
```

Expected on a healthy stack — one `role: COVERED` line per lane and one
`template: PRESENT` line per template, ending in

```
VERIFY OK — every router sink lane is writable and every template is installed.
```

`role: UNCOVERED <pattern>` means defect 1: add the pattern to `roles.yml` and
re-run bootstrap 3 (`opensearch-security-init`). `template: MISSING <name>`
means bootstrap 4 never landed — run `bash scripts/bootstrap-opensearch.sh`.

The same audit runs inside the deploy gate:

```bash
bash scripts/deploy-qualify.sh          # B4 "router lanes writable"
```

### Confirming a 403 is what you are looking at

```bash
# The router's own complaint (the batch it dropped):
docker compose logs --since 30m vector-router | grep -i 'security_exception\|no permissions'

# The lane's indices — absent, not empty, when the role is missing:
bash scripts/bootstrap-opensearch.sh --verify        # then, if you need detail:
docker compose exec -T opensearch curl -s \
  --cacert /usr/share/opensearch/config/tls/ca.pem \
  -u "svc_bootstrap:$OS_BOOTSTRAP_PASSWORD" \
  'https://opensearch:9200/_cat/indices/netops-*?h=index,docs.count'
```

Never add `-k`/`--insecure` to any of these. The OpenSearch SAN set is
`DNS:opensearch` plus a SPIFFE URI and nothing else, so the host name must be
`opensearch` — `localhost` fails hostname verification, and silencing that with
`-k` would turn a real MITM or a misissued certificate into a silent pass.

---

## 5. Prevention (already in the tree)

| Guard | Catches |
|---|---|
| `tests/test_upgrade_bootstraps.py` | a router sink lane with no `netops_writer` write/create permission; an api-read lane outside `netops_api`; a lane with no index template; a second owner of the template PUT; an unbounded/missing B4 |
| `scripts/bootstrap-opensearch.sh --verify` | the same two properties against the **running** cluster |
| `scripts/deploy-qualify.sh` B4 | both, on every deploy, read-only and bounded |
| `tests/test_security_lane.py` | the findings lane's wiring, identity, mapping and Kafka ACL |
