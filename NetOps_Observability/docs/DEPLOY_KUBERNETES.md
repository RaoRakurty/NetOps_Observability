# Deploying Correlix on Kubernetes

The Helm chart lives at `deployment/helm/correlix`. It packages the same stack
`deployment/docker/docker-compose.yml` runs: device discovery → multi-protocol
telemetry ingestion → Kafka → storage (OpenSearch / VictoriaMetrics /
ClickHouse) → correlation → API → dashboard, behind one ingress.

> **What is proven, and what is not.** The chart is **rendered and validated**:
> `helm lint` is clean, `helm template` renders the default and the lab variant,
> every object validates against the Kubernetes 1.30 schemas, and
> `tests/test_helm_chart.py` asserts the properties a schema cannot see. It has
> **never been installed to a cluster** — no cluster was available. A manifest
> that validates can still fail to schedule, fail a volume bind, or crash-loop.
> `docs/audit/INVARIANTS.md` §11 records that distinction. Treat the first real
> install as a bring-up, not a rollout, and run the verification steps below.

---

## Quick start

```bash
# 1. A namespace with the Pod Security labels the chart is written for.
kubectl create namespace correlix
kubectl label namespace correlix \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# 2. The Secret. THE CHART NEVER CREATES ONE — see "Secrets" below.
kubectl -n correlix create secret generic correlix-secrets --from-env-file=k8s-secrets.env

# 3. Install.
helm install correlix deployment/helm/correlix -n correlix \
  --set ingress.host=correlix.example.com \
  --set global.storageClass=<your-class>
```

`helm install` exiting 0 is not evidence. Go to **Verifying an install**.

---

## Prerequisites

| Requirement | Why |
|---|---|
| Kubernetes ≥ 1.27 | `Chart.yaml` `kubeVersion`. Validated against 1.30 schemas. |
| A CNI that enforces NetworkPolicy (Calico, Cilium, Antrea) | The chart's default-deny posture is inert under flannel: the objects are accepted and enforce nothing. **Verify before relying on them.** |
| A default (or named) StorageClass, `ReadWriteOnce` | Every store keeps a PVC. |
| Optionally a `ReadWriteMany` class | Only for `sharedData.enabled=true`; see "Shared data volume". |
| Swap off on nodes running OpenSearch | The chart sets `bootstrap.memory_lock=false` because mlock needs `CAP_IPC_LOCK`, which `restricted` forbids. Swap-off is the substitute, and it is the standard OpenSearch prerequisite. |
| `vm.max_map_count >= 262144` on those nodes | OpenSearch refuses to start below it. Set it on the node (sysctl / node image), not in the pod — a sysctl init container needs privilege. |
| An Ingress controller | Or `ingress.enabled=false` and `kubectl port-forward svc/nginx 8000:8080`. |
| Container images | Four of them are yours to build and publish — see "Images". |

---

## Images

Every third-party image is **pinned by the same sha256 digest the compose stack
pins**, and `tests/test_helm_chart.py::test_every_third_party_image_is_digest_pinned`
fails if the chart and compose ever disagree.

Five images are Correlix's own and have no digest until your pipeline publishes
them:

| values key | Built from | Published by |
|---|---|---|
| `api.image` | `deployment/docker/Dockerfile.backend` | `.github/workflows/publish-images.yml` |
| `correlation.image` | `Dockerfile.correlation` | same |
| `frontend.image` | `Dockerfile.frontend` | same |
| `gateway.image` | `Dockerfile.nginx` | same |
| `vectorRouter.image` | `deployment/docker/vector-router/Dockerfile` | **not published today** — build and push it yourself |

The frontend image COPYs a prebuilt SPA bundle (`src/frontend/dist`) and the
docs portal build, neither of which is in git. Build the web assets **before**
building the image, in the main tree.

**In production set `images.requireDigest: true`** and supply each `digest`. The
flag is a real gate, not a hint: with it on, an image without an `@sha256:`
reference fails the render and names the offending service. `prober` reuses the
api image.

Air-gapped or private registry: `global.imageRegistry` prefixes every reference.

---

## Secrets

**The chart never generates a credential.** A chart that mints secrets writes
them into the release manifest, where `helm get manifest` and every backup of
the release Secret hand them out. `secrets.existingSecret` names a Secret you
create, or that an ExternalSecret materialises from your vault.

The key names are exactly the variable names `scripts/install.py` generates, so
an existing compose install's `.env` is a direct source. **Never commit that
file and never `kubectl create secret --from-literal` a value you want to keep
out of your shell history.**

| Key | Needed by | Notes |
|---|---|---|
| `DB_USER`, `DB_PASSWORD` | postgres, api | |
| `DATABASE_URL` | api, when `store.backend=postgres` | DSN for the **non-superuser, NOBYPASSRLS** `netops_app` role. A superuser (or any `BYPASSRLS` role) ignores RLS even under `FORCE ROW LEVEL SECURITY`, and the api refuses to start as one. |
| `REDIS_PASSWORD` | redis, api, prober | |
| `CLICKHOUSE_PASSWORD` | clickhouse, api, correlation, vector-router | |
| `KAFKA_CLUSTER_ID` | kafka | Generate **once** per install (22-char base64url UUID). The data volume is formatted with it; changing it makes the broker refuse its own volume. |
| `JWT_SECRET`, `ENCRYPTION_KEY` | api | The api refuses to boot without them. |
| `ADMIN_INITIAL_PASSWORD` | api | |
| `INGEST_TOKEN` | api, vector-router | |
| `INGEST_TOKEN_TRAPS`, `_PROBES`, `_METRICS`, `_BUS` | api, vector-aggregator, prober | Per-lane. The shared `INGEST_TOKEN` opens **no** lane. |
| `VMALERT_WEBHOOK_TOKEN` | vmalert, api | The alert-delivery shared secret. vmalert reads it from a **file**, never a flag — a token on a command line is in every process listing. |
| `CORR_DEBUG_TOKEN` | api, correlation | Unset ⇒ the debug routes answer 503 and a trace honestly reports the bus stage as "not observable". |
| `GRAFANA_ADMIN_PASSWORD` | grafana | Only when `grafana.enabled`. |
| `OS_API_PASSWORD`, `OS_ROUTER_PASSWORD`, `OS_CORRELATION_PASSWORD`, `OS_BOOTSTRAP_PASSWORD`, `OS_DASHBOARDS_PASSWORD`, `OS_AGGREGATOR_PASSWORD` | opensearch-security-init | Only when `bootstrap.opensearchSecurityInit.enabled`. |
| `VMAUTH_*_PASSWORD` (api, gnmic, vector, vmalert, grafana, prober) | vmauth | Only when `vmauth.enabled`. |

Integration credentials (Slack, PagerDuty, SMTP, ServiceNow, Jira, Teams,
`COPILOT_API_KEY`) go in a **second** Secret named by
`secrets.existingIntegrationSecret`, mounted `envFrom` on the api only, so the
platform credentials and the integration credentials can have different owners
and rotations.

### External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata: {name: correlix-secrets, namespace: correlix}
spec:
  refreshInterval: 1h
  secretStoreRef: {name: <your-store>, kind: ClusterSecretStore}
  target: {name: correlix-secrets}     # the name secrets.existingSecret expects
  dataFrom:
    - extract: {key: correlix/platform}
```

---

## Storage

Every store keeps a `ReadWriteOnce` PVC created from a StatefulSet
`volumeClaimTemplate`; `<service>.persistence.size` and `.storageClass` set
each, and `global.storageClass` is the fallback. Defaults are starting points,
not sizing: **`docs/RESOURCE_SIZING.md` owns the real model.** Run

```bash
python3 scripts/install.py --plan-resources <profile>   # or --sizing-file
```

against your intended host shape and transfer the result into values. The
chart's built-in numbers are the compose lab limits.

OpenSearch snapshots get their **own** claim, deliberately: a snapshot living
inside the thing it backs up is not a backup. Replicate
`opensearch-snapshots` off-cluster to make it one.

**PVCs are not deleted by `helm uninstall`.** That is correct — it is your data —
and it means a reinstall adopts the old volumes. Delete them explicitly when you
mean to start clean.

### Shared data volume

The compose stack bind-mounts `data/api/enrichment` and
`data/api/processors/router` from the api into vector-aggregator, vector-router
and correlation. On Kubernetes that is one `ReadWriteMany` volume: the api
writes it, the three consumers mount it read-only.

With no RWX class, set `sharedData.enabled=false`. The consequences, stated
rather than left to be discovered:

* tenant enrichment falls back to the default tenant (`device_tenant.csv` is not
  visible to the aggregator or the engine);
* the router uses the default processor set baked into the chart — operator-
  authored, hot-reloaded processors are unavailable.

---

## The gateway, and why it is still there

The tracker item this chart closes said "ingress replacing nginx". It replaces
the **host port publish**, not the gateway pod, and that is deliberate.

`deployment/docker/nginx/default.conf` is not a path router. It runs
`auth_request` subrequests against the api in front of Grafana, OpenSearch
Dashboards, NetBox and Keycloak. An Ingress cannot express that. Splitting those
paths across Ingress rules would publish four authenticated surfaces
**unauthenticated**. So the Ingress terminates outside traffic and forwards one
path to the `nginx` Service, which keeps the compose routing table and its auth
gates intact.

The chart's copy of that config differs from the compose one by **exactly one
line** — `resolver`, because Docker's embedded DNS at `127.0.0.11` does not
exist in a pod — and
`test_gateway_config_differs_from_compose_only_in_the_resolver` fails if
anything else moves.

---

## Service names are literal

Every Service is named after its compose service: `api`, `kafka`, `victoria`,
`opensearch`, `clickhouse`, `postgres`, `redis`, `correlation`, `frontend`,
`nginx`, `vector-aggregator`, `vector-router`, `syslog-ng`, `goflow2`. No
release-name prefix.

That is what lets `vector.yaml`, `vmscrape.yml`, `rules.yaml`, `gnmic.yaml` and
the api's environment work **unmodified**: in-namespace DNS resolves the short
name. Renaming one breaks the pipeline silently — the request simply goes
nowhere.

**Consequence: one Correlix release per namespace.** Two releases in one
namespace would collide on every Service name.

---

## Configuration files

Helm cannot read a file outside the chart root, so the chart carries checked-in
mirrors under `deployment/helm/correlix/files/` and renders its ConfigMaps from
them. This is the same mirror-plus-drift-gate shape the repository already uses
for the AI docs corpus (`scripts/sync-docs-corpus.sh` +
`ai/docs_corpus_drift_test.go`).

**When you change `src/config/rules.yaml`, a Vector config, the ClickHouse init
SQL or any other mirrored file, re-stage:**

```bash
bash deployment/helm/stage-configs.sh          # write
bash deployment/helm/stage-configs.sh --check  # what CI runs
```

`tests/test_helm_chart.py::test_staged_configs_match_canonical_sources` fails
until you do. Never edit `files/` by hand.

**Adding a file to a directory the compose stack mounts whole** — `syslog-ng/`,
`gnmic/`, `vector/`, `vector-router/`, `opensearch/`, `src/config/` — also
requires staging it, and `test_whole_directory_mounts_are_staged_whole` fails
until you either stage it or record why it does not belong in the chart. That
guard exists because the first pass of this chart cherry-picked
`syslog-ng/syslog-ng.conf` and missed the `core.conf` it `@include`s: helm
rendered, kubeconform passed, every probe and limit was in place, and the daemon
would have refused to start.

---

## Network policy

`networkPolicy.enabled=true` by default: default-deny both directions, then
named allows. The authoritative allow lives at the **receiver** — one precise
ingress policy per server component naming exactly the clients that legitimately
reach it, and on which port. Egress inside the namespace is granted coarsely,
because a NetworkPolicy set is a union of allows and a broad egress rule cannot
widen what a narrow ingress rule permits.

Two lists you must fill in:

* **`networkPolicy.deviceCIDRs`** — the ranges your estate sends telemetry from
  (syslog 514, NetFlow 2055, IPFIX 4739, sFlow 6343, SNMP traps, BMP). Empty
  means nothing off-cluster can send. That is the safe default **and** a silent
  black hole if you expected device telemetry.
* **`networkPolicy.apiEgressCIDRs`** — where the api may reach off-cluster (LLM
  provider, ITSM, ntfy, RIPEstat/RDAP, device SSH). Empty means nowhere. This
  and the api's own SSRF gate are two independent layers, on purpose.

The gateway's ingress policy accepts from **any** namespace on 8080, because the
chart does not know where your Ingress controller runs. Narrow it with a
`namespaceSelector` once you do.

---

## Pod Security

Every workload is written for the `restricted` standard: `runAsNonRoot`, a
`RuntimeDefault` seccomp profile, `allowPrivilegeEscalation: false`,
`capabilities.drop: [ALL]`. `syslog-ng` adds `NET_BIND_SERVICE` — the one
capability `restricted` permits — because it binds 514.

Two opt-in add-ons **cannot** meet it, and say so in their own annotations:

| Workload | Needs | Why |
|---|---|---|
| `prober` | `baseline` | `CAP_NET_RAW` for raw ICMP construction and per-packet IP TTL. Hop-by-hop path measurement is not possible without it. |
| `hostExporters` (cadvisor, node-exporter) | `privileged` | hostPath into the container runtime and host namespaces. |

Both default to **off**. Enable them in their own namespace with the matching
label; most clusters already run node metrics of their own, which is the better
answer for the second row.

No pod mounts a Kubernetes API token (`automountServiceAccountToken: false`
everywhere) and the chart creates no Role or RoleBinding — nothing in this stack
talks to the Kubernetes API, so nothing holds a credential for it.

---

## App-state backend

`store.backend` defaults to **`postgres`** (tracker 245: PostgreSQL is the
default for new installations). `file` is explicit compatibility mode, `memory`
is dev/test only and loses everything on restart. Full detail, including which
registries exist on which backend and what a `501` from the Applications
registry means: `docs/DEPLOY_POSTGRES_APPSTATE.md`.

The chart does **not** provision the `netops_app` role. Create it as a
non-superuser `NOBYPASSRLS` role and put its DSN in the `DATABASE_URL` Secret
key. (`scripts/install.py` does this for compose installs; there is no
Kubernetes equivalent yet.)

---

## Bootstraps

Three jobs run as `post-install,post-upgrade` Helm hooks, in weight order. All
are idempotent.

| Weight | Job | What it does | Default |
|---|---|---|---|
| 0 | `kafka-init` | Pre-creates the 21 canonical `netops.*` topics at `env.BUS_PARTITIONS`. Broker auto-create is **off**, so a producer to a missing topic fails loud instead of minting a lane nobody retains or consumes. Increase-only. | on |
| 5 | `kafka-acls` | The SEC-007 per-identity ACL matrix. **Only meaningful on an authorizing broker**, i.e. with TLS. Against a plaintext broker it is a no-op that looks like coverage. | off |
| 10 | `opensearch-init` | ISM retention policy + snapshot repository and policy. The #1 disk-fill protection for a long run. | on |
| 15 | `opensearch-security-init` | Security-plugin users/roles/mappings. Needs `tls.enabled` and a `correlix-opensearch-security` ConfigMap you create from `deployment/docker/opensearch/security/`. | off |

`hook-delete-policy` keeps a **failed** job's pod: the reason a bootstrap failed
is the whole diagnostic.

---

## TLS

`tls.enabled=false` by default, exactly like the compose stack, whose base file
is plaintext-default with `compose.tls.yml` as the supported opt-in variant.

**The compose mesh is not ported, and could not be.** There, every SVID is
minted by the api's own internal CA whose root is sealed to a swtpm sidecar — a
host TPM device — and the api *refuses* to enable `TLS_INTERNAL_CA` without that
custody (the seal gate in `tls_ca.go`). Kubernetes has no equivalent. Two
supported shapes instead:

* **cert-manager** (`certManager.enabled=true`): the chart renders one
  `Certificate` per service from an issuer **you** own, with the bare Service DNS
  name as SAN and a SPIFFE URI matching the trust domain the ACL matrix uses.
  Custody becomes your issuer's problem, which is the honest trade.
* **Manual**: mint the same SANs yourself and list the Secret names under
  `tls.existingSecrets`.

`certManager.duration` defaults to 168h, matching `TLS_SVID_TTL` in
`compose.tls.yml` — chosen because a service that loads its SVID once at start
has a fuse of the cert's TTL from its last restart, and 24h meant nightly store
outages.

---

## The watchdog

`scripts/stack-watchdog.sh` stays **outside the cluster**. Its defining property
is that it survives the whole stack dying; a CronJob inside the cluster cannot
hold that, because the cluster is what fails. Keep running it from a host cron,
pointed at the ingress.

`watchdog.enabled=true` renders an **additional** in-cluster CronJob covering
only the checks that do not need to survive cluster death — consumer-group
membership and the alert-delivery heartbeat, both of which come straight from
the 2026-09-02 outage. It is additive, not a replacement, and it needs
`kafkaExporter.enabled=true` to have any series to read (without it, it fails
loudly rather than reporting green).

---

## Verifying an install

Each step answers a question the previous one cannot.

```bash
# 1. Did the bootstraps run? (helm exiting 0 does not say so)
kubectl -n correlix logs job/kafka-init
kubectl -n correlix logs job/opensearch-init

# 2. Is the platform serving?
kubectl -n correlix exec deploy/nginx -- wget -qO- http://api:8080/admin/health

# 3. IS THE ENGINE ACTUALLY CONSUMING?  A green pod is not an answer.
#    Needs kafkaExporter.enabled=true. Query VictoriaMetrics:
#      kafka_consumergroup_members{consumergroup="netops-correlation"} >= 1
#      kafka_consumergroup_lag_sum{consumergroup=~"netops-.*"}    (draining?)

# 4. Does an alert reach a human?
#    The always-firing AlertingHeartbeat rule stamps
#    netops_alert_webhook_heartbeat_timestamp_seconds on arrival. A stale stamp
#    means alerts are firing and reaching nobody — the 2026-09-02 shape.
```

Step 3 exists because on 2026-09-02 the correlation engine consumed nothing for
three hours while every container read `healthy`, `docker compose ps` was clean,
and the off-host watchdog was green the whole time. Liveness was perfect and the
pipeline was dead. `scripts/deploy-qualify.sh` is the compose version of this
question; there is no Kubernetes port of it yet (see below).

---

## Upgrades

```bash
helm upgrade correlix deployment/helm/correlix -n correlix -f my-values.yaml
```

* The bootstrap hooks re-run on every upgrade. They are idempotent by design.
* **`api` uses the `Recreate` strategy**, because it owns a `ReadWriteOnce`
  volume two pods cannot mount at once. That is a brief, real outage on every
  api upgrade — not a rolling one.
* **A StatefulSet's `volumeClaimTemplates` are immutable.** Changing a
  `persistence.size` in values makes the upgrade fail. Resize the PVC directly
  (if your class allows expansion) and then align values.
* Raising `env.BUS_PARTITIONS` is **increase-only** and must be done in a quiet
  window: keyed records produced before the increase stay in their old
  partitions. Procedure: `docs/scale-correlation.md`.
* `correlation.replicas` beyond `BUS_PARTITIONS` join the consumer group,
  receive nothing and process nothing. Raise partitions first.

Rollback: `helm rollback correlix <revision>`. This rolls back **manifests, not
data** — a schema or index change a newer version made is still there.

---

## What differs from the compose stack

| | Compose | Helm |
|---|---|---|
| Entry point | host port `:8000` | Ingress → `nginx` Service :8080 |
| Sizing | `mem_limit`/`cpus` from the resource planner | pod requests/limits in values (same numbers) |
| Secrets | `.env`, generated by `install.py` | a Secret **you** create; nothing is generated |
| Bootstraps | one-shot compose services + `deploy-qualify.sh` | `post-install,post-upgrade` Helm hooks |
| Internal TLS | api-minted SVIDs sealed to a swtpm sidecar | cert-manager or your own Secrets |
| App logs | `docker_logs` → `netops.applogs` | **not collected** (see below) |
| Watchdog | host cron | host cron (unchanged) + an optional partial CronJob |
| OpenSearch image | locally built slim derivative | the upstream image it derives FROM |
| `bootstrap.memory_lock` | `true` | `false` (needs `CAP_IPC_LOCK`); use swap-off |
| Store replicas | one process each | one replica each — **raising it does not cluster them** |

---

## What is not supported yet

Stated here rather than left to be discovered.

1. **`netops.applogs` is not collected.** The aggregator's `docker` source is
   `docker_logs`, which tails the Docker json-file logs of the platform's own
   containers. There is no Docker socket in a pod: the aggregator logs
   docker-socket errors and that one lane stays empty. Every other lane —
   syslog, traps, probes, metrics, the bus bridge, flows — is socket-based and
   works unchanged. A `kubernetes_logs` variant of `vector.yaml` is the fix and
   is not written.
2. **No cluster proof.** Nothing here has been installed. See the banner.
3. **No Kubernetes `deploy-qualify.sh`.** The compose post-deploy gate that
   *proves* the engines are consuming has no port; run its questions by hand
   (step 3 above).
4. **The stores do not cluster.** `replicas: 1` is the topology, matching
   compose: OpenSearch runs `discovery.type: single-node`, Kafka is single-node
   KRaft. Raising a replica count produces N independent un-clustered instances
   behind one Service, which is worse than one. Clustering any of them is a
   separate design.
5. **No HPA/VPA, no PodDisruptionBudgets.** Autoscaling a stateful,
   partition-bound pipeline needs the co-partitioning design worked through
   first (`docs/scale-correlation.md`), not an HPA on CPU.
6. **No air-gapped image bundle for a Kubernetes registry.** `global.imageRegistry`
   points the chart at a mirror; populating that mirror is not automated the way
   `make-installer.sh` automates the compose bundle.
7. **The `netops_app` PostgreSQL role is not provisioned.** Create it yourself.
8. **NetBox, Keycloak, Telegraf, the mock services and the cloud-ingest sidecar
   are not in the chart.** They are compose profiles for lab and integration
   work; add them if you need them.
9. **`opensearch-security-init` needs a ConfigMap you build.** The security
   directory carries per-identity role and mapping YAML an operator is expected
   to review; the chart deliberately does not stage a copy of it.
10. **There is no customer-facing page for this.** `docs-portal/docs/deploy/`
    deliberately carries no "Install on Kubernetes": publishing one would tell a
    customer the platform supports Kubernetes, and a chart that has never run on
    a cluster does not support anything yet. The page is owed once item 2 is
    closed, not before.

---

## Uninstall

```bash
helm uninstall correlix -n correlix
kubectl -n correlix delete pvc -l app.kubernetes.io/name=correlix   # DESTROYS DATA
```

The second command is separate on purpose.
