# Correlix Packaging Strategy — Final Design (#97)

Merges the owner's packaging research (Helm umbrella / Kustomize / OLM /
GitOps, 2026-07-03) with the measured reality of the product. Decides what we
ship now, what the Kubernetes target looks like, and how the analytics tier
(ClickHouse) scales independently. Companion: `docs/runbooks/storage-and-volume-operations.md`,
`docs/design/research/db-optimization-best-practices.md`.

---

## 1. Reality check — what Correlix actually is today

A **Docker-Compose product**: 23 services on one host behind nginx (`:8000`),
five application images we build (api, frontend, nginx, correlation, prober)
plus pinned third-party stores/collectors. There are **no Kubernetes
manifests, no CRDs, no operator** today. Two facts dominate packaging:

- The frontend `dist/` and docs portal are **build artifacts a client must
  never produce** — bundles ship prebuilt images (client prereq shrinks to
  Docker + Compose v2 + zstd).
- Every install generates **fresh secrets on the client host** (`install.py`)
  — nothing secret ever enters a bundle.

## 2. Verdict on the research

**Adopt (correct and used here):** modular-packages-with-umbrella principle;
prebuilt images always; SemVer + lockstep image/version stamping; air-gap as a
first-class path (single compressed artifact); monitoring shipped with the
app; per-component RBAC when K8s lands; GitOps for fleet management later.

**Defer (right idea, wrong phase):** Helm umbrella + subcharts (Phase 2 —
there is no K8s demand signed up yet, and charts without a consumer rot);
Kustomize overlays (Helm values suffice initially); ArgoCD app-of-apps
(Phase 3, our own SaaS fleet); Operator/OLM (only if we ever manage fleets of
Correlix instances programmatically — do **not** build an operator before the
umbrella chart has real users).

**Correct (research is stale or doesn't fit):**
- *Bitnami subcharts*: the Bitnami public catalog was gated/relocated under
  Broadcom (Aug 2025). Build on **vendor operators/charts** instead (see §5).
- *"CRDs first, Correlix operator reconciles CorrelixCluster"*: assumed
  architecture that doesn't exist; our tenancy is **app-layer** (JWT-scoped,
  RLS-backed), not namespace-per-tenant. K8s isolation unit = one **instance**
  per namespace.
- *One chart per microservice*: we are a monorepo with five lockstep images —
  per-image SemVer adds coordination cost with zero consumer benefit today.
  One product version stamps everything (§7).

## 3. Final design — three phases

### Phase 1 — Offline Compose bundle (SHIPPED with this design)

The deployable unit clients actually run. Implemented:

- **`scripts/make-installer.sh [--core] [--out DIR]`** — builds frontend dist
  if missing, `compose build`s the app images, resolves the exact pinned image
  set from `compose config --images` (unshipped profiles — mock-*, sso,
  netbox, flowgen, seal — excluded by construction), `docker save | zstd -T0`
  into one archive, `git archive` for source, MANIFEST + SHA256SUMS +
  INSTALL.md. `--core` drops OpenSearch-Dashboards/Grafana/cadvisor/
  node-exporter for eval VMs.
- **`install.py --bundle IMAGES.tar.zst`** (implies `--offline`) — verifies,
  `docker load`s, then `compose up -d --no-build`: a missing image is a hard
  error, never a silent build/pull on an air-gapped host.
- Measured sizes: see MANIFEST of the first build (full ≈ 4–5 GB compressed,
  core ≈ 3–3.5 GB; source 6.5 MB).

Client experience: `sha256sum -c` → untar → one `install.py --bundle` command
→ stack on `:8000` with per-host secrets. GPG-signing the SHA256SUMS is the
one remaining nicety (needs a product signing key — owner decision).

### Phase 2 — Kubernetes (target architecture, build on first real demand)

**Umbrella chart `deploy/helm/correlix/`** with subcharts for OUR services
only — api, ui (frontend+nginx), correlation, prober/collectors — and
**vendor operators for every stateful store**, consumed as dependencies with
`condition:` toggles (each also supports `external: {url}` bring-your-own):

| Store | K8s mechanism | Note |
|---|---|---|
| ClickHouse | Altinity `clickhouse-operator` | see §5 analytics options |
| VictoriaMetrics | `victoria-metrics-operator` (VMSingle → VMCluster) | |
| OpenSearch | OpenSearch operator | or external/managed |
| PostgreSQL | CloudNativePG | |
| Redis | Valkey chart | licensing swap, §4 |
| Redpanda | Redpanda operator | **BSL** — or swap to Strimzi/Kafka (KRaft), §4 |

K8s-specific design points:
- **UDP ingest is the hard part** (syslog 5514, NetFlow 2055/4739, sFlow 6343,
  traps 1162): cloud LoadBalancers handle UDP unevenly. Ship the edge
  receivers (syslog-ng, goflow2, trap receiver) as a **DaemonSet with
  hostPorts** (on-prem default) *or* behind MetalLB/NLB UDP Services (values
  toggle). Device-facing ports must be stable node IPs — document per target.
- **Namespace-per-instance**, not per-tenant; tenancy stays in the app.
- Secrets: install-time generation moves to a Helm pre-install Job (same
  generator), or ExternalSecrets for enterprises.
- Watchdog → liveness/readiness probes + PrometheusRules (the compose
  healthchecks already define the probe conditions 1:1).
- **Honest K8s-readiness blockers in the app itself** (work items before GA):
  the api holds file/kv state under `/data` (needs PVC at minimum; the M0
  kv→PG migration is the real fix), runs the WS hub + schedulers in-process
  (**replicas=1 until then** — document as a known constraint), and CH schema
  management is init.sql-plus-documented-ALTERs (needs a versioned migration
  runner before external-CH support, §5C).

### Phase 3 — Fleet/SaaS (later)
GitOps app-of-apps (ArgoCD/Flux) over the Phase 2 chart for our own hosted
fleet; only then evaluate an operator.

## 4. Licensing gate (blocks EXTERNAL distribution of bundles)

| Image | License | Action |
|---|---|---|
| Redpanda | **BSL** (source-available) | Get written OK for redistribution, or swap the bus to Apache Kafka (KRaft mode, Strimzi on K8s). Compose/K8s seam is small — Kafka-API compatible by design |
| Redis `7-alpine` (**resolves to 7.4.9**) | **RSALv2/SSPL** | Pin `redis:7.2-alpine` (BSD) or swap to **Valkey** (BSD, drop-in). Recommended: Valkey |
| Grafana | AGPLv3 | Distributable with obligations; it's optional (self-observability) — `--core` bundle already omits it |
| syslog-ng | GPLv3 | Fine unmodified |
| OpenSearch, ClickHouse, VictoriaMetrics, Postgres, Vector (MPL-2), goflow2, Prometheus, gnmic | Apache-2/BSD/MPL | Fine |

Internal/lab bundles are unaffected. This table must be re-verified at each
base-image bump (digests are pinned, so licenses can't drift silently).

## 5. Analytics (ClickHouse) growth — the owner's question

> "Analytics may enlarge over time — does it have to be its own component/pod,
> or should we offer both?"

**Offer both, and the seam already exists.** Every ClickHouse access in the
product goes through one env var (`CLICKHOUSE_URL` — API proxy, workers,
correlation service alike), so "where analytics lives" is a deployment choice,
not a code change:

| Option | What it is | When |
|---|---|---|
| **A — Embedded** (default today) | CH inside the stack: compose service / one operator-managed pod. | Labs, evals, SMB. A tuned single node comfortably carries low-TB scale — with the #96 codecs/TTLs, our per-day footprint is small |
| **B — Dedicated analytics tier** | Same product, CH split out: compose → second host with `CLICKHOUSE_URL` override (works TODAY); K8s → Altinity operator CHI in its own StatefulSet with its own storage class, optional **S3-tiered cold storage** (`TTL … TO VOLUME`), later shards/replicas | Retention × ingest outgrows the app host; different disk economics wanted; first "real" customer |
| **C — External / BYO** | Customer's existing ClickHouse or ClickHouse Cloud endpoint; we ship schema + migrations only | Enterprise. **Gated on building a versioned CH migration runner** (today: init.sql for fresh + documented ALTERs for upgrades — fine for A/B where we own the server, not for C) |

**Recommendation:** default **A**; expose **B** as a first-class values/env
profile (compose: documented `CLICKHOUSE_URL` override; K8s:
`analytics.mode: embedded|dedicated`); park **C** until the migration runner
exists. Same pattern later applies to OpenSearch and VM (both also
single-URL seams) — analytics first because it's the store that grows with
retention ambition.

## 6. Versioning & CI

- One **product version** (git tag) stamps bundle name, MANIFEST, and all five
  app images — monorepo lockstep by construction; third-party images stay
  digest-pinned in compose (the bundle is reproducible from a tag).
- CI addition (Phase 1): a workflow job that runs `make-installer.sh --core`
  on tag, uploads the bundle as a release artifact, and smoke-tests
  `install.py --bundle` in a clean VM (extends the existing
  fresh-install-integrity workflow).
- Chart SemVer starts in Phase 2; charts pushed as OCI artifacts next to
  images.

## 7. Decision log

1. Ship Compose bundles now; Helm umbrella is the committed K8s shape, built
   on first real demand — not speculatively.
2. Stateful stores ride vendor operators on K8s, never our own subchart
   re-implementations; every store also supports bring-your-own.
3. Analytics ships embedded by default with a supported dedicated-tier
   profile; BYO waits for a CH migration runner.
4. No operator/CRDs before the chart has users. No Bitnami dependencies.
5. Licensing gate (§4) blocks external distribution until Redpanda/Redis
   items are resolved (Valkey swap recommended regardless).
