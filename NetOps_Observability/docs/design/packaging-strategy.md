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
| Valkey (cache) | Valkey chart | swap done, §4 |
| Apache Kafka (bus) | Strimzi (KRaft) | swap done, §4 — embedded single-node in compose; Strimzi when a K8s chart exists |

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

**GATE CLOSED 2026-07-03** — both flagged images are out of the product; the
guards in `make-installer.sh` + `preflight-install.py` + the release-bundle
smoke keep them out. The customer-facing statement of this table ships in the
bundle as `LICENSES.md`.

| Image | License | Status |
|---|---|---|
| ~~Redpanda~~ | ~~BSL~~ | ✅ **REMOVED 2026-07-03** — bus swapped to **Apache Kafka 4.1** (Apache-2.0, `apache/kafka` official image, single-node KRaft, digest-pinned). Redpanda is not shipped in any bundle and no lab profile was retained (clients were Kafka-API-only, so nothing needed it). The Go pandaproxy producer became the Vector bus bridge (`bus_producer.go` → :8692). External Kafka-compatible brokers supported via `BROKER_URLS` |
| ~~Redis `7-alpine` (7.4.9 = RSALv2/SSPL)~~ | ~~RSALv2~~ | ✅ **REMOVED 2026-07-03** — swapped to **Valkey 8-alpine** (BSD-3, digest-pinned; redis-* compat symlinks so the service name, `REDIS_HOST` consumers, and `redis-cli` callers are untouched). Upgrade note: Valkey can't read Redis 7.4 RDB v12 — existing installs drop `data/redis/dump.rdb` (TTL'd collector caches only) |
| Apache Kafka | Apache-2.0 | ✅ included — allowed with notices (bundle `LICENSES.md`; upstream NOTICE ships inside the image) |
| Grafana | AGPLv3 | Distributable unmodified with obligations; optional (self-observability) — `--core` bundle omits it |
| syslog-ng | GPLv3 | Fine unmodified |
| OpenSearch, ClickHouse, VictoriaMetrics, Postgres, Vector (MPL-2), goflow2, Prometheus, gnmic, Valkey | Apache-2/BSD/MPL | Fine |

This table must be re-verified at each base-image bump (digests are pinned,
so licenses can't drift silently).

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
- CI addition (Phase 1): a workflow job that builds the bundle on tag, uploads
  it as a release artifact, and smoke-tests `install.py --bundle` in a clean VM
  (extends the existing fresh-install-integrity workflow).
  **Amended 2026-09-03:** `.github/workflows/release-bundle.yml` builds the
  **full** profile (base appliance + add-on packs), not `--core`. `--core`
  predates the add-on-pack model (`25a6045a`); it is still a supported flag for
  eval-sized bundles, but the shipped release carries the packs. The workflow's
  smoke step asserts `profile:  full` in the MANIFEST and that both pack
  archives exist, so the label and the contents move together.
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
5. Licensing gate (§4) — CLOSED 2026-07-03: Redis→Valkey and Redpanda→Apache
   Kafka both shipped; build/preflight/CI guards keep flagged images out.

---

## 8. Bundle size — the measured lever table (tracker 148)

**Why this section exists.** Tracker 148 listed the remaining bundle-size levers
in leverage order but carried no measurements, so "we could save ~150 MB" and
"we did save 22 MB" looked the same on the page. Everything below was measured
on 2026-09-06 on the lab host; anything that was *not* measured says so.

**How the numbers were taken.** Two different sizes matter and they are not the
same number:

* **on disk** — `docker images` / `docker image inspect` uncompressed size. What
  the customer's Docker daemon unpacks.
* **in the bundle** — `docker save <image> | wc -c`. `scripts/make-installer.sh`
  (line 531) does exactly `docker save $SAVE_REFS | zstd -q -T0 -3`, and the
  containerd image store already holds layers compressed, so the save stream IS
  the bundle contribution: measured on `netops-correlation`, `zstd -3` on top of
  the save removed a further 0.2 % (66 451 456 → 66 302 645 B). **The bundle
  itself was NOT built here** — that is disk-gated (tracker 125), and this host
  sat at 93 % — so every bundle figure below is a per-image `docker save`
  measurement, not a bundle diff.

### 8.1 Shipped levers, measured

| # | Lever | State | Measured effect |
|---|---|---|---|
| L1 | Correlation base `python:3.12-slim` → `python:3.12-alpine` (tracker 263) | **shipped 2026-09-06** | image **281 → 182 MB** on disk; bundle **66.45 → 44.22 MB (−22.23 MB)**. Inherited package surface **87 dpkg → 38 apk**; the register of undischarged corresponding-source obligations (`scripts/source-mirror.json`) goes from **60 rows to 14** for this image (58 Debian rows deleted, 12 Alpine rows recorded, the 2 `Simple Launcher` rows unchanged), which the evaluation prints as **18 recorded obligations** because Syft reports `Simple Launcher` under six spellings |
| L2 | Root `.dockerignore` for the eight services that build with `context: ../..` (tracker 193, `d0a125ce`) | shipped, re-verified here | build context **16.06 GB / 62 889 files → 0.89 GB / 5 824 files**; per service `correlation` 53.15 → 6.29 MB (independently re-measured cold today: 6.35 MB), `api` 79.69 → 37.03 MB. **Zero effect on bundle size** — this is a build-cost, cache-invalidation and *safety* lever (`data/`, `.env` and key material can no longer reach an image), not a size lever. `tests/test_dockerignore_copy_sources.py` guards it |
| L3 | Go binary: `-trimpath -ldflags="-s -w"`, `CGO_ENABLED=0`, distroless-static runtime | already in `Dockerfile.backend` | `netops-api` = **55 MB** on disk / **13.6 MB** in the bundle, of which `gcr.io/distroless/static-debian12` is 6.12 MB. Stripping measured directly, same tree, same toolchain (go 1.26.8), only the `-s -w` flags differing: **48 085 306 → 36 016 290 B on disk (−12.07 MB, −25.1 %)** and **22 524 626 → 12 767 065 B compressed (−9.76 MB, −43.3 %)**. It applies per Go image, so `netops-api` and `netops-prober` each carry the saving |
| L4 | No build toolchain in any shipped image (multi-stage) | verified, and extended by L1 | the correlation **build** stage now installs `gcc musl-dev zlib-dev` (aiokafka publishes no `musllinux` wheel at any version, so its C extension is compiled from the hash-locked sdist); none of it reaches the runtime stage — `which gcc` in the shipped image returns nothing |
| L5 | Dev dependencies never enter an image | verified | the frontend image ships build OUTPUT only: `src/frontend/dist` (6.8 MB) + `docs-portal/build` (9.9 MB). The 682 MB of `node_modules` is excluded by L2. `netops-frontend` = 118 MB on disk / 30 MB in the bundle |

### 8.2 Levers considered and rejected, with the reason

* **Layer squashing — rejected, it would make the bundle BIGGER.** The bundle is
  a single `docker save` of every image at once, so a layer shared between images
  is stored **once**. `netops-frontend` and `netops-nginx` share the entire
  `nginx:1.27-alpine` base (8 layers, 74.5 MB); squashing each image into one
  layer duplicates that base per image. Squashing is a lever for a *single*
  image pushed to a registry, which is not the shape we ship.
* **Dropping the correlation test suite and fixtures from the image — rejected
  for now.** 163 `test_*.py` (2.7 MB) + `fixtures/` (1.6 MB) ≈ 4.3 MB
  uncompressed, under ~1 MB in the bundle — and running that suite *inside* both
  the old and the new image, with the working tree mounted so the source is
  identical, is how the L1 base swap was qualified (16 failures before, the same
  16 after). Deleting the evidence to save 1 MB is a bad trade. Revisit if the
  image ever ships to a size-constrained edge target.

### 8.3 What is still open (unchanged from tracker 148)

These are functional migrations, not build changes, and each needs its own
validation; none of them was attempted here:

* **syslog-ng → Vector consolidation** (~180 MB + one fewer service).
* **`apache/kafka` → `apache/kafka-native`** (~150 MB; upstream positions the
  GraalVM image for dev/test — prod-worthiness for a single-node KRaft appliance
  has to be established first).
* **OSD add-on pack trim** (427 MB pack; the same flatten-and-trim treatment the
  server image already got).
* **Correlation Python → Go** — after L1 the remaining Python base is ~44 MB in
  the bundle rather than ~66 MB, which weakens this one considerably.
