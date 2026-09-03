# Release checklist

What has to be true before Correlix is tagged, and who has to do it.

Derived from the machinery that **actually exists** in this repository as of 2026-09-03 — not from a
template. Every step names the real script or workflow, and is marked:

| Mark | Meaning |
|---|---|
| 🟢 **AUTOMATED** | A CI job or script does it. Nobody can forget it. |
| 🟡 **MANUAL** | A human runs a real command. It exists; it is not wired to anything. |
| 🔴 **MISSING** | Nothing does it. Listed so the gap is visible rather than assumed away. |
| 👤 **OWNER** | Reserved to the owner. Not delegable. |

> **The release is `v0.9.0-rc1`.** See [`docs/RELEASE_NOTES_v0.9.0-rc1.md`](RELEASE_NOTES_v0.9.0-rc1.md)
> for why that number and why `-rc1`.

---

## 0. Preconditions — the ones that block everything

| | Step | State |
|---|---|---|
| 0.1 | **Branch protection matches the real job names.** `docs/runbooks/ci-branch-protection.md` §1 requires a check named `build · vet · test · race · fuzz`; the job's actual `name:` is **`build · vet · test · race`**. A required check naming a job that does not exist pins every PR at "Expected" forever. | 🔴 MISSING — runbook is stale |
| 0.2 | **Work is merged to `main`.** All of this ships from `feat/observability-platform`; `main` is behind. Tagging a branch that is not `main` makes `release-bundle.yml`'s `branches: [main]` leg and every "on main" assumption wrong. | 🟡 MANUAL |
| 0.3 | Working tree clean, no untracked source. `git status --porcelain` empty. | 🟡 MANUAL |
| 0.4 | `.trivyignore.yaml` entries each still carry a reason and a revisit condition. | 🟡 MANUAL |

---

## 1. Code gates — must be green on the release commit

All of these run on every PR and push. None needs a human unless it fails.

| | Gate | Workflow · job | State |
|---|---|---|---|
| 1.1 | gofmt, `go build`, `go vet`, `go vet -tags=pgintegration`, `go test`, `go test -race` | `backend-ci` · `build · vet · test · race` | 🟢 AUTOMATED |
| 1.2 | **Offline vendor build** — `GOFLAGS=-mod=vendor GOPROXY=off go build/vet/test-compile`, cold module cache | `backend-ci` · `offline vendor build (blocking)` | 🟢 AUTOMATED *(new — CLAUDE.md §6 gate 2, previously asserted but never proven)* |
| 1.3 | Postgres integration + the full RLS / tenant-isolation corpus against a live DB as a `NOBYPASSRLS` role | `backend-ci` · `Postgres integration (blocking)` | 🟢 AUTOMATED |
| 1.4 | `govulncheck` | `backend-ci` · `govulncheck (blocking)` | 🟢 AUTOMATED |
| 1.5 | staticcheck + gosec + golangci-lint on the crypto/trust packages | `backend-ci` · `staticcheck + gosec …` | 🟢 AUTOMATED |
| 1.6 | golangci-lint repo-wide | `backend-ci` · `golangci-lint (repo-wide, blocking)` | 🟢 AUTOMATED |
| 1.7 | `pytest` (whole suite — also the signature-catalogue fixture gate and the golden-replay gate) | `correlation-ci` · `pytest (blocking)` | 🟢 AUTOMATED |
| 1.8 | ruff · bandit · mypy · **pip-audit** | `correlation-ci` · `lint (blocking)` | 🟢 AUTOMATED |
| 1.9 | `tsc -b && vite build` | `frontend-ci` · `tsc -b && vite build (blocking)` | 🟢 AUTOMATED |
| 1.10 | `npm audit --audit-level=high` | `frontend-ci` · `npm audit (blocking)` | 🟢 AUTOMATED |
| 1.11 | Playwright E2E in headless Chromium against the real SPA | `frontend-ci` · `Playwright E2E (blocking)` | 🟢 AUTOMATED |
| 1.12 | Panel↔metric contract — no dashboard panel wired to a metric nothing emits | `frontend-ci` · `metric-contract` | 🟢 AUTOMATED |
| 1.13 | Trivy filesystem scan (vuln + secret + misconfig, CRITICAL/HIGH) | `supply-chain` · `trivy-fs` | 🟢 AUTOMATED |
| 1.14 | gitleaks, **full history** | `supply-chain` · `gitleaks` | 🟢 AUTOMATED |
| 1.15 | CIS-Docker policy gate (non-root, digest pins, `no-new-privileges`, `cap_drop: ALL`, cap allowlist) | `supply-chain` · `cis-docker` | 🟢 AUTOMATED |
| 1.16 | Ingest contract, telemetry catalogue, tracker staleness | `ingest-contract-ci`, `telemetry-catalog-ci`, `tracker-ci` | 🟢 AUTOMATED |
| 1.17 | Fuzz corpus exploration | `fuzz-nightly` (scheduled, not per-PR) | 🟢 AUTOMATED |
| 1.18 | **`go.mod` direct requires ⊆ the CLAUDE.md §6 allowlist** | — | 🔴 MISSING — human review only |

**Local mirror before pushing:** `bash scripts/ci-backend-guard.sh` (build + vet + the exact
golangci-lint version CI uses). The gate tools live in `/home/rao/go/bin` and are **not** on a default
PATH — export it, or you get a green run that checked nothing.

---

## 2. Install and boot integrity

| | Step | How | State |
|---|---|---|---|
| 2.1 | Every `${VAR}` the compose stack requires is provisioned by `install.py`; every bind-mount source exists; every data dir is created | `scripts/preflight-install.py` — static, stdlib | 🟢 AUTOMATED (`fresh-install-integrity` · `integrity`) |
| 2.2 | Every committed config **boots** in its real pinned binary (Vector topology, nginx `-t`, promtool, VictoriaMetrics, syslog-ng) | `scripts/preflight-configs.sh` | 🟢 AUTOMATED (same job) |
| 2.3 | **A full TLS install on a clean runner** — no crash-loops behind exit 0, live SEC-007 ACL matrix, TLS ingress served with `--cacert` (never `-k`), SVID mint complete for 10 services | `fresh-install-integrity` · `tls-install-boot` (~45 min) | 🟢 AUTOMATED |
| 2.4 | `scripts/*.py` lint | `fresh-install-integrity` · `scripts-lint` (ruff, pinned) | 🟢 AUTOMATED |
| 2.5 | API boot security-posture evaluation (`secprofile`), exported on `/metrics` and `/admin/security/posture` | runtime, every boot | 🟢 AUTOMATED *(gap: no rule covers the bus or ingest lanes — a production boot with a plaintext bus is not refused)* |
| 2.6 | **`install.py` has no `--dry-run` or `--validate-only`.** `--no-start` (config only, no `compose up`) is the closest thing. | — | 🔴 MISSING |
| 2.7 | `install.py` never invokes `preflight.sh` / `preflight-configs.sh`, though both scripts' headers claim it does | — | 🔴 MISSING (doc drift) |
| 2.8 | No disk-space, free-memory, port-conflict or `vm.max_map_count` gate in `install.py` (host prep is out of band in `bootstrap-ubuntu.sh` / `prepare-host.sh`) | — | 🔴 MISSING |

### 2.9 Clean-clone dry run — **verified 2026-09-03**

Run against a fresh `git clone` in a temp directory. Results, not predictions:

| Command | Result |
|---|---|
| `python3 scripts/install.py --help` | ✅ exit 0 — full flag surface documented |
| `python3 scripts/preflight-install.py` | ✅ exit 0 — 44 scaffold paths, bus guardrails, 58 transport edges, prompt/flag parity all pass |
| `python3 scripts/install.py --no-start --tls=no --bootstrap-docker=no --no-plan-resources` | ✅ exit 0 — `.env` written (0600), data dirs prepared |
| `docker compose config` (default profiles) | ✅ exit 0 — 19 services; 25 with all profiles |
| `docker build -f deployment/docker/Dockerfile.frontend .` | ❌ **exit 1** — `"/src/frontend/dist": not found` |

**What a customer would hit:** `install.py` runs `docker compose up -d --build`, and
`Dockerfile.frontend` `COPY`s `src/frontend/dist` and `docs-portal/build` — **both gitignored**. On a
git clone they do not exist, so the frontend image build fails. The Dockerfile header documents the
prerequisite (`npm install && npm run build` in both trees) and explains why it is not built inside
Docker, so this is deliberate — but `validate_scaffold()` does not check for it and the installer
gives no guidance when it fails.

This affects the **git-clone / evaluator path only**. The customer bundle path is unaffected:
`make-installer.sh` always rebuilds both trees and ships pre-built images, and `install-correlix.sh`
never builds. **Recommended before tagging:** add `src/frontend/dist` and `docs-portal/build` to
`REQUIRED_PATHS` (or emit a targeted error) so the failure names its own fix. 🔴 MISSING

Other first-time friction, in order of likelihood:
- Docker + Compose v2 required; legacy `docker-compose` is explicitly rejected. On Debian family the
  installer offers to bootstrap Docker, then **forces a re-login and exits 0** — a two-pass install.
- Two interactive prompts (TLS `[Y/n]`, Docker bootstrap). On a non-TTY the TLS prompt silently keeps
  **plaintext**; `--tls=yes|no` and `--bootstrap-docker=yes|no` beat both.
- After install, the admin and Grafana passwords must be read out of `.env` by hand.
- TLS installs terminate on a **self-signed** certificate; the browser warns.

---

## 3. Qualification — the gate that says a build is good enough to ship

| | Step | How | State |
|---|---|---|---|
| 3.1 | **Reference-capacity regression.** `t-storm-2.5k`, seed 20260829, scorer v2: completion ≤ 2 700 s, losslessness (injected == persisted, 0 DLQ), memory caps held with no sustained growth, accuracy ≥ 93 %, replica stability, exact aggregation accounting. Verdict is three-valued — `INVALID` can never be reported as `PASS`. | `python3 scripts/release-qualify.py` — ~1 h exclusive rig time, ≥ 10 GiB free, `load1 ≤ 6.0`, exactly 2 correlation replicas | 🟡 MANUAL — **and never yet executed** (tracker 203) |
| 3.2 | Storm SLO / shippable-lane contract | `make release-gate` (offline) | 🟡 MANUAL |
| 3.3 | Same, against a live stack (per-endpoint read budgets, retention preview) | `make release-gate-live` | 🟡 MANUAL |
| 3.4 | First-customer acceptance — everything above **plus** proof a critical alert leaves the app via an external push channel | `make first-customer-check` (`SEND=1` to deliver a real push) | 🟡 MANUAL |
| 3.5 | Nightly scale mini-ladder and perf regression | `scale-miniladder-nightly`, `perf-nightly` | 🟢 AUTOMATED *(these are regression trend, **not** the release gate)* |
| 3.6 | **Rebalance correctness** — 155 of 199 clauses report SKIPPED, because `ownership_runner.py` has no CLI | — | 🔴 MISSING |
| 3.7 | Neither `deploy-qualify.sh` nor `release-qualify.py` is scheduled anywhere | — | 🟡 by design (rig time is scarce) |

> **3.1 is the release blocker.** The harness, the frozen profile and the `storm-s11` baseline all
> exist. The run does not. Until it returns `QUALIFICATION PASS`, the honest label is `-rc1`.

---

## 4. Artifacts

| | Step | How | State |
|---|---|---|---|
| 4.1 | **Offline customer bundle** — images + source + `MANIFEST` + `SHA256SUMS` + the GUI installer, with licensing guards (must contain `apache/kafka:` and `valkey/valkey:`; must **not** contain redpanda/redis/prometheus) and `LAB_PATHS` scrubbing | `bash scripts/make-installer.sh` → `dist/correlix-<version>/`; `release-bundle.yml` on a `v*.*.*` tag | 🟢 AUTOMATED on tag |
| 4.2 | Bundle smoke test — `sha256sum -c`, `zstd -t`, git-SHA lockstep against MANIFEST, full `docker load` round-trip with `docker image inspect` per MANIFEST image, source tarball extracted and `preflight-install.py` run inside it | `release-bundle.yml` | 🟢 AUTOMATED |
| 4.3 | Bundle staleness gate | `make bundle-status` / `scripts/bundle-staleness.sh` (warn-only pre-push hook) | 🟢 AUTOMATED (advisory) |
| 4.4 | **GHCR images** — `netops-{api,correlation,nginx,frontend}`, tagged `semver`, `major.minor`, `sha` | `publish-images.yml` on a `v*.*.*` tag | 🟢 AUTOMATED on tag — ⚠️ **has no `needs:`; it pushes without gating on any test job** |
| 4.5 | **Build provenance** — `actions/attest-build-provenance`, keyless Sigstore, `push-to-registry: true` | `publish-images.yml` | 🟢 AUTOMATED on tag — **never executed**, because no `v*` tag has ever existed |
| 4.6 | Per-image CycloneDX SBOM | `anchore/sbom-action` in `publish-images.yml` | 🟢 AUTOMATED on tag — never executed |
| 4.7 | **Committed source SBOM** — CycloneDX for Go vendor, both npm trees, the pip lock and every image pin | `python3 scripts/sbom.py` → `docs/sbom/`; verified by `scripts/sbom.py --check` and `tests/test_sbom.py` | 🟢 AUTOMATED *(new)* |
| 4.8 | **Bundle signature.** `make-installer.sh` GPG-signs `SHA256SUMS` → `SHA256SUMS.asc` when `CORRELIX_SIGNING_KEY` is set, and `install-correlix.sh` treats a bad signature as fatal. **`release-bundle.yml` never sets the key**, so every bundle ever produced is checksum-only. | — | 🔴 MISSING — see 👤 6.4 |
| 4.9 | **Container image signing (cosign / Notation).** Zero references repo-wide. Provenance attestation (4.5) is adjacent but is not a signature over the image. | — | 🔴 MISSING |
| 4.10 | `release-bundle.yml` names its artifact `correlix-bundle-core` but invokes `make-installer.sh` **without `--core`**, so it builds the *full* bundle. Header and behaviour disagree. | — | 🔴 fix before tagging |
| 4.11 | VM appliance images (qcow2/vmdk/vhdx) | `scripts/make-vm-image.sh` | 🟡 MANUAL |
| 4.12 | **No root `.dockerignore`** while 8 services build with `context: ../..` (tracker 193) | — | 🔴 MISSING (build-size, not correctness) |

---

## 5. Documentation

| | Step | Where | State |
|---|---|---|---|
| 5.1 | `CHANGELOG.md` — Keep-a-Changelog, from the 2026-07-01 baseline | `CHANGELOG.md` | 🟢 present *(new)* |
| 5.2 | Release notes in customer voice, with honest known limitations | `docs/RELEASE_NOTES_v0.9.0-rc1.md` | 🟢 present *(new)* |
| 5.3 | Upgrade path and the bootstraps it does not run | `docs/UPGRADE.md`, `docs/runbooks/upgrade-bootstraps.md` | 🟢 present |
| 5.4 | Install guide, sizing, quick reference | `docs/DEPLOY_LINUX.md`, `docs/HOSTING_SIZING_GUIDE.md`, `docs/RESOURCE_SIZING.md`, `docs/QUICK_REFERENCE.md` | 🟢 present |
| 5.5 | Acceptance and pilot playbook | `docs/runbooks/first-customer-acceptance.md`, `docs/runbooks/pilot-playbook.md` | 🟢 present |
| 5.6 | What is proven versus merely built | `docs/audit/INVARIANTS.md` | 🟢 present |
| 5.7 | Third-party licence obligations inventory | — | 🔴 MISSING (ship-readiness C2; owned by another workstream) |
| 5.8 | **No `LICENSE` file** at either repository root. `NOTICE` is the only licence-adjacent file. | — | 🔴 MISSING — 👤 owner decision |
| 5.9 | **No `VERSION` file.** Version comes from `git describe --tags --match 'v[0-9]*'`, falling back to a date stamp. Once a `v*` tag exists this resolves correctly everywhere (bundle name, `/admin/version`, SBOM metadata). | — | 🟡 by design |
| 5.10 | `docs/runbooks/ci-branch-protection.md` §6 still says container CVE scanning, SBOM and gitleaks are "not yet wired" — all three shipped | — | 🔴 stale, correct it |

---

## 6. 👤 Owner-only — the actual ship

Nothing below is delegable. Steps 6.2 and 6.3 fire automatically **from the tag**, so 6.1 is the point
of no return: `publish-images.yml` pushes to GHCR with no test job gating it.

| | Step | Command / place |
|---|---|---|
| 6.1 | **Create the tag.** Annotated, on `main`, at the commit whose CI is green. Consider `-s` (GPG-signed) — the tag is the only signed link between the source and the artifacts until 6.4 exists. | `git tag -s -a v0.9.0-rc1 -m "Correlix v0.9.0-rc1"` then `git push origin v0.9.0-rc1` |
| 6.2 | **Bundle publish** fires on the tag: builds, smoke-tests, then `gh release create --verify-tag` + `gh release upload --clobber`. | `release-bundle.yml` (automatic) |
| 6.3 | **GHCR publish** fires on the tag: 4 images + build provenance + per-image SBOM, to a **private** registry. | `publish-images.yml` (automatic) |
| 6.4 | **Decide the signing story and wire it.** Three separate gaps: (a) set `CORRELIX_SIGNING_KEY` in `release-bundle.yml` so `SHA256SUMS.asc` is actually produced — the verifier in `install-correlix.sh` already exists and already fails closed; (b) decide whether cosign signs the GHCR images, or whether keyless build provenance (6.3) is the whole story; (c) publish the public key wherever customers can fetch it. | repo secrets + `release-bundle.yml` |
| 6.5 | **Grant registry access.** GHCR packages are private. Decide public versus per-customer read tokens. | GitHub → Packages |
| 6.6 | **Write the GitHub release page** from `docs/RELEASE_NOTES_v0.9.0-rc1.md`. Mark it **pre-release** while the tag carries `-rc1`. | GitHub → Releases |
| 6.7 | **Ratify the open exceptions** the release notes disclose: tracker 212 (gnmic→Kafka plaintext, `review_by 2026-12-02`), O10 (api→gotenberg plaintext), and the deployment of tracker 209 (OpenSearch flood-stage fix — built, deploy pending owner approval). | — |
| 6.8 | **Green-light the qualification run** (§3.1). ~1 h of exclusive rig time. Dropping `-rc1` depends on it. | — |
| 6.9 | `/code-review ultra` on the release diff. | — |

---

## 7. Post-tag verification

| | Step | How |
|---|---|---|
| 7.1 | Download the published bundle **from the release page**, not from `dist/`, and install it on a clean host | `./prepare-host.sh` then `./install-correlix.sh install` |
| 7.2 | Prove the engines consume | `scripts/deploy-qualify.sh` — exit **0** only. `2` is INCOMPLETE, which is not a pass |
| 7.3 | Confirm the deployed build is the tagged build | `GET /admin/version` — `identified: false` is the drift signal |
| 7.4 | Prove a critical alert reaches a human | `scripts/verify-critical-alert-channel.sh --send` |
| 7.5 | Confirm the watchdog is installed and pinging | `scripts/install-watchdog.sh`, then `scripts/stack-watchdog.sh --test` — ⚠️ sends a real push to the owner's phone |

---

## Verdict

**Not ready to tag as final. Ready to tag as `v0.9.0-rc1` once §0 is cleared.**

The engineering gates are in unusually good shape: 16 blocking CI checks, a live 45-minute TLS
install-and-boot test on every PR, full-history secret scanning, a container policy gate, and now a
proven offline vendor build and a committed SBOM. What is missing is not code quality — it is
**release plumbing and one un-run measurement**:

**Blocking a `-rc1` tag (all small):**
1. §0.1 branch protection names a job that does not exist.
2. §0.2 the work is on `feat/observability-platform`, not `main`.
3. §4.10 `release-bundle.yml` builds the full bundle while labelling it `core`.

**Blocking a *final* tag:**
4. §3.1 the reference-capacity regression has never been executed.
5. §4.8 no bundle is signed, though both the signer and the fail-closed verifier already exist.
6. §4.9 no image signing story.
7. §5.8 no `LICENSE` file.
8. §2.9 a clean clone cannot build the frontend image without an undocumented-at-the-failure-point
   `npm run build` (bundle path unaffected).

**Should not block, but must be disclosed** — and is, in the release notes: the file-versus-relational
backend limitation, the flags that default off, the `PARTIAL` OpenSearch snapshot, and the rig-gate
invariants that are "proven on a named run" rather than regression-proof.
