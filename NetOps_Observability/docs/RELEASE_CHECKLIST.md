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
| 0.1 | **Branch protection matches the real job names.** The runbook is now correct (18 required checks, §1.1) and machine-checked against the workflows by `tests/test_required_checks_consistency.py`. What remains is an **admin action outside the repo**: apply the ruleset. Command in 👤 §6.2. | 🟡 MANUAL — 👤 owner/admin, not yet applied |
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
| 1.8 | ruff · bandit · mypy · **pip-audit** | `correlation-ci` · `ruff · bandit · mypy · pip-audit (blocking)` | 🟢 AUTOMATED |
| 1.9 | `tsc -b && vite build` | `frontend-ci` · `tsc -b && vite build (blocking)` | 🟢 AUTOMATED |
| 1.10 | `npm audit --audit-level=high` | `frontend-ci` · `npm audit (blocking)` | 🟢 AUTOMATED |
| 1.11 | Playwright E2E in headless Chromium against the real SPA | `frontend-ci` · `Playwright E2E (blocking)` | 🟢 AUTOMATED |
| 1.12 | Panel↔metric contract — no dashboard panel wired to a metric nothing emits | `frontend-ci` · `panel↔metric contract (blocking)` | 🟢 AUTOMATED |
| 1.13 | Trivy filesystem scan (vuln + secret + misconfig, CRITICAL/HIGH) | `supply-chain` · `Trivy filesystem scan (blocking)` | 🟢 AUTOMATED |
| 1.14 | gitleaks, **full history** | `supply-chain` · `gitleaks secret scan (blocking, full history)` | 🟢 AUTOMATED |
| 1.15 | CIS-Docker policy gate (non-root, digest pins, `no-new-privileges`, `cap_drop: ALL`, cap allowlist) | `supply-chain` · `CIS-Docker policy gate (blocking)` | 🟢 AUTOMATED |
| 1.16 | Ingest + storage contracts (dead-letter lanes, frozen log templates, authenticated ingest sources) | `ingest-contract-ci` · `ingest + storage contracts (blocking)` | 🟢 AUTOMATED *(required check since 2026-09-04)* |
| 1.16a | Telemetry catalogue invariants + gNMI fixture-replay conformance | `telemetry-catalog-ci` · `invariants · conformance · pytest (blocking)` | 🟢 AUTOMATED *(required check since 2026-09-04)* |
| 1.16b | Tracker staleness | `tracker-ci` · `tracker staleness (blocking on HIGH)` | 🟢 AUTOMATED *(deliberately **not** a required check — runbook §1.3)* |
| 1.16c | **Third-party licence gate** | `supply-chain` · `Third-party licence gate (blocking)` | 🟢 AUTOMATED |
| 1.16d | **OCI image compliance** — the FINAL image is the compliance boundary: inherited base-layer software (BusyBox et al.) is discovered, its corresponding-source obligation evaluated, and the Correlix-retained artifact checksum-verified. Tracker 238 | `supply-chain` · `OCI image compliance (inherited layers, blocking)`; release mode runs per pushed digest in `publish-images` | 🟢 AUTOMATED |
| 1.17 | Fuzz corpus exploration | `fuzz-nightly` (scheduled, not per-PR) | 🟢 AUTOMATED |
| 1.18 | **`go.mod` direct requires ⊆ the CLAUDE.md §6 allowlist** | — | 🔴 MISSING — human review only |

> **Every one of the gates above also runs on the TAG.** `.github/workflows/release-gate.yml`
> is a `workflow_call`-only workflow that calls `backend-ci`, `frontend-ci`, `correlation-ci`,
> `supply-chain`, `ingest-contract-ci`, `telemetry-catalog-ci` and `fresh-install-integrity`;
> `publish-images.yml` and `release-bundle.yml` run it as their first job and `needs:` it from
> every other job. `workflow_call` takes no `paths:` filter, so a tag runs **all** of it against
> the tag's exact commit. See `docs/runbooks/ci-branch-protection.md` §2.1.

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
| 4.1 | **Offline customer bundle** — images + source + `MANIFEST` + `SHA256SUMS` + the GUI installer, with licensing guards (must contain `apache/kafka:` and `valkey/valkey:`; must **not** contain redpanda/redis/prometheus) and `LAB_PATHS` scrubbing | `bash scripts/make-installer.sh` → `dist/correlix-<version>/`; `release-bundle.yml` on a `v*.*.*` tag, **behind `needs: gate`** | 🟢 AUTOMATED on tag |
| 4.2 | Bundle smoke test — `sha256sum -c`, `zstd -t`, git-SHA lockstep against MANIFEST, full `docker load` round-trip with `docker image inspect` per MANIFEST image, source tarball extracted and `preflight-install.py` run inside it | `release-bundle.yml` | 🟢 AUTOMATED |
| 4.2a | **The licensing assertions actually fail the build.** They were written `! grep -qi redpanda MANIFEST`; under `set -e` bash never exits on a pipeline whose value is inverted with `!`, so a bundle carrying redpanda/redis/prometheus passed the smoke test **silently**. Replaced with a `refute` helper that prints the offending line and `exit 1`s (2026-09-04). | `release-bundle.yml` | 🟢 AUTOMATED *(fixed)* |
| 4.3 | Bundle staleness gate | `make bundle-status` / `scripts/bundle-staleness.sh` (warn-only pre-push hook) | 🟢 AUTOMATED (advisory) |
| 4.4 | **GHCR images** — `netops-{api,correlation,nginx,frontend}`, tagged `semver`, `major.minor`, `sha` | `publish-images.yml` on a `v*.*.*` tag, **behind `needs: gate`** | 🟢 AUTOMATED on tag *(gate added 2026-09-04 — it previously pushed with no test job gating it)* |
| 4.5 | **Build provenance** — `actions/attest-build-provenance`, keyless Sigstore, `push-to-registry: true` | `publish-images.yml` | 🟢 AUTOMATED on tag — **never executed**, because no `v*` tag has ever existed |
| 4.6 | Per-image CycloneDX SBOM | `anchore/sbom-action` in `publish-images.yml` | 🟢 AUTOMATED on tag — never executed |
| 4.7 | **Committed source SBOM** — CycloneDX for Go vendor, both npm trees, the pip lock and every image pin | `python3 scripts/sbom.py` → `docs/sbom/`; verified by `scripts/sbom.py --check` and `tests/test_sbom.py` | 🟢 AUTOMATED *(new)* |
| 4.8 | **Bundle signature.** `make-installer.sh` GPG-signs `SHA256SUMS` → `SHA256SUMS.asc` when `CORRELIX_SIGNING_KEY` is set, and `install-correlix.sh` treats a bad signature as fatal. **`release-bundle.yml` never sets the key**, so every bundle ever produced is checksum-only. | — | 🔴 MISSING — see 👤 6.4 |
| 4.9 | **Container image signing (cosign / Notation).** Zero references repo-wide. Provenance attestation (4.5) is adjacent but is not a signature over the image. | — | 🔴 MISSING |
| 4.10 | `release-bundle.yml` artifact name, MANIFEST `profile:` line and release notes all say **full**, and the smoke step asserts the MANIFEST agrees — they can no longer drift silently. | `release-bundle.yml` | 🟢 fixed 2026-09-03 |
| 4.11 | VM appliance images (qcow2/vmdk/vhdx) | `scripts/make-vm-image.sh` | 🟡 MANUAL |
| 4.12 | **No root `.dockerignore`** while 8 services build with `context: ../..` (tracker 193) | — | 🔴 MISSING (build-size, not correctness) |
| 4.14 | **GPL/LGPL corresponding source ships with the bundle.** Owner decision 2026-09-04 (licence audit D2): the source obligation is discharged under GPL-2.0 §3(a) by SHIPPING the source, not by a three-year written offer. `make-installer.sh` mirrors the pinned upstream tarball into `source-offer/`, verifies its sha256 against `scripts/source-mirror.json`, and FAILS THE BUILD on any fetch or integrity failure. **Generalised 2026-09-05 (tracker 238):** the same table now also carries the source for copyleft software INHERITED from base-image layers — BusyBox is named in no Dockerfile of ours but is in every frontend/nginx image we ship. Verify on the produced bundle that EVERY pin-table component is present, hashes to its pin and appears in `SHA256SUMS` (the release-bundle smoke does this for the whole table, not one component), and that `source-offer/README` states the terms. Re-mirror whenever a pinned image or base image version changes | `bash scripts/make-installer.sh` (dry run: `--source-offer-only`); asserted in `release-bundle.yml`; contract guarded by `tests/test_source_offer.py` | 🟢 AUTOMATED (build-time fail-closed) |
| 4.15 | **Gotenberg can no longer reach a bundle.** The `pdf` profile hides PDFtk (GPL-2.0+), a proprietary Microsoft font EULA and Google Chrome. Was a written convention; now a build failure if the image appears in the base set or any add-on pack | `scripts/make-installer.sh` licensing guards | 🟢 AUTOMATED *(2026-09-04)* |
| 4.13 | **Pipeline debugger in the bundle** — `correlix-debug` is built (§7c), self-tested on the build host (`--help` must exit 0 before the build continues) and covered by `SHA256SUMS`. Verify on the produced bundle: `cd dist/correlix-<version> && ./correlix-debug --help` (exit 0) and `grep correlix-debug SHA256SUMS` | `bash scripts/make-installer.sh`; contract guarded by `tests/test_pipeline_debug_ship.py` | 🟢 AUTOMATED (build-time self-test) + 🟡 MANUAL on the published bundle |

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
| 5.7 | **Third-party licence obligations inventory** — every distributed component, its licence, the distribution unit it ships in, the licence texts and the written source offer | `docs/THIRD_PARTY_LICENSES.md` (GENERATED by `python3 scripts/license-audit.py --notices` from `scripts/license-data.json`); gated by `python3 scripts/license-audit.py --check` and `tests/test_license_audit.py`; served by the product at `/licenses/`; shipped as the bundle's `LICENSES.md`; summarised for customers at `docs-portal/docs/deploy/third-party-components.md` | 🟢 present *(2026-09-03; owner decisions D1–D6 recorded 2026-09-04)* |
| 5.7a | **Owner licence decisions are recorded, not pending.** `python3 scripts/license-audit.py` prints every acknowledged finding still awaiting an owner call. The list must be empty, or every remaining entry must be one the owner has knowingly left open | `python3 scripts/license-audit.py` | 🟢 D1–D6 DECIDED 2026-09-04 — see `docs/security/LICENSE_AUDIT_2026-09-03.md` §4 |
| 5.7b | **Red Hat UBI EULA acceptance is stated in the ship set.** Keycloak ships in the core bundle on a UBI base, which is not an OSS licence. The acceptance AND the terms URL (<https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf>) must appear in the generated notices, in `NOTICE`, on the customer docs page, and in the release notes | `grep -l 'Universal Base Image' docs/THIRD_PARTY_LICENSES.md NOTICE docs-portal/docs/deploy/third-party-components.md docs/RELEASE_NOTES_v0.9.0-rc1.md`; automated by `tests/test_license_audit.py::test_the_ubi_eula_reaches_every_ship_set_surface` | 🟢 present *(2026-09-04; release notes + test added 2026-09-05)* |
| 5.8 | **Project licence declared.** Apache-2.0 open core with commercial add-ons under `LicenseRef-Correlix-Enterprise` (owner, 2026-09-04). `LICENSE` (the mixed-licence notice), `LICENSES/Apache-2.0.txt`, `LICENSES/Correlix-Enterprise.txt` and `LICENSING.md` ship at BOTH repository roots, byte-identical; `CONTRIBUTING.md` carries the CLA requirement | `LICENSE`, `LICENSES/`, `LICENSING.md`, `CONTRIBUTING.md`, `NetOps_Observability/licensing-policy.json` | 🟢 present *(2026-09-04)* |
| 5.8a | **Licensing consistency is green.** One canonical sentence in all nine places that state the licence, every top-level directory classified exactly once, every Correlix image labelled, core never importing commercial code | `python3 -m pytest tests/test_licensing_consistency.py` and `python3 scripts/licensing-gate.py` (checks A–H) | 🟢 AUTOMATED |
| 5.8b | **`LICENSING.md` is not stale.** It is GENERATED from `licensing-policy.json`; a hand edit enforces nothing | `python3 scripts/gen-licensing-map.py --check` | 🟢 AUTOMATED |
| 5.8c | 👤 **The Correlix Enterprise License text does not exist.** `LICENSES/Correlix-Enterprise.txt` is a placeholder, yet `src/backend/internal/ldap` is already marked with the identifier — those files are licensed to nobody. Engineering must not draft, paraphrase or borrow commercial licence terms | `python3 scripts/licensing-gate.py --release` fails while the placeholder is present | 🔴 BLOCKING a tag — 👤 owner: obtain the text from counsel |
| 5.8d | 👤 **No CLA signing process.** `CONTRIBUTING.md` states the requirement and says honestly that the mechanism is undecided. Open core depends on the right to relicense contributed code; without a signed CLA that right is not held | same `--release` gate (`CLA-PROCESS-TBD` marker) | 🔴 BLOCKING external contributions — 👤 owner decision |
| 5.8e | **Directories that still mix core and commercial code** are named in `LICENSING.md` § Still mixed and stay Apache-2.0 in full until extracted to `src/backend/ee/` | tracker row 240 | 🟡 tracked |
| 5.9 | **No `VERSION` file.** Version comes from `git describe --tags --match 'v[0-9]*'`, falling back to a date stamp. Once a `v*` tag exists this resolves correctly everywhere (bundle name, `/admin/version`, SBOM metadata). | — | 🟡 by design |
| 5.10 | `docs/runbooks/ci-branch-protection.md` §6 said container CVE scanning, SBOM and gitleaks were "not yet wired" — all three shipped | `docs/runbooks/ci-branch-protection.md` §6 | 🟢 corrected 2026-09-04 (open remainder named: image signing, `SHA256SUMS.asc`) |

---

## 6. 👤 Owner-only — the ship sequence

Nothing below is delegable, and the **order is load-bearing**. 6.5 is the point of no return:
`release-bundle.yml` and `publish-images.yml` both fire off the tag, and a pushed image digest
cannot be unpublished from a customer's cache.

> **What changed 2026-09-04.** This section used to open with *"6.1 is the point of no return:
> `publish-images.yml` pushes to GHCR with no test job gating it."* That is fixed — both
> publishing workflows now `needs:` `release-gate.yml`, which runs the full blocking gate against
> the tag's own commit (§1). The tag can still publish the wrong *content*; it can no longer
> publish **untested** content.

### 6.1 Add the tag gate — 🟢 DONE (verify, do not re-do)

```bash
# The gate must exist and be wired before the ruleset is set, because the ruleset's
# check names and the gate's call list are one list (runbook §1).
python3 -m pytest NetOps_Observability/tests/test_required_checks_consistency.py -q
actionlint            # .github/workflows/ must be clean
```

### 6.2 Correct branch protection — the required job names

Apply the **eighteen** names from `docs/runbooks/ci-branch-protection.md` §1.1. They are the
jobs' real `name:` fields; a required check that names no real job pins every PR at
*"Expected — Waiting for status to be reported"* forever. Requires `gh auth login` **as a repo
admin** — this cannot be done from CI or by an agent.

```bash
gh api -X PUT repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "build · vet · test · race"},
      {"context": "offline vendor build (blocking)"},
      {"context": "Postgres integration (blocking)"},
      {"context": "govulncheck (blocking)"},
      {"context": "staticcheck + gosec (crypto/trust packages, blocking)"},
      {"context": "golangci-lint (repo-wide, blocking)"},
      {"context": "pytest (blocking)"},
      {"context": "ruff · bandit · mypy · pip-audit (blocking)"},
      {"context": "tsc -b && vite build (blocking)"},
      {"context": "npm audit (blocking)"},
      {"context": "Playwright E2E (blocking)"},
      {"context": "panel↔metric contract (blocking)"},
      {"context": "Trivy filesystem scan (blocking)"},
      {"context": "gitleaks secret scan (blocking, full history)"},
      {"context": "CIS-Docker policy gate (blocking)"},
      {"context": "Third-party licence gate (blocking)"},
      {"context": "OCI image compliance (inherited layers, blocking)"},
      {"context": "ingest + storage contracts (blocking)"},
      {"context": "invariants · conformance · pytest (blocking)"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

# Verify — this list must equal runbook §1.1, in order.
gh api repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  | jq -r '.required_status_checks.checks[].context'
```

A check appears in GitHub's picker only **after it has run at least once**. If the `PUT` is
rejected for an unknown context, open one PR first so every check reports, then re-run.
Optionally add the three `fresh-install-integrity` checks (runbook §1.2) — the TLS boot leg is
~45 min per PR. They run on the tag either way.

### 6.3 Merge to `main`

All of this ships from `feat/observability-platform`. Tagging anything else makes
`release-bundle.yml`'s `branches: [main]` leg and every "on main" assumption wrong (§0.2). Merge
through a PR so the ruleset from 6.2 is exercised at least once before it guards a release.

```bash
git checkout main && git pull --ff-only
gh pr create --base main --head feat/observability-platform   # then merge when all 18 are green
git status --porcelain    # must be empty at the commit you are about to tag (§0.3)
```

### 6.4 Sign the tag

Annotated **and GPG-signed**, on `main`, at the commit whose CI is green. Until 6.6 exists the
tag is the only signed link between the source and the artifacts.

```bash
git tag -s -a v0.9.0-rc1 -m "Correlix v0.9.0-rc1"
git tag -v v0.9.0-rc1            # verify the signature before it leaves the machine
```

### 6.5 Push the tag — the point of no return

```bash
git push origin v0.9.0-rc1
```

Both publishing workflows start. Each runs `release-gate.yml` first (the full blocking gate on
this commit, ~45–60 min because of the TLS install leg) and only then:

- `release-bundle.yml` → builds the full bundle, smoke-tests it, `gh release create --verify-tag`,
  `gh release upload --clobber`.
- `publish-images.yml` → 4 images to **private** GHCR + keyless SLSA build provenance +
  per-image CycloneDX SBOM.

If a gate fails, nothing is published and the tag stands with no artifacts — delete the tag,
fix, re-tag. Watch it: `gh run watch` / `gh run list --workflow=publish-images.yml`.

### 6.6 Grant registry access and publish the release page

| | Step | Command / place |
|---|---|---|
| 6.6a | **Grant GHCR access.** Packages are private on first push. Decide public versus per-customer read tokens; the correlation image carries readable Python source, so "public" is a disclosure decision, not a convenience one. | GitHub → Packages → `netops-{api,correlation,nginx,frontend}` → Package settings |
| 6.6b | **Write the release page** from `docs/RELEASE_NOTES_v0.9.0-rc1.md`. Mark it **pre-release** while the tag carries `-rc1`. | GitHub → Releases |
| 6.6c | Verify the provenance a customer would check: `gh attestation verify oci://ghcr.io/raorakurty/netops-api@<digest> --owner RaoRakurty` | local |

### 6.7 Still owner-only, not sequenced with the tag

| | Step | Command / place |
|---|---|---|
| 6.7a | **Decide the signing story and wire it.** Three gaps: (a) set `CORRELIX_SIGNING_KEY` in `release-bundle.yml` so `SHA256SUMS.asc` is produced — the fail-closed verifier in `install-correlix.sh` already exists; (b) decide whether cosign signs the GHCR images or keyless build provenance is the whole story; (c) publish the public key where customers can fetch it. | repo secrets + `release-bundle.yml` |
| 6.7b | **Ratify the open exceptions** the release notes disclose: tracker 212 (gnmic→Kafka plaintext, `review_by 2026-12-02`), O10 (api→gotenberg plaintext), and the deployment of tracker 209 (OpenSearch flood-stage fix — built, deploy pending owner approval). | — |
| 6.7c | **Green-light the qualification run** (§3.1). ~1 h of exclusive rig time. Dropping `-rc1` depends on it. | — |
| 6.7d | `/code-review ultra` on the release diff. | — |

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

**Blocking a `-rc1` tag (all small, and all owner-only now):**
1. 👤 §6.2 apply the branch ruleset — the 18 required checks. The runbook and the workflows
   agree and are machine-checked; GitHub's ruleset is the half that is not in the repo.
2. 👤 §6.3 the work is on `feat/observability-platform`, not `main`.

Cleared since the last revision: the runbook no longer names a job that does not exist (§0.1);
`release-bundle.yml` no longer labels a full bundle `core` (§4.10); and **the tag now has a test
gate at all** — `publish-images.yml` and `release-bundle.yml` `needs:` `release-gate.yml`, whose
licensing assertions also actually fail the build now (§4.2a).

**Blocking a *final* tag:**
4. §3.1 the reference-capacity regression has never been executed.
5. §4.8 no bundle is signed, though both the signer and the fail-closed verifier already exist.
6. §4.9 no image signing story.
7. §5.8c the Correlix Enterprise License text is a placeholder while code is already marked with its identifier, and §5.8d the CLA has no signing process. Both are owner actions; `scripts/licensing-gate.py --release` fails on each. (The `LICENSE` files themselves landed 2026-09-04.)
8. §2.9 a clean clone cannot build the frontend image without an undocumented-at-the-failure-point
   `npm run build` (bundle path unaffected).

**Should not block, but must be disclosed** — and is, in the release notes: the file-versus-relational
backend limitation, the flags that default off, the `PARTIAL` OpenSearch snapshot, and the rig-gate
invariants that are "proven on a named run" rather than regression-proof.
