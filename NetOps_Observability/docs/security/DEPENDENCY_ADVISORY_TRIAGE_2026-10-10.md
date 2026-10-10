# Dependency advisory triage — 2026-10-10

**Why:** new advisory-database entries turned three blocking gates red on every
branch at once (seen on PR #20 and PR #21, base `main` @ `bec0957`, neither of
which touched a dependency):

| Gate | Finding |
|---|---|
| `frontend-ci` → `npm audit --audit-level=high` | `source-map-js` 1.2.1 — GHSA-68fv-2mgg-jv7q (high) |
| `supply-chain` → Trivy fs | `golang.org/x/net` v0.57.0 — CVE-2026-78669 (high); docs-portal `compression`, `proxy-addr`, `shell-quote`, `tinypool` (1 high, 4 critical) |
| `backend-ci` → `govulncheck` | 12 Go **standard-library** advisories in go1.26.8, fixed in go1.26.9 (e.g. GO-2026-6599 / GO-2026-6600, `html/template`) |

**Outcome:** `npm audit` and Trivy are cleared by this change. **`govulncheck`
is not** — see §4 for why, and for exactly what clearing it needs.

---

## 1. `src/backend` — `golang.org/x/net` v0.57.0 → v0.60.0

| Module | Was | Now | Why |
|---|---|---|---|
| `golang.org/x/net` | v0.57.0 | **v0.60.0** | CVE-2026-78669 (Trivy HIGH): HTTP/2 SETTINGS-flood DoS in `x/net/http2`. First fixed release. |
| `golang.org/x/crypto` | v0.56.0 | v0.57.0 | the minimum x/net v0.60.0 requires |
| `golang.org/x/sys` | v0.47.0 | v0.48.0 | required by the above |
| `golang.org/x/text` | v0.41.0 | v0.42.0 | required by the above |
| `golang.org/x/sync` | v0.22.0 | v0.23.0 | required by the above |

Reachability: the backend imports only `ipv4`, `ipv6`, `icmp`, `bpf` (and their
`internal/*`) from x/net; `http2` is not imported and is not even vendored. The
bump is still required: the Trivy gate scans the module graph, not the call
graph. Every bumped module declares `go 1.26.0`, so the language version, the
`toolchain go1.26.8` line and the gate-tool pins are all unchanged. CLAUDE.md §6
allowlist rows for x/crypto and x/net record the new pins.

**Verified:** `go mod tidy && go mod vendor` under go1.26.8 ·
`GOFLAGS=-mod=vendor GOPROXY=off go build ./...` (the offline contract) ·
`go vet ./...` · `go test ./...` · the three satellite modules build.

## 2. `docs-portal` — four `overrides` floors

| Package | Was | Now | Advisory | Parent → range |
|---|---|---|---|---|
| `compression` | 1.8.1 | **1.8.2** | CVE-2026-87776 (high) | `webpack-dev-server` → `^1.8.1` |
| `proxy-addr` | 2.0.7 | **2.0.8** | CVE-2026-90711 (critical) | `express@4` → `~2.0.7` |
| `shell-quote` | 1.9.0 | **1.12.0** | CVE-2026-102422 (critical) | `launch-editor` → `^1.8.4` |
| `tinypool` | 1.1.1 | **2.2.0** | CVE-2026-104848 / -104849 (critical) | `@docusaurus/core` → `^1.0.2` |

All four sit in the parent's range except `tinypool`, but `npm update` does not
reach these transitive packages, so each gets an `overrides` floor, the same way
`joi`, `brace-expansion` and `fast-uri` were handled on 2026-10-04. The floor
also stops a later lock regeneration from slipping back.

`tinypool` is a **major** (1 → 2) outside Docusaurus's declared range, so it was
checked rather than assumed:
- Docusaurus imports it only in `ssgExecutor.js`, and only when
  `future.faster.ssgWorkerThreads` is set. `docusaurus.config.js` does not set
  it, so the portal build never loads tinypool.
- Should someone turn it on: tinypool 2.x still exports a default `Tinypool`
  class and still accepts every option Docusaurus passes (`filename`,
  `minThreads`, `maxThreads`, `concurrentTasksPerWorker`, `runtime`,
  `isolateWorkers`, `workerData`, `maxMemoryLimitBeforeRecycle`,
  `resourceLimits`) and still sets `process.__tinypool_state__` in the worker.
- tinypool 2.x needs Node `^20 || >=22`; the portal already requires `>=20.0`.

**Verified:** `npm ci` · `npm ls --all` exit 0 (no invalid trees) ·
`npm run build`: no warnings, 170 HTML pages · `npm test` 10/13 pass, the same
three failures as on `main` (pre-existing voice/prose rules).

## 3. `src/frontend` — `source-map-js` 1.2.1 → 1.2.2

`npm audit fix`, lockfile only, one package (vite/postcss build-time
dependency; not in the bundle). **Verified:** `npm audit` 0 · `npm run build` ·
`npx vitest run` 277 files / 4771 tests, identical to `main`.

## 4. NOT cleared here — Go toolchain 1.26.8 → 1.26.9 (`govulncheck`)

The 12 findings are in the Go standard library, so the only fix is building
with go1.26.9. A patch-level raise moves nine sites together
(`docs/runbooks/patch-train.md`, "Toolchain raise playbook"). One of them is the
three `golang:1.26.N-alpine@sha256:…` builder pins, and
`tests/test_toolchain_pin.py` requires those to match `go.mod`'s toolchain line.

Changing a pinned digest trips `tests/test_oci_digest_lock.py`, by design.
`docs/compliance/OCI_SOURCE_COMPLIANCE.md` §13 then requires a fresh compliance
evaluation of the four shipped images, and forbids hand-editing
`docs/compliance/oci-inventory.json`:

1. rebuild the images;
2. Syft-scan them;
3. materialise the corresponding-source offer (`scripts/source-archive.py
   materialise --all` + `make-installer.sh --source-offer-only`);
4. re-evaluate, regenerate the inventory, re-review the register.

That could not be completed in the environment this change was prepared in.
Its egress policy refused (HTTP 403 at the proxy):
- the Alpine package CDN (`apk add` in `Dockerfile.correlation`);
- the pinned upstream source hosts in `scripts/source-mirror.json`:
  `busybox.net`, `distfiles.alpinelinux.org`, `gitlab.alpinelinux.org`,
  `ftp.gnu.org`, `musl.libc.org`, `deb.debian.org`, `snapshot.debian.org`,
  `gnupg.org`, `dev.gentoo.org`, `git.kernel.org`.

The netops-api, frontend and nginx images did build and Syft is available, so
only the network blocks it. **Hand-editing the inventory to make the lock test
pass would be exactly the false claim the lock exists to prevent, so it was not
done.**

The work that was done and verified, and can be reused:
- `golang:1.26.9-alpine` index digest =
  `sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade`.
  Three independent sources agree: the registry via mirror.gcr.io,
  docker-library/repo-info, and `docker pull`'s RepoDigest.
- With that digest and go1.26.9, the backend builds offline, vets, and the
  satellite modules build.

**To finish it**, on a host with that egress (or in this cloud environment once
those hosts are allowed):
1. Run the playbook's nine sites: go1.26.9 in `src/backend/go.mod`,
   `backend-ci.yml` and `fuzz-nightly.yml` `GO_VERSION`, the three Dockerfile
   pins to the digest above, and the three satellite `go.mod` files. The gate
   tools stay as they are: same minor, `go 1.26.0` unchanged.
2. Run OCI_SOURCE_COMPLIANCE.md §10 steps 1–7, then
   `python3 -m pytest tests/test_toolchain_pin.py tests/test_oci_digest_lock.py tests/test_oci_compliance.py`.

Until then `govulncheck (blocking)` stays red on every branch, as it already was.

## 5. Records

- `docs/sbom/` regenerated with `scripts/sbom.py`; `--check` reports all 6
  documents current. `pip-correlation.cdx.json` changes only in its
  commit-derived metadata.
- Trivy 0.70.0 (the CI version), vuln scanner, CI flags (`CRITICAL,HIGH`,
  `--ignore-unfixed`, `.trivyignore.yaml`) over the repo root: **exit 0**. No
  ignore entry was added.
- `tests/test_toolchain_pin.py`, `test_sbom.py`, `test_oci_digest_lock.py`,
  `test_oci_compliance.py`: 108 passed.
