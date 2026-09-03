# Software Bill of Materials

Generated, committed CycloneDX 1.6 inventories of everything Correlix depends on.

**Regenerate:** `python3 scripts/sbom.py` — always from the repository root of the product tree
(`NetOps_Observability/`). **Verify:** `python3 scripts/sbom.py --check` (exit 1 if stale).

| File | Source of truth | Components (2026-09-03) |
|---|---|---|
| `go-backend.cdx.json` | `src/backend/vendor/modules.txt` + `go.mod` | 10 (9 modules + toolchain) |
| `npm-frontend.cdx.json` | `src/frontend/package-lock.json` | 265 |
| `npm-docs-portal.cdx.json` | `docs-portal/package-lock.json` | 1 203 |
| `pip-correlation.cdx.json` | `src/correlation/requirements.txt` | 27 |
| `container-images.cdx.json` | every `image:` in `deployment/docker/*compose*.yml`, every `FROM` in every Dockerfile | 56 distinct refs |
| `correlix.cdx.json` | the deduplicated union of the five | 1 382 |

## Why this exists next to the CI SBOM

`.github/workflows/supply-chain.yml` already emits a Trivy CycloneDX document — but only as an
ephemeral workflow artifact that expires. You cannot diff it, cite it in release notes, or hand it to
a customer asking what is in the appliance. These files are committed, so:

- a component appearing or changing version is a **reviewable line in a pull request**;
- "what shipped in `v0.9.0`" is answerable from the tag alone;
- `tests/test_sbom.py::test_committed_sbom_matches_the_current_dependency_tree` fails when a
  dependency moves and the SBOM is not regenerated.

This is the *inventory*. The Trivy scan is what resolves CVEs against it — the two are complements,
not alternatives.

## Reading the annotations

Each component carries `properties` beyond the CycloneDX basics:

| Property | Meaning |
|---|---|
| `correlix:class` | which of the five inventories it came from |
| `correlix:direct` | Go only — `true` means a direct `require`, i.e. part of the **CLAUDE.md §6 allowlist surface**. There should be exactly three. |
| `correlix:vendored` | Go only — present in `vendor/`, so it is in the offline build |
| `correlix:dev` | npm only — a build-time dependency, not shipped in the runtime image |
| `correlix:image:digest-pinned` | container images — `false` is an audit finding, not a detail |
| `correlix:origin` | container images — every `file:line(service)` the pin appears at, so a change can be applied everywhere |

## Known finding visible in this data

`container-images.cdx.json` shows **27 of 56** image references not digest-pinned. **22 of those 27
are `compose.offline-images.yml`**, the offline-mirror pull list, which references by tag the same
images `docker-compose.yml` pins by digest. The two files can drift apart silently — the offline
bundle would then ship a different image than the online stack runs, with no error anywhere. Tracked
in `docs/design/PATCH_AUTOMATION_PLAN_2026-09-03.md` §6.3 / §9.3.

The genuinely unpinned Dockerfile bases are `deployment/docker/cloud-ingest/Dockerfile`
(`python:3.12-slim`), `deployment/docker/vm-image-builder/Dockerfile` (`ubuntu:24.04`),
`docker-compose.flowgen.yml` (`python:3.12-slim`) and `scripts/lab/traffic-generator/Dockerfile`.

## Determinism

Same commit + same dependencies ⇒ byte-identical output. The timestamp is the HEAD commit date (or
`SOURCE_DATE_EPOCH`), never "now", and the serial number is derived from a hash of the component set.
A committed artifact that churned on every run would be noise nobody reads — and noise nobody reads
is how a real change slips through.
