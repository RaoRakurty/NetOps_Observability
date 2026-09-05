# Inherited-layer regression fixtures (tracker 238)

`Dockerfile.inherited` is the whole point of tracker 238 in three lines: a pinned
Alpine base, one `COPY`, and nothing else. It installs no BusyBox, mentions no
BusyBox, and declares no dependency — yet the image it produces contains
`busybox`, `busybox-binsh` and `ssl_client`, all **GPL-2.0-only**, inherited from
the base image's layers.

`scripts/oci-compliance.py` must find them anyway. If a change to the discovery
path ever stops it doing so, `tests/test_oci_compliance.py` fails here rather
than in a customer's compliance review.

`Dockerfile.inherited-other-version` pins **Alpine 3.20**, whose BusyBox is
`1.36.1-r29` rather than `1.37.0-r12`. The retained source artifact is for
1.37.0, so this image must FAIL: a version-blind match would ship the wrong
source and call it compliance.

`USER nobody` is present only to satisfy the repository's container-posture
scanners (AVD-DS-0002). These images are never built for deployment, never
published and never shipped — they exist to be scanned.

## The checked-in scans

`sbom-a321.cdx.json` and `sbom-a320.cdx.json` are REAL Syft output
(`anchore/syft:v1.18.1`, CycloneDX JSON) from the two images above, and
`base-layers-*.txt` are the pinned bases' `RootFS.Layers`. They are checked in so
the regression suite runs offline — no Docker daemon, no network, no scanner.
`image-id-*.txt` records which image each scan came from.

`.github/workflows/supply-chain.yml` additionally builds and scans
`Dockerfile.inherited` live on every PR, so the fixtures cannot quietly drift
away from what the tool would see today.

Regenerating them is documented in `docs/compliance/OCI_SOURCE_COMPLIANCE.md` §10.
