# Vendored Kubernetes JSON schemas for the chart gate

`tests/test_helm_chart.py::test_kubeconform_validates_rendered_manifests` used to
let kubeconform download these schemas from raw.githubusercontent.com at test
time. One failed download red-lined the blocking `helm chart` job on #267
(head `dd13fcd29`; a rerun passed). A gate that depends on the network is a
flake source and cannot run offline, so the schemas the chart can render are
pinned here and kubeconform reads ONLY this directory (`-schema-location`, no
remote fallback). `test_kubeconform_reads_only_vendored_schemas` guards that.

## Provenance

- Source: <https://github.com/yannh/kubernetes-json-schema>
- Pinned commit: `f82dcba5de3856cb8b0e1ae87705480528cea81b` (2024-04-19, the last
  commit touching `v1.30.0-standalone-strict/`)
- Path: `v1.30.0-standalone-strict/` — Kubernetes 1.30.0 (the chart's
  `KUBE_VERSION`), "standalone" = every `$ref` inlined, "strict" = no extra
  properties (what kubeconform's `-strict` selects)
- URL form: `https://raw.githubusercontent.com/yannh/kubernetes-json-schema/<commit>/v1.30.0-standalone-strict/<file>`
- Licence: Apache-2.0 (the repository's `LICENSE`: "Kubernetes JSON Schema,
  Copyright (C) 2017 Gareth Rushgrove, Copyright (C) 2017 Yanh Hamon"). The
  schemas are generated from the Kubernetes OpenAPI spec (Apache-2.0). Test
  data only: in no image, but present in the customer source archive (it is a
  git archive of the repository and `tests/` is not export-ignored), so the
  attribution is in `NOTICE`.

| File | sha256 |
|---|---|
| configmap-v1.json | `e0eaddebd677c08aa092b2da2264d86ac4fc34eed112b9fac2945b3f00c1e9b1` |
| cronjob-batch-v1.json | `b656c7b2da7088c0e0e3324be481613e3828f2d8991772ca4857467ba3b595b0` |
| daemonset-apps-v1.json | `236f67158bc740a7c301840d1bd02c7f3cafe354ecd3d768348da663f5475be8` |
| deployment-apps-v1.json | `eec9281764590b81aae81f0571790a1733e886585093e389f6bc03e233809763` |
| ingress-networking-v1.json | `231dc74ae89766305b110d34730803434f9b4f29732fe3e083c7d936034d6740` |
| job-batch-v1.json | `10a36c2ac43f955296a8f311bc950eab81f9285ae99a12c79e059f1bb91c10c9` |
| namespace-v1.json | `138cced5c47a317a9cce78a59a0d5f9e330f9b8a40f48077f5a3d9a6ce289e52` |
| networkpolicy-networking-v1.json | `68f66caa6cb28841e7ab6b2b1cf5ac56085d50730a3813e538dd9204529b5b04` |
| persistentvolumeclaim-v1.json | `237f0dde284c7c5d1eb79ecf90dfea1f786ad7883643351c31cb9a301d0ac7e0` |
| service-v1.json | `4de9eaf03191038e5b82edaed358d91abc474dd375c582d216b951c12934fbed` |
| serviceaccount-v1.json | `30f37eecc08c8793b1b96f954986e48320a7d5c265bf3a00cefd8595c2c63b44` |
| statefulset-apps-v1.json | `c290e27cf5f8e435eafc00f7f74df4dde6bbcaa9d48c502320f0c31bba81fe59` |

The guard test re-checks these digests, so a file edited by hand fails.

## Which kinds, and what is not here

Every native kind a chart template can render (`grep '^kind:' templates/`).
`Certificate` (cert-manager, rendered only when `tls.enabled` and
`certManager.enabled` are both set) is a
CRD and is not vendored: neither gated render (default, `values-lab.yaml`)
produces it. If a gated render ever emits a kind with no file here, kubeconform
fails with "could not find schema" — it is never silently skipped.

## Adding a kind

Fetch the file at the same commit, add its row and digest above (the guard
test reads this table), and keep the commit pinned. To move to a new
Kubernetes version, vendor a new `v<version>-standalone-strict/` directory and
change `KUBE_VERSION` in the test in the same change.
