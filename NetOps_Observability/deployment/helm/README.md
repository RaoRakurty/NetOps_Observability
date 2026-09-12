# Correlix Helm chart

`correlix/` packages the whole Docker-Compose stack for Kubernetes.

**Read `docs/DEPLOY_KUBERNETES.md` first.** It carries the install, secrets,
storage, upgrade and security guidance, and — the part that matters most — an
explicit statement of what is proven: the chart is **rendered and validated**,
not cluster-proven.

```bash
helm lint deployment/helm/correlix
helm template correlix deployment/helm/correlix | kubeconform -strict -kubernetes-version 1.30.0
pytest tests/test_helm_chart.py            # the gate CI runs
```

`stage-configs.sh` refreshes `correlix/files/` — the chart's checked-in mirror
of the canonical stack configuration. Helm cannot read a file outside the chart
root, so those copies are what the ConfigMaps render from. **Re-run it whenever
you change `src/config/*`, a Vector config, the ClickHouse init SQL, the nginx
gateway config, the OpenSearch ISM script or the Kafka ACL matrix**; the pytest
gate fails until you do. Never edit `correlix/files/` by hand.

```bash
bash deployment/helm/stage-configs.sh          # write
bash deployment/helm/stage-configs.sh --check  # what CI runs
```
