# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""A status gauge must be ONE series whose value changes — never a series per status.

2026-10-17 (lab): opensearch_cluster_status carried a `status_text` tag, so a
red→yellow recovery started a new series while the old `red` one stayed inside
VictoriaMetrics' 5-minute lookback. max() — OpenSearchClusterRed and
deploy-qualify Q9 — kept reading RED for ~5 minutes after the cluster had
recovered. The numeric value already encodes the status.
"""
import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = ("deployment/docker/vector/vector.yaml", "deployment/helm/correlix/files/vector/vector.yaml")


def _metrics(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for name, t in (cfg.get("transforms") or {}).items():
        if t.get("type") == "log_to_metric":
            for m in t.get("metrics") or []:
                yield name, m


def test_cluster_status_gauge_has_no_status_valued_tag():
    for path in VECTORS:
        found = [m for _, m in _metrics(path) if m.get("name") == "opensearch_cluster_status"]
        assert found, f"{path}: opensearch_cluster_status is no longer emitted"
        for m in found:
            tags = m.get("tags") or {}
            assert "status_text" not in tags, f"{path}: status_text splits the gauge into one series per status"
            assert not any("status" in str(v) for v in tags.values()), (path, tags)


def test_rules_do_not_template_the_removed_label():
    for p in ("src/config/rules.yaml", "src/config/rules-scale-slo.yaml",
              "deployment/helm/correlix/files/config/rules.yaml",
              "deployment/helm/correlix/files/config/rules-scale-slo.yaml"):
        with open(os.path.join(ROOT, p), encoding="utf-8") as fh:
            assert "$labels.status_text" not in fh.read(), p
