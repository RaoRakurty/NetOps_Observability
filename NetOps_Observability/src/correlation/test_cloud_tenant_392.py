# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 392 — a cloud metric sample's tenant comes from the cloud inventory,
never from the DEVICE registry.

THE DEFECT: a cloud sample names its resource twice — `device` is the resource
NAME, `index` the provider's resource id. Vector stamped the tenant by looking
`device` up in device_tenant.csv, and handle_metric verified that claim against
the SAME registry by the SAME name. So once tenant B owned a device named like
tenant A's cloud resource, A's cloud series were stamped and "verified" as B's,
and A's CUSUM anomalies became B's RCA evidence.

THE CONTRACT pinned here: for signal_family "cloud_resource" the identity is
`cloud:<index>` (rows the api writes from the cloud inventory, Go
internal/cloudtenant), and the lane is REGISTRY-ANCHORED — a resource the
inventory does not list (or two tenants list) is refused, never the platform
tenant. Every other metric is unchanged.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

import main
from episodes import EpisodeEvent


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.inserts.append((table, list(rows)))
        return True


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """B owns a DEVICE named `web-1`; `web-1` is also the NAME of A's cloud
    resource `i-a`. `i-p` is a platform-owned resource (single-tenant install)."""
    csv_path = tmp_path / "device_tenant.csv"
    csv_path.write_text(
        "identity,tenant_id\n"
        "web-1,t_b\n"
        "cloud:i-a,t_a\n"
        "cloud:i-p,\n"
    )
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(csv_path))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)
    return csv_path


@pytest.fixture
def lane(monkeypatch):
    """Capture the tenant each accepted sample reaches the episode detector with."""
    seen: list[str] = []

    def fake_observe(tenant, entity_id, metric, ts, value, clock_quality="unknown", **_kw):
        seen.append(tenant)
        return EpisodeEvent(phase="onset", key=(tenant, entity_id, metric), onset_ts=ts,
                            onset_uncertainty_s=30.0, value=value, baseline=1.0,
                            deviation=8.0, peak_deviation=8.0, integral=100.0)

    monkeypatch.setattr(main.DETECTOR, "observe", fake_observe)
    monkeypatch.setattr(main, "ch", RecordingCH())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "METRICS_ACCEPTED", 0)
    monkeypatch.setattr(main, "METRICS_DROPPED", 0)
    main.TENANT_REFUSALS.clear()
    main.QUARANTINE.clear()
    yield seen
    main.TENANT_REFUSALS.clear()
    main.QUARANTINE.clear()


def cloud_sample(**over) -> dict:
    """The exact shape deployment/docker/cloud-ingest/cloud_events.metric_event
    emits, plus the tenant Vector stamps from the cloud row."""
    ev = {
        "observer_type": "cloud_provider",
        "modality_class": "device_telemetry",
        "collection_path": "cloudwatch_api",
        "device": "web-1",       # the resource NAME
        "vendor": "aws",
        "index": "i-a",          # the provider's resource id
        "signal_family": "cloud_resource",
        "metric": "cloud_cpu_utilization",
        "value": 97.0,
        "unit": "percent",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    ev.update(over)
    return ev


def test_a_cloud_sample_belongs_to_the_resource_owner_not_the_same_named_device(registry, lane):
    run(main.handle_metric(cloud_sample(tenant_id="t_a")))
    assert main.METRICS_ACCEPTED == 1
    assert lane == ["t_a"]


def test_no_claim_still_resolves_the_resource_owner(registry, lane):
    # Before 392 this resolved through the device registry: `web-1` → t_b.
    run(main.handle_metric(cloud_sample()))
    assert lane == ["t_a"]


def test_the_old_device_name_stamp_is_refused_and_quarantined(registry, lane):
    # What the pre-392 Vector stamped (device_tenant by `device`). The old engine
    # "verified" it against the same name and accepted A's series as B's.
    run(main.handle_metric(cloud_sample(tenant_id="t_b")))
    assert lane == []
    assert main.METRICS_DROPPED == 1
    assert main.METRICS_ACCEPTED == 0


def test_a_resource_in_no_inventory_is_unattributable_never_platform(registry, lane):
    run(main.handle_metric(cloud_sample(index="i-unknown")))
    assert lane == []
    assert main.METRICS_DROPPED == 1


def test_a_sample_without_a_resource_id_is_refused(registry, lane):
    run(main.handle_metric(cloud_sample(index="")))
    assert lane == []
    assert main.METRICS_DROPPED == 1


def test_a_platform_owned_resource_stays_platform(registry, lane):
    run(main.handle_metric(cloud_sample(device="db-1", index="i-p")))
    assert lane == ["global"]


def test_device_metrics_still_resolve_through_the_device_registry(registry, lane):
    # Non-cloud lanes are untouched: B's own device sample is B's.
    run(main.handle_metric({
        "observer_type": "collector", "modality_class": "device_telemetry",
        "collection_path": "snmp_poll", "device": "web-1", "vendor": "cisco",
        "signal_family": "device_resource", "metric": "device_cpu_percent",
        "value": 91.0, "unit": "percent", "ts": datetime.now(timezone.utc).isoformat(),
    }))
    assert lane == ["t_b"]


def test_the_cloud_key_matches_the_go_and_vector_spelling():
    assert main.CLOUD_IDENTITY_PREFIX == "cloud:"
    assert main.CLOUD_SIGNAL_FAMILY == "cloud_resource"
