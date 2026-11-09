# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stage [1] normalize — a trap from a retained interface address.

A device that has stopped answering SNMP polls may still send traps, from an
interface address rather than its management address. The trap receiver cannot
attribute that source, so handle_snmptrap asks EntityResolver.device_for_ip. The
collector now keeps the device's last-known rows (collectors/if_rows_retention.go);
the rows it exports look exactly like fresh ones, so nothing here changed. These
tests pin that this is enough, end to end, from the exported file:

  rows present      → the trap recovers its device and reaches a tenant
  rows absent       → refused identity_unattributable (the defect)
  address shared    → never guessed, refused the same way
"""
from __future__ import annotations

import asyncio
import json

import pytest

import main

TENANT = "acme"
DEVICE = "cedge-81-11060ae2"
SOURCE = "192.168.200.33"


class RecordingCH:
    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.inserts.append((table, list(rows)))
        return True


def _trap(**over) -> dict:
    ev = {
        "device": "",
        "host": SOURCE,
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "trap_name": "linkDown",
        "severity": "warning",
        "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1.7", "value": "GigabitEthernet2"}],
    }
    ev.update(over)
    return ev


def _export(tmp_path, monkeypatch, interface_ips: list[dict], devices: list[dict] | None = None) -> None:
    """entity_resolver.json in the exporter's wire format, plus the registry."""
    devices = devices if devices is not None else [
        {"tenant_id": TENANT, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": "192.168.222.81"},
    ]
    er = tmp_path / "entity_resolver.json"
    er.write_text(json.dumps({"devices": devices, "interface_ips": interface_ips, "ifindex": []}))
    monkeypatch.setattr(main, "ENTITY_RESOLVER_FILE", str(er))
    monkeypatch.setattr(main, "_er_raw", {"devices": {}, "interface_ips": {}, "ifindex": {}})
    monkeypatch.setattr(main, "_er_mtime", -1.0)
    monkeypatch.setattr(main, "_resolver_cache", {})
    monkeypatch.setattr(main, "_resolver_cache_mtime", -1.0)

    reg = tmp_path / "device_tenant.csv"
    rows = "identity,tenant_id\n" + "".join(
        f"{d['device']},{d['tenant_id']}\n{d['name']},{d['tenant_id']}\n{d['mgmt_ip']},{d['tenant_id']}\n"
        for d in devices
    )
    reg.write_text(rows)
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(reg))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.TENANT_REFUSALS.clear()
    main._TENANT_REFUSE_LOG_LAST.clear()
    main.QUARANTINE.clear()
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "ch", RecordingCH())
    monkeypatch.setattr(main, "TRAPS_RECANON", 0)
    captured: list[dict] = []

    async def _batch(row):
        captured.append(row)

    monkeypatch.setattr(main, "batch_signal", _batch)
    yield captured
    main.TENANT_REFUSALS.clear()
    main.QUARANTINE.clear()


def test_trap_from_a_retained_interface_address_recovers_its_device(tmp_path, monkeypatch, _clean):
    _export(tmp_path, monkeypatch, [
        {"tenant_id": TENANT, "device": DEVICE, "ip": SOURCE, "ifname": "GigabitEthernet2"},
    ])

    assert main.cached_entity_resolver_all().device_for_ip(SOURCE) == DEVICE
    asyncio.run(main.handle_snmptrap(_trap()))

    assert main.TRAPS_RECANON == 1
    assert main.TENANT_REFUSALS == {}
    assert list(main.QUARANTINE) == []
    assert [r["tenant_id"] for r in _clean] == [TENANT]


def test_without_the_row_the_trap_is_refused(tmp_path, monkeypatch, _clean):
    """The defect: a device with 0 interface rows loses all of its traps."""
    _export(tmp_path, monkeypatch, [])

    assert main.cached_entity_resolver_all().device_for_ip(SOURCE) is None
    asyncio.run(main.handle_snmptrap(_trap()))

    assert main.TRAPS_RECANON == 0
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}
    assert _clean == []


def test_an_address_two_devices_claim_is_never_guessed(tmp_path, monkeypatch, _clean):
    """A retained row next to a fresh one for the same address stays a conflict."""
    other = "cedge-40-aaaaaaaa"
    _export(tmp_path, monkeypatch, [
        {"tenant_id": TENANT, "device": DEVICE, "ip": SOURCE, "ifname": "GigabitEthernet2"},
        {"tenant_id": TENANT, "device": other, "ip": SOURCE, "ifname": "GigabitEthernet2"},
    ], devices=[
        {"tenant_id": TENANT, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": "192.168.222.81"},
        {"tenant_id": TENANT, "device": other, "name": "cEDGE-40", "mgmt_ip": "192.168.222.40"},
    ])

    assert main.cached_entity_resolver_all().device_for_ip(SOURCE) is None
    asyncio.run(main.handle_snmptrap(_trap()))

    assert main.TRAPS_RECANON == 0
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}
    assert _clean == []


def test_two_tenants_reusing_an_address_are_never_guessed(tmp_path, monkeypatch, _clean):
    """The ingest resolver spans tenants: the overlap resolves to neither."""
    other = "edge-b"
    _export(tmp_path, monkeypatch, [
        {"tenant_id": TENANT, "device": DEVICE, "ip": SOURCE, "ifname": "Gi2"},
        {"tenant_id": "bravo", "device": other, "ip": SOURCE, "ifname": "Gi2"},
    ], devices=[
        {"tenant_id": TENANT, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": "192.168.222.81"},
        {"tenant_id": "bravo", "device": other, "name": "edge-b", "mgmt_ip": "192.168.222.82"},
    ])

    asyncio.run(main.handle_snmptrap(_trap()))

    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}
    assert _clean == []
