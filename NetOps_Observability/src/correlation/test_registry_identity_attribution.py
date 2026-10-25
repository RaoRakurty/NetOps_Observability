# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stage [1] normalize — tenant attribution of a lane's device identity.

THE DEFECT (lab, 2026-10-25): ~48 SNMP traps / 70 min quarantined as

    SECURITY: tenant claim refused … lane=snmptrap reason=identity_unattributable
    identity=vedge-20-1e95f00f claimed_tenant=- registry_tenant=-

The trap receiver stamps the trap's `device` with the INVENTORY ID
(collectors/snmptrap.go attributeDevice → Target.ID). For an SNMP-discovered
device that id is discovery.ScanDeviceID(sysName, addr) — "vedge-20-1e95f00f".
The registry the API exported (telemetry_enrichment.go) carried only the device
NAME ("vEdge-20") and ADDRESS rows, never the id, so verified_tenant on the
registry-anchored trap lane saw an identity the registry had never heard of and
refused it. Traps from SNMP-discovered devices never reached the window.

The fix is in the exporter (one row per id, name AND address). These tests pin
the reader half: the lab file shape is reproduced before (refused) and after
(attributed), an identity listed under two tenants is never resolved to either
(§3a), and default-closed stays: an identity in no row is still refused.
"""
from __future__ import annotations

import asyncio

import pytest

import main


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.inserts.append((table, list(rows)))
        return True

    def rows_for(self, table: str) -> list[dict]:
        return [r for t, rs in self.inserts if t == table for r in rs]


# The exact lab file shape on 2026-10-25: NAME rows and ADDRESS rows, empty
# tenant (= platform), and no row for the scan id the trap carries.
LAB_ROWS_BEFORE = (
    "identity,tenant_id\n"
    "192.168.222.101,\n"
    "cEDGE-81,\n"
    "vEdge-20,\n"
)
# What the fixed exporter writes for the same inventory: the id rows join.
LAB_ROWS_AFTER = LAB_ROWS_BEFORE + (
    "cedge-81-11060ae2,\n"
    "vedge-20-1e95f00f,\n"
)


def _load(tmp_path, monkeypatch, body: str) -> None:
    p = tmp_path / "device_tenant.csv"
    p.write_text(body)
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(p))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.TENANT_REFUSALS.clear()
    main._TENANT_REFUSE_LOG_LAST.clear()
    main.QUARANTINE.clear()
    monkeypatch.setattr(main, "TENANT_CLAIMS_VERIFIED", 0)
    monkeypatch.setattr(main, "TENANT_CLAIMS_REFUSED", 0)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    yield
    main.TENANT_REFUSALS.clear()
    main.QUARANTINE.clear()


def _trap(**over) -> dict:
    ev = {
        "device": "vedge-20-1e95f00f",
        "host": "192.168.222.20",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "trap_name": "linkDown",
        "severity": "warning",
        "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1.7", "value": "ge0/1"}],
    }
    ev.update(over)
    return ev


# ── regression: the exact lab shape ─────────────────────────────────────────


def test_lab_shape_before_fix_refuses_the_scan_id(tmp_path, monkeypatch):
    """Pins the defect: name row present, id row absent → refused."""
    _load(tmp_path, monkeypatch, LAB_ROWS_BEFORE)
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("", "vedge-20-1e95f00f", "snmptrap", registry_anchored=True)
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}


def test_lab_shape_after_fix_attributes_the_scan_id(tmp_path, monkeypatch):
    _load(tmp_path, monkeypatch, LAB_ROWS_AFTER)
    for ident in ("vedge-20-1e95f00f", "cedge-81-11060ae2", "vEdge-20", "192.168.222.101"):
        assert main.verified_tenant("", ident, "snmptrap", registry_anchored=True) == "global"
    assert main.TENANT_REFUSALS == {}


def test_lab_trap_reaches_corr_signals_after_fix(tmp_path, monkeypatch):
    """End to end through handle_snmptrap: the trap that was quarantined on
    the lab now produces a signal under the device's own tenant."""
    _load(tmp_path, monkeypatch, LAB_ROWS_AFTER)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main.handle_snmptrap(_trap()))
    run(main.SIGNAL_BATCH.flush())
    rows = ch.rows_for("netops.corr_signals")
    assert rows, "the lab trap still produced no signal"
    assert {r["tenant_id"] for r in rows} == {"global"}
    assert main.TENANT_REFUSALS == {}
    assert list(main.QUARANTINE) == []


def test_tenant_owned_scan_id_attributes_to_that_tenant(tmp_path, monkeypatch):
    """Not only the platform: a tenant-owned device's id resolves to its owner
    on every registry-anchored lane, and a claim of another tenant still fails."""
    _load(tmp_path, monkeypatch,
          "identity,tenant_id\nmx480-core-1-0a1b2c3d,acme\nmx480-core#1,acme\n10.20.0.1,acme\n")
    for lane in ("snmptrap", "syslog", "flows"):
        assert main.verified_tenant("", "mx480-core-1-0a1b2c3d", lane,
                                    registry_anchored=True) == "acme"
        assert main.verified_tenant("acme", "mx480-core-1-0a1b2c3d", lane,
                                    registry_anchored=True) == "acme"
    assert main.verified_tenant("", "mx480-core-1-0a1b2c3d", "metrics") == "acme"
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("globex", "mx480-core-1-0a1b2c3d", "snmptrap",
                             registry_anchored=True)


# ── default-closed stays ────────────────────────────────────────────────────


def test_unknown_identity_still_refused_after_fix(tmp_path, monkeypatch):
    _load(tmp_path, monkeypatch, LAB_ROWS_AFTER)
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("", "vedge-99-deadbeef", "snmptrap", registry_anchored=True)
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}


def test_lookup_is_exact_not_a_prefix_or_case_fold(tmp_path, monkeypatch):
    """The scan id's name prefix, or a case variant, is not the identity."""
    _load(tmp_path, monkeypatch, LAB_ROWS_AFTER)
    assert main.tenant_lookup("vedge-20") is None
    assert main.tenant_lookup("VEDGE-20-1E95F00F") is None


# ── §3a ambiguity ───────────────────────────────────────────────────────────


def test_identity_listed_under_two_tenants_is_refused(tmp_path, monkeypatch):
    """The exporter omits an identity two tenants share. If a file ever lists
    one twice anyway, the reader must not pick either (no last-row-wins)."""
    _load(tmp_path, monkeypatch,
          "identity,tenant_id\n"
          "core-1,acme\n"
          "acme-only,acme\n"
          "core-1,globex\n"
          "globex-only,globex\n")
    assert main.tenant_lookup("core-1") is None
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("", "core-1", "snmptrap", registry_anchored=True)
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("globex", "core-1", "snmptrap", registry_anchored=True)
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("acme", "core-1", "syslog", registry_anchored=True)
    # The unshared identities keep their attribution.
    assert main.tenant_lookup("acme-only") == "acme"
    assert main.tenant_lookup("globex-only") == "globex"


def test_ambiguity_survives_a_third_row_restating_the_first_owner(tmp_path, monkeypatch):
    _load(tmp_path, monkeypatch,
          "identity,tenant_id\ncore-1,acme\ncore-1,globex\ncore-1,acme\n")
    assert main.tenant_lookup("core-1") is None


def test_same_tenant_duplicate_row_is_not_ambiguous(tmp_path, monkeypatch):
    """Platform "" and "global" are one principal (canon_tenant) — a repeat
    under either spelling is a duplicate, not a second owner."""
    _load(tmp_path, monkeypatch,
          "identity,tenant_id\nleaf1,acme\nleaf1,acme\nplat1,\nplat1,global\n")
    assert main.tenant_lookup("leaf1") == "acme"
    assert main.tenant_lookup("plat1") == ""
