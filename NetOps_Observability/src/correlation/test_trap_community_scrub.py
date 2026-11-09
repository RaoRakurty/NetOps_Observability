# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""The v1/v2c community is a shared device credential.

A receiver older than 2026-11-09 published it as `snmp_community`, and such a
record can stay on netops.snmptrap for the bus retention window. It must not
reach the signal, the dead-letter ring, the durable dead-letter file or a debug
peek, whatever its value, and removing it must not change the signal.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest

import main
from producers import trap_control_signal

VALUE = "fabricated-community-7f3a"


def _trap(**extra) -> dict:
    return {
        "timestamp": "2026-11-09T02:25:00Z",
        "device": "leaf1",
        "host": "10.0.0.5",
        "tenant_id": "lab",
        "snmp_version": "v2c",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "trap_name": "linkDown",
        "severity": "warning",
        "authenticated": False,
        "varbinds": [{"oid": "1.3.6.1.2.1.2.2.1.1.2", "name": "ifIndex", "value": "2"}],
        **extra,
    }


def test_signal_is_identical_with_and_without_the_field() -> None:
    now = datetime(2026, 11, 9, 2, 25, tzinfo=timezone.utc)
    with_field = trap_control_signal(_trap(snmp_community=VALUE), "lab", now)
    without = trap_control_signal(_trap(), "lab", now)
    assert with_field is not None and without is not None
    assert with_field.signal_id == without.signal_id
    assert with_field.to_ch_row() == without.to_ch_row()
    assert VALUE not in json.dumps(with_field.to_ch_row(), default=str)


@pytest.mark.parametrize("value", [VALUE, "public"])
def test_quarantine_record_drops_the_field_from_a_decoded_event(value: str) -> None:
    event = _trap(snmp_community=value)
    rec = main._quarantine_record("deadletter:trap", event, ValueError("boom"))
    assert "snmp_community" not in rec["payload"]
    assert '"snmp_version": "v2c"' in rec["payload"]
    # The caller's dict is not part of the contract: only the kept record is.
    assert main.QUARANTINE[-1] is rec


@pytest.mark.parametrize("raw", [
    json.dumps({"snmp_community": VALUE, "a": 1}),
    '{"snmp_community" : "' + VALUE + '", "a"',     # poison: failed to decode
    '{"a":1,"snmp_community":"' + VALUE,            # cut mid-value
    '{"snmp_community":"x\\"' + VALUE + '"}',       # escaped quote in the value
])
def test_quarantine_record_scrubs_undecoded_bytes(raw: str) -> None:
    rec = main._quarantine_record("netops.snmptrap", raw.encode(), ValueError("decode"))
    assert VALUE not in rec["payload"]


def test_durable_dead_letter_file_never_gets_the_value(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    main._quarantine_record("deadletter:trap", _trap(snmp_community=VALUE), ValueError("boom"))
    main._quarantine_record("netops.snmptrap", json.dumps(_trap(snmp_community=VALUE)).encode(), ValueError("x"))
    written = (tmp_path / "corr-deadletter.ndjson").read_text()
    assert written.count("\n") == 2
    assert VALUE not in written


def test_handler_removes_the_field_before_any_dead_letter(monkeypatch) -> None:
    kept: list[object] = []
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "ch", object())

    def refuse(*_a, **_k):
        raise main.TenantClaimRefused("claim contradicts the registry")

    monkeypatch.setattr(main, "verified_tenant", refuse)
    monkeypatch.setattr(main, "keep_deadletter_payload", lambda _lane, ev, _exc: kept.append(ev))
    asyncio.run(main.handle_snmptrap(_trap(snmp_community=VALUE)))
    assert kept, "the refusal path must have run"
    assert VALUE not in json.dumps(kept, default=str)


def test_scrub_leaves_other_bytes_alone() -> None:
    clean = b'{"snmp_community_present":true,"message":"snmp_community"}'
    assert main.scrub_community_bytes(clean) == clean
    assert main.scrub_community_bytes(b'{"a":1,"snmp_community":"x","b":2}') == \
        b'{"a":1,"snmp_community":"[REDACTED]","b":2}'
