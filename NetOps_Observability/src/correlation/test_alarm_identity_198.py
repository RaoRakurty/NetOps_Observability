"""Tracker 198 — a generic alarm's `signal_id` must identify the EVENT.

`signal_id = uuid5(NS, "{source}|{native_id}|{ts_ms}")`, and the two generic
`device_alarm` nets used to build a native_id out of classification metadata
ONLY (host + facility + mnemonic + interface; device + trap OID). Two DIFFERENT
lines from one device sharing those inside one millisecond therefore derived the
SAME id, and the deduplicators downstream — `CHBatcher.add`'s pending-identity
check and the engine window's `_BUFFERED_IDS` — discarded one of them as a
"replay". That is uncounted evidence loss, and across a commit boundary the same
collision instead produced the duplicate `corr_signals` row seen in the 155c/155d
control arms (docs/scale/TRACKER_198_DUPLICATE_SIGNAL_RCA_2026-09-02.md).

What is pinned here:
  * distinct content ⇒ distinct id, same content ⇒ same id (idempotent replay);
  * the discriminator survives the MAX_ID_CHARS tail cap on a hostile hostname;
  * the classified producers we deliberately did NOT change keep their ids;
  * the in-batch collapse still yields ONE row and is now COUNTED;
  * the counter is exported on /metrics.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

import main
from producers import (
    MAX_ID_CHARS,
    _content_tag,
    port_event_signal,
    syslog_control_signal,
    trap_control_signal,
)

T0 = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)
TS = "2026-06-12T10:00:01Z"


def alarm_event(**over) -> dict:
    """The unrecognized-but-severe syslog line that becomes a device_alarm."""
    ev = {
        "hostname": "core1", "appname": "%ENVMON-2-FAN_FAILED",
        "message": "Fan 2 in chassis 1 has failed", "severity": "critical",
        "timestamp": TS, "tenant_id": "",
    }
    ev.update(over)
    return ev


def trap_alarm_event(**over) -> dict:
    """An unclassified vendor trap at err → the generic trap device_alarm."""
    ev = {
        "device": "leaf9", "trap_oid": "1.3.6.1.4.1.9.9.999.0.1",
        "trap_name": "vendorAlarm", "severity": "err", "timestamp": TS,
        "varbinds": [{"oid": "1.3.6.1.4.1.9.9.999.1.1",
                      "name": "alarmText", "value": "PSU 1 failed"}],
    }
    ev.update(over)
    return ev


def run(coro):
    return asyncio.run(coro)


# ── (a) distinct content ⇒ distinct id; identical content ⇒ identical id ─────


def test_two_alarms_differing_only_in_message_get_different_ids():
    """THE BUG. Same host, same facility, same mnemonic, no interface, the SAME
    millisecond — only the text differs. Before tracker 198 these were one
    signal and one of them was silently dropped."""
    a = syslog_control_signal(alarm_event(), "", T0)
    b = syslog_control_signal(
        alarm_event(message="Fan 3 in chassis 1 has failed"), "", T0)
    assert a is not None and b is not None
    assert a.kind == b.kind == "device_alarm"
    assert int(a.ts.timestamp() * 1000) == int(b.ts.timestamp() * 1000), \
        "the collision only exists at identical millisecond stamps"
    assert a.attrs["facility"] == b.attrs["facility"]
    assert a.attrs["mnemonic"] == b.attrs["mnemonic"]
    assert a.signal_id != b.signal_id, \
        "two DISTINCT alarms must not share one signal_id"


def test_byte_identical_alarm_is_idempotent():
    """The other half of the contract: a Kafka redelivery carries byte-identical
    text, so it must still derive the SAME id and still dedup. A content
    discriminator that broke this would turn every retry into a duplicate row."""
    ids = {syslog_control_signal(alarm_event(), "", T0).signal_id
           for _ in range(3)}
    assert len(ids) == 1


def test_trap_alarms_differing_only_in_varbinds_get_different_ids():
    """Same defect on the trap lane: the OID classifies the trap, the varbinds
    say WHICH entity/threshold it is about."""
    a = trap_control_signal(trap_alarm_event(), "", T0)
    b = trap_control_signal(trap_alarm_event(
        varbinds=[{"oid": "1.3.6.1.4.1.9.9.999.1.1",
                   "name": "alarmText", "value": "PSU 2 failed"}]), "", T0)
    assert a is not None and b is not None
    assert a.kind == b.kind == "device_alarm"
    assert a.signal_id != b.signal_id
    # …and idempotent under redelivery.
    assert trap_control_signal(trap_alarm_event(), "", T0).signal_id == a.signal_id


def test_content_tag_is_process_independent_and_surrogate_tolerant():
    """The tag must be a stable hash, never `hash()` (salted per process) — a
    replay re-derives the id in ANOTHER process. And the text is an untrusted
    device string decoded from JSON, so a lone surrogate must not raise."""
    assert _content_tag("abc") == _content_tag("abc")
    assert _content_tag("abc") != _content_tag("abd")
    assert len(_content_tag("abc")) == 8
    assert _content_tag("bad \ud800 byte")  # would raise on a plain .encode()


def test_discriminator_survives_the_native_id_cap():
    """`Signal` caps native_id at MAX_ID_CHARS by cutting the TAIL, and hostname
    is an untrusted device string. If the tag were simply appended, a 300-char
    hostname would truncate it away and restore the collision."""
    host = "h" * 300
    a = syslog_control_signal(alarm_event(hostname=host), "", T0)
    b = syslog_control_signal(
        alarm_event(hostname=host, message="a different failure"), "", T0)
    assert a is not None and b is not None
    assert len(a.native_id) <= MAX_ID_CHARS
    assert a.native_id.endswith(_content_tag("Fan 2 in chassis 1 has failed"))
    assert a.signal_id != b.signal_id


# ── (d) determinism pin ──────────────────────────────────────────────────────


def test_alarm_signal_id_is_pinned():
    """A fixed fixture derives a fixed id, forever — replay, archive rehydration
    and the Go readers all depend on it.

    THESE VALUES CHANGED BY DESIGN AT THIS COMMIT (tracker 198): the syslog
    alarm was 410fb5d7-a694-5b60-8416-1e4d665744d9 and the trap alarm was
    c56f0b17-660d-5241-b157-097da6b3b666 before the content tag was folded in.
    Historic `corr_signals` rows keep their stored ids (rehydration reads
    stored_signal_id), so this is a forward-only change of identity for NEW
    generic alarms; nothing re-derives an id for an already-persisted row.
    """
    s = syslog_control_signal(alarm_event(), "", T0)
    assert s is not None
    assert s.native_id == "core1|alarm|ENVMON|FAN_FAILED|-|1781258401000|ee1fc7b0"
    assert str(s.signal_id) == "f97967e3-3ddd-5153-bbb8-d62871448093"

    t = trap_control_signal(trap_alarm_event(), "", T0)
    assert t is not None
    assert t.native_id == (
        "leaf9|alarm|1.3.6.1.4.1.9.9.999.0.1|1781258401000|51918ae9")
    assert str(t.signal_id) == "b845aa9e-7ea3-584d-843b-fde94499c7f3"


def test_classified_producers_keep_their_native_ids():
    """The audit's other verdict, pinned: a CLASSIFIED line's native_id already
    carries the classifier's extracted content (peer/interface/state/port), so it
    was deliberately left alone. This test fails if a later change quietly
    re-keys the whole control-plane lane."""
    link = syslog_control_signal({
        "hostname": "leaf1", "appname": "%LINK-3-UPDOWN", "facility": "LINK",
        "message": "Interface Ethernet3, changed state to down",
        "timestamp": TS, "tenant_id": "",
    }, "", T0)
    assert link is not None and link.kind == "link_state_change"
    assert link.native_id == "leaf1|link|Ethernet3|down|1781258401000"

    trap = trap_control_signal({
        "device": "leaf9", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "timestamp": TS,
        "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1", "name": "ifName",
                      "value": "Ethernet7"}],
    }, "", T0)
    assert trap is not None and trap.kind == "link_state_change"
    assert trap.native_id == "leaf9|trap_link|Ethernet7|down|1781258401000"

    port = port_event_signal({
        "hostname": "leaf1", "interface": "Ethernet4", "timestamp": TS,
        "message": "Loss of signal detected on Ethernet4",
    }, "", T0)
    assert port is not None
    assert port.native_id == "leaf1|portevt|link_down_no_light|Ethernet4|1781258401000"


# ── (b) the in-batch collapse still yields ONE row, and is COUNTED ───────────


class _RecordingCH:
    def __init__(self) -> None:
        self.batches: list[tuple[str, list[dict], str]] = []

    async def insert(self, table, rows, dedup_token=""):
        self.batches.append((table, list(rows), dedup_token))
        return True


@pytest.fixture
def _clean_batcher():
    main.SIGNAL_BATCH.drop_pending()
    yield
    main.SIGNAL_BATCH.drop_pending()


def test_in_batch_duplicate_collapses_to_one_row_and_is_counted(
        monkeypatch, _clean_batcher):
    """A byte-identical redelivery inside one batch is still dropped (correct,
    idempotent) — but it is no longer INVISIBLE. Same-identity drops are the
    one place a native_id collision destroys evidence, so the rate is now on
    /metrics even though no single row can be judged from inside add()."""
    ch = _RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    before = main.BATCH_ROWS_IDENTITY_COLLAPSED
    replay_before = main.BATCH_ROWS_REPLAY_DEDUPED

    async def scenario():
        await main.batch_signal({"signal_id": "sig-198", "kind": "device_alarm"})
        await main.batch_signal({"signal_id": "sig-198", "kind": "device_alarm"})
        assert main.SIGNAL_BATCH.pending() == 1, "the duplicate must not be buffered"
        await main.SIGNAL_BATCH.flush()

    run(scenario())
    assert len(ch.batches) == 1
    assert [r["signal_id"] for r in ch.batches[0][1]] == ["sig-198"], \
        "ONE row lands, not two"
    assert main.BATCH_ROWS_IDENTITY_COLLAPSED - before == 1
    assert main.BATCH_ROWS_REPLAY_DEDUPED == replay_before, \
        "an in-batch collapse is not a post-flush replay drop — separate events"


def test_distinct_identities_are_not_collapsed(monkeypatch, _clean_batcher):
    """The counter must count COLLAPSES, not adds: two distinct ids buffer two
    rows and move nothing."""
    monkeypatch.setattr(main, "ch", _RecordingCH())
    before = main.BATCH_ROWS_IDENTITY_COLLAPSED

    async def scenario():
        await main.batch_signal({"signal_id": "sig-a"})
        await main.batch_signal({"signal_id": "sig-b"})
        assert main.SIGNAL_BATCH.pending() == 2

    run(scenario())
    assert main.BATCH_ROWS_IDENTITY_COLLAPSED == before


# ── (c) the counter is exported ─────────────────────────────────────────────


def test_identity_collapse_counter_is_on_metrics():
    text = main._metrics_text()
    assert 'corr_signal_batch{event="rows_identity_collapsed"}' in text
    # …in the same family as the drops it must be read against.
    assert 'corr_signal_batch{event="rows_replay_deduped"}' in text
    assert 'corr_signal_batch{event="rows_flushed"}' in text
    line = next(ln for ln in text.splitlines()
                if ln.startswith('corr_signal_batch{event="rows_identity_collapsed"}'))
    assert int(line.rsplit(" ", 1)[1]) >= 0
