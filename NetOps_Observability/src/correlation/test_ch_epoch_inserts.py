"""S4 (log-time standard) — ClickHouse inserts carry epoch-ms integers.

DateTime64(3) interprets an inserted INTEGER as a scaled Unix timestamp in
UTC, while a zone-less STRING is interpreted in the server/column timezone —
the R1 dependency S4 removes. These tests pin: (a) every writer formats
datetimes as epoch-ms ints, (b) the parser accepts every historical wire
form, and (c) the to_ch_row/from_ch_row round trip stays byte-faithful.
"""
from datetime import datetime, timezone

import engine
from signals import (EntityType, ModalityClass, Observer, ObserverType,
                     Severity, Signal, Source, _ch_dt, _parse_ch_dt)

TS = datetime(2026, 7, 16, 21, 56, 3, 562_431, tzinfo=timezone.utc)
TS_MS = 1784238963562  # 2026-07-16T21:56:03.562Z — µs truncated like strftime[:-3]


def test_ch_dt_is_epoch_ms_int_with_truncation():
    v = _ch_dt(TS)
    assert isinstance(v, int)
    assert v == TS_MS
    # engine's writer stays in lockstep with the signals writer.
    assert engine._ch_dt(TS) == v
    # naive input is UTC by contract, never process-local.
    assert _ch_dt(TS.replace(tzinfo=None)) == v


def test_parse_ch_dt_accepts_every_wire_form():
    want = TS.replace(microsecond=562_000)  # ms precision, like the store
    assert _parse_ch_dt(TS_MS) == want                       # epoch-ms int (S4)
    assert _parse_ch_dt(str(TS_MS)) == want                  # digit string
    assert _parse_ch_dt("2026-07-16 21:56:03.562") == want   # legacy zone-less
    assert _parse_ch_dt("2026-07-16T21:56:03.562Z") == want  # RFC 3339 (S3)
    assert _parse_ch_dt("2026-07-16 21:56:03") == want.replace(microsecond=0)


def _signal() -> Signal:
    return Signal(
        tenant_id="acme",
        ts=TS,
        source=Source.SYSLOG,
        kind="link_down",
        native_id="dev-1|link_down|test",
        observer=Observer(observer_id="dev-1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE,
        entity_type=EntityType.INTERFACE,
        entity_id="dev-1:eth0",
        entity_tokens=("dev-1", "dev-1:eth0"),
        severity=Severity.CRIT,
    )


def test_signal_row_ts_is_epoch_ms_and_round_trips():
    row = _signal().to_ch_row()
    assert isinstance(row["ts"], int)
    assert row["ts"] == TS_MS
    back = Signal.from_ch_row(row)
    assert back.to_ch_row() == row, "rehydration must stay byte-faithful (replay)"
    # A legacy archive row (string ts, pre-S4) still rehydrates to the instant.
    legacy = dict(row)
    legacy["ts"] = "2026-07-16 21:56:03.562"
    assert Signal.from_ch_row(legacy).ts == TS.replace(microsecond=562_000)


def test_signal_identity_survives_the_format_change():
    # signal_id derives from source|native_id|ts-ms — NOT from the wire format —
    # so the same event keeps the same identity across the S4 rollout.
    a, b = _signal(), _signal()
    assert a.signal_id == b.signal_id
    assert str(Signal.from_ch_row(a.to_ch_row()).signal_id) == str(a.signal_id)
