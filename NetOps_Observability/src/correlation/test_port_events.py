"""Port Intelligence physical-layer event producer tests (#94 P3b)."""
from datetime import datetime, timezone

from producers import port_event_signal

T0 = datetime(2026, 7, 3, tzinfo=timezone.utc)


def ev(msg, host="leaf1", **kw):
    d = {"hostname": host, "message": msg, "timestamp": "2026-07-03T00:00:00Z"}
    d.update(kw)
    return d


def test_unsupported_transceiver():
    s = port_event_signal(ev("%PLATFORM-4-UNSUPPORTED_TRANSCEIVER: Detected for transceiver in Ethernet1/1", interface="Ethernet1/1"), "t1", T0)
    assert s and s.kind == "transceiver_unsupported"
    assert s.entity_id == "leaf1:Ethernet1/1"
    assert s.modality_class.value == "device_telemetry"


def test_fortigate_unqualified_sfp():
    s = port_event_signal(ev("interface port5 unqualified SFP transceiver inserted", interface="port5"), "t1", T0)
    assert s and s.kind == "transceiver_unsupported"


def test_dom_rx_low_and_temp_high():
    lo = port_event_signal(ev("%OPTICS-3-RX_POWER_LOW: Ethernet3 receive power below low alarm threshold", interface="Ethernet3"), "t1", T0)
    assert lo and lo.kind == "dom_rx_power_low"
    hi = port_event_signal(ev("Transceiver temperature high alarm on Ethernet4", interface="Ethernet4"), "t1", T0)
    assert hi and hi.kind == "dom_temperature_high"


def test_fec_and_pcs():
    f = port_event_signal(ev("FEC uncorrectable codewords detected on Ethernet5", interface="Ethernet5"), "t1", T0)
    assert f and f.kind == "prefec_ber_rising"
    lf = port_event_signal(ev("%ETH-3-LOCAL_FAULT: Ethernet6 local fault", interface="Ethernet6"), "t1", T0)
    assert lf and lf.kind == "pcs_local_fault"


def test_no_light():
    s = port_event_signal(ev("Ethernet7 loss of signal (LOS)", interface="Ethernet7"), "t1", T0)
    assert s and s.kind == "link_down_no_light"


def test_interface_extracted_from_message():
    # No explicit interface field — pulled from the message text.
    s = port_event_signal(ev("%OPTICS-3-RX_POWER_LOW: Ethernet9 receive power below low alarm threshold"), "t1", T0)
    assert s and s.entity_id == "leaf1:Ethernet9"


def test_unrecognized_returns_none():
    assert port_event_signal(ev("user admin logged in via ssh"), "t1", T0) is None
    assert port_event_signal(ev("BGP neighbor 10.0.0.1 Up"), "t1", T0) is None


def test_missing_host_returns_none():
    assert port_event_signal({"message": "FEC uncorrectable"}, "t1", T0) is None


# ── H11: classifier must be ReDoS-proof on device-supplied text ──────────────


def test_h11_adversarial_message_returns_fast():
    """The rules run on unbounded syslog text on the single event loop.
    Pre-fix, chained `.*` gaps made a 4KB keyword-dense message cost ~3.9s of
    backtracking (frozen consume/healthz/engine). With the token cap + bounded
    gaps a 16KB adversarial message must return well under 50ms."""
    adversarials = [
        "rx power low " * 1300,          # ~16.9KB, the reported repro shape
        "rx power below " * 1200,        # keyword-dense, forces deep rule scans
        "transceiver temp high fec corrected align lane " * 350,
        "a" * 16384,                     # no keywords: every rule scanned to None
    ]
    for text in adversarials:
        # min of 3 runs: immune to scheduler noise on a busy runner; the
        # pre-fix behaviour is ~2 orders of magnitude over the bound.
        elapsed = min(
            _measure(lambda text=text: port_event_signal(ev(text), "t1", T0))
            for _ in range(3))
        assert elapsed < 0.05, f"classifier took {elapsed:.3f}s on {len(text)}B input"


def _measure(fn):
    import time as _time
    t0 = _time.perf_counter()
    fn()
    return _time.perf_counter() - t0


def test_h11_normal_dom_line_still_classifies_the_same():
    """Behaviour preservation: the bounded-gap rewrite must classify the same
    legitimate vendor lines to the same kinds as the chained-`.*` rules did."""
    cases = [
        ("%OPTICS-3-RX_POWER_LOW: Ethernet3 receive power below low alarm threshold", "dom_rx_power_low"),
        ("Rx power low alarm on Ethernet2", "dom_rx_power_low"),
        ("Transceiver temperature high alarm on Ethernet4", "dom_temperature_high"),
        ("Laser tx bias current high alarm on Ethernet8", "dom_lane_bias_anomaly"),
        ("FEC uncorrectable codewords detected on Ethernet5", "prefec_ber_rising"),
        ("FEC corrected codeword rate high on Ethernet5", "fec_corrected_rate_high"),
        ("PCS alignment marker lock failed, lane deskew", "pcs_deskew_fault"),
        ("transceiver in Ethernet9 not supported by this platform", "transceiver_unsupported"),
        ("SFP transceiver inserted then removed then inserted on port2", "link_flap_on_insert"),
    ]
    for msg, want in cases:
        s = port_event_signal(ev(msg), "t1", T0)
        assert s is not None and s.kind == want, f"{msg!r} → {s.kind if s else None}, want {want}"
