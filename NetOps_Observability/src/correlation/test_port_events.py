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
