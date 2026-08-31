"""Minimal protobuf + gNMI message codec (gnmi_proto).

The wire numbers are asserted against BYTES, not against our own encoder alone,
wherever the value is load-bearing (a self-consistent encoder/decoder pair can
agree on a wrong field number forever). The path matcher gets the paths
`deployment/docker/gnmic/gnmic.yaml` actually subscribes to.
"""
import pytest
from gnmi_proto import (
    ENCODING_NAMES,
    LIST_MODE_ONCE,
    LIST_MODE_STREAM,
    SUB_MODE_ON_CHANGE,
    SUB_MODE_SAMPLE,
    ProtoError,
    dec_get_request,
    dec_path,
    dec_subscribe_request,
    enc_bytes,
    enc_msg,
    enc_path,
    enc_str,
    enc_subscribe_response_sync,
    enc_typed_json_ietf,
    enc_uint,
    enc_varint,
    parse,
    parse_path,
    path_matches,
    path_str,
)

# The exact subscription paths from deployment/docker/gnmic/gnmic.yaml.
OC_INTERFACES = ["/interfaces/interface/state/counters",
                 "/interfaces/interface/state/oper-status",
                 "/interfaces/interface/state/admin-status"]
OC_BGP_SESSION = ("/network-instances/network-instance[name=*]/protocols"
                  "/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor"
                  "/state/session-state")


# ── primitives ──────────────────────────────────────────────────────────────

def test_varint_matches_known_encodings():
    assert enc_varint(0) == b"\x00"
    assert enc_varint(1) == b"\x01"
    assert enc_varint(300) == b"\xac\x02"


def test_parse_returns_repeated_fields_in_wire_order():
    buf = enc_uint(4, 1) + enc_uint(4, 2) + enc_str(1, "x")
    fields = parse(buf)
    assert fields[4] == [1, 2]
    assert fields[1] == [b"x"]


def test_parse_refuses_a_length_past_the_buffer():
    with pytest.raises(ProtoError):
        parse(b"\x0a\x7f")           # field 1, LEN 127, nothing follows


def test_parse_refuses_field_number_zero_and_unknown_wire_types():
    with pytest.raises(ProtoError):
        parse(b"\x00\x01")
    with pytest.raises(ProtoError):
        parse(b"\x0b")               # field 1, wire type 3 (group, removed)


def test_typed_value_json_ietf_is_field_11():
    """TypedValue.json_ietf_val = 11 — the encoding gnmic.yaml declares."""
    body = enc_typed_json_ietf('"UP"')
    assert list(parse(body)) == [11]
    assert parse(body)[11] == [b'"UP"']


def test_subscribe_response_sync_is_bool_field_3():
    assert enc_subscribe_response_sync() == b"\x18\x01"


# ── paths ───────────────────────────────────────────────────────────────────

def test_parse_path_round_trips_through_path_str():
    text = "/interfaces/interface[name=Ethernet1]/state/counters/in-octets"
    assert path_str(parse_path(text)) == text


def test_parse_path_reads_multiple_keys_on_one_element():
    elems = parse_path("/protocols/protocol[identifier=BGP][name=BGP]/bgp")
    assert elems[1] == ("protocol", {"identifier": "BGP", "name": "BGP"})


def test_path_encode_decode_preserves_elements_and_keys():
    elems = parse_path(OC_BGP_SESSION)
    assert dec_path(enc_path(elems))["elem"] == elems


def test_deprecated_string_element_path_form_is_refused_loudly():
    with pytest.raises(ProtoError):
        dec_path(enc_str(1, "interfaces"))


def test_oc_interfaces_subscription_selects_every_counter_leaf():
    leaf = parse_path("/interfaces/interface[name=Ethernet7]/state/counters"
                      "/in-octets")
    assert path_matches(parse_path(OC_INTERFACES[0]), leaf)
    # ...and does NOT select oper-status, which is its own subscription path
    oper = parse_path("/interfaces/interface[name=Ethernet7]/state"
                      "/oper-status")
    assert not path_matches(parse_path(OC_INTERFACES[0]), oper)
    assert path_matches(parse_path(OC_INTERFACES[1]), oper)


def test_wildcard_key_matches_any_value_but_a_literal_key_does_not():
    leaf = parse_path("/interfaces/interface[name=Ethernet1]/state"
                      "/oper-status")
    assert path_matches(
        parse_path("/interfaces/interface[name=*]/state/oper-status"), leaf)
    assert not path_matches(
        parse_path("/interfaces/interface[name=Ethernet2]/state/oper-status"),
        leaf)


def test_gnmic_bgp_wildcard_path_selects_the_served_default_instance():
    leaf = parse_path(
        "/network-instances/network-instance[name=default]/protocols"
        "/protocol[identifier=BGP][name=BGP]/bgp/neighbors"
        "/neighbor[neighbor-address=203.0.113.9]/state/session-state")
    assert path_matches(parse_path(OC_BGP_SESSION), leaf)


def test_multi_level_wildcard_spans_any_number_of_elements():
    leaf = parse_path("/a/b/c/d")
    assert path_matches(parse_path("/a/.../d"), leaf)
    assert path_matches(parse_path("/.../d"), leaf)
    assert not path_matches(parse_path("/a/.../z"), leaf)


# ── SubscribeRequest / GetRequest ───────────────────────────────────────────

def _subscription(path: str, mode: int, sample_ns: int = 0,
                  heartbeat_ns: int = 0) -> bytes:
    body = enc_msg(1, enc_path(parse_path(path))) + enc_uint(2, mode)
    if sample_ns:
        body += enc_uint(3, sample_ns)
    if heartbeat_ns:
        body += enc_uint(5, heartbeat_ns)
    return enc_msg(2, body)


def _subscribe_request(subs: bytes, mode: int = LIST_MODE_STREAM,
                       encoding: int = 4, updates_only: bool = False) -> bytes:
    body = subs + enc_uint(5, mode) + enc_uint(8, encoding)
    if updates_only:
        body += enc_uint(9, 1)
    return enc_msg(1, body)


def test_decode_stream_sample_subscription_like_oc_interfaces():
    raw = _subscribe_request(
        b"".join(_subscription(p, SUB_MODE_SAMPLE, sample_ns=30_000_000_000)
                 for p in OC_INTERFACES))
    req = dec_subscribe_request(raw)
    assert req["kind"] == "subscribe"
    assert req["mode"] == LIST_MODE_STREAM
    assert ENCODING_NAMES[req["encoding"]] == "json_ietf"
    assert len(req["subscriptions"]) == 3
    assert all(s["mode"] == SUB_MODE_SAMPLE for s in req["subscriptions"])
    assert all(s["sample_interval_ns"] == 30_000_000_000
               for s in req["subscriptions"])
    assert path_str(req["subscriptions"][1]["path"]) == OC_INTERFACES[1]


def test_decode_on_change_subscription_with_heartbeat_like_oc_bgp():
    raw = _subscribe_request(_subscription(OC_BGP_SESSION, SUB_MODE_ON_CHANGE,
                                           heartbeat_ns=30_000_000_000))
    sub = dec_subscribe_request(raw)["subscriptions"][0]
    assert sub["mode"] == SUB_MODE_ON_CHANGE
    assert sub["heartbeat_interval_ns"] == 30_000_000_000
    assert sub["sample_interval_ns"] == 0


def test_decode_once_mode_and_updates_only():
    raw = _subscribe_request(_subscription(OC_INTERFACES[0], SUB_MODE_SAMPLE),
                             mode=LIST_MODE_ONCE, updates_only=True)
    req = dec_subscribe_request(raw)
    assert req["mode"] == LIST_MODE_ONCE
    assert req["updates_only"] is True


def test_poll_request_is_recognised_not_mistaken_for_a_subscription():
    assert dec_subscribe_request(enc_bytes(3, b""))["kind"] == "poll"


def test_subscribe_request_with_neither_oneof_arm_is_refused():
    with pytest.raises(ProtoError):
        dec_subscribe_request(enc_uint(5, 0))


def test_get_request_decodes_prefix_and_paths():
    raw = (enc_msg(1, enc_path(parse_path("/interfaces")))
           + enc_msg(2, enc_path(parse_path("/interface[name=Ethernet1]")))
           + enc_uint(5, 4))
    req = dec_get_request(raw)
    assert path_str(req["prefix"]) == "/interfaces"
    assert path_str(req["paths"][0]) == "/interface[name=Ethernet1]"
    assert req["encoding"] == 4
