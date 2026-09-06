# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Minimal protobuf + gNMI message codec (tracker 152, design §4.6).

The twin serves gNMI to OUR collector (`gnmic` 0.46.0, pinned in
`deployment/docker/docker-compose.yml`), so only the messages that collector
puts on the wire are modelled: Capabilities, Get and — the one that matters —
Subscribe. Field numbers are from openconfig/gnmi `gnmi.proto` v0.8.x and are
asserted end-to-end by the live gnmic round-trip, not by trust: a wrong number
produces an unparseable message at the real client, not a silent mis-decode.

Deliberately NOT a protobuf runtime: no descriptors, no reflection, no
unknown-field preservation, no `grpcio`/`protobuf` wheels in the twin image
(design §4.1 keeps the lab image's dependency set pinned and tiny). Parsing is
zero-trust: every length is bounds-checked against the buffer, recursion is
depth-capped, and an unknown field is skipped by wire type rather than
guessed at.
"""
from __future__ import annotations

# ── wire types ──────────────────────────────────────────────────────────────
WT_VARINT = 0
WT_FIXED64 = 1
WT_LEN = 2
WT_FIXED32 = 5

_MAX_DEPTH = 12          # gNMI's deepest nesting is ~6; 12 is generous


class ProtoError(ValueError):
    """A protobuf buffer was malformed. Never recoverable mid-message."""


# ── primitive encoders ──────────────────────────────────────────────────────

def enc_varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64                     # two's complement, as protobuf does
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field: int, wire_type: int) -> bytes:
    return enc_varint((field << 3) | wire_type)


def enc_uint(field: int, value: int) -> bytes:
    return _tag(field, WT_VARINT) + enc_varint(value)


def enc_bool(field: int, value: bool) -> bytes:
    return enc_uint(field, 1 if value else 0)


def enc_bytes(field: int, value: bytes) -> bytes:
    return _tag(field, WT_LEN) + enc_varint(len(value)) + value


def enc_str(field: int, value: str) -> bytes:
    return enc_bytes(field, value.encode("utf-8"))


def enc_msg(field: int, body: bytes) -> bytes:
    return enc_bytes(field, body)


# ── primitive decoder ───────────────────────────────────────────────────────

def _dec_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ProtoError("varint: truncated")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ProtoError("varint: longer than 10 octets")


def parse(buf: bytes) -> dict[int, list]:
    """Flat field map: field number → list of values (varints as int, LEN as
    bytes, fixed32/64 as int). Repeated fields keep every occurrence, in wire
    order; that is what makes `repeated Update` and `oneof` both work."""
    out: dict[int, list] = {}
    pos = 0
    while pos < len(buf):
        key, pos = _dec_varint(buf, pos)
        field, wire_type = key >> 3, key & 7
        if field == 0:
            raise ProtoError("field number 0 is illegal")
        if wire_type == WT_VARINT:
            value, pos = _dec_varint(buf, pos)
        elif wire_type == WT_LEN:
            length, pos = _dec_varint(buf, pos)
            if length < 0 or pos + length > len(buf):
                raise ProtoError(f"field {field}: length {length} past buffer")
            value = buf[pos:pos + length]
            pos += length
        elif wire_type == WT_FIXED64:
            if pos + 8 > len(buf):
                raise ProtoError(f"field {field}: truncated fixed64")
            value = int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
        elif wire_type == WT_FIXED32:
            if pos + 4 > len(buf):
                raise ProtoError(f"field {field}: truncated fixed32")
            value = int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
        else:
            raise ProtoError(f"field {field}: unsupported wire type "
                             f"{wire_type}")
        out.setdefault(field, []).append(value)
    return out


def _one(fields: dict[int, list], num: int, default=None):
    vals = fields.get(num)
    return vals[-1] if vals else default


# ── gNMI Path ───────────────────────────────────────────────────────────────
# message PathElem { string name = 1; map<string,string> key = 2; }
# message Path { repeated string element = 1 [deprecated];
#                string origin = 2; repeated PathElem elem = 3;
#                string target = 4; }

PathElem = tuple[str, dict[str, str]]


def enc_path(elems: list[PathElem], origin: str = "",
             target: str = "") -> bytes:
    out = bytearray()
    if origin:
        out += enc_str(2, origin)
    for name, keys in elems:
        body = enc_str(1, name)
        for k, v in sorted(keys.items()):
            body += enc_msg(2, enc_str(1, k) + enc_str(2, str(v)))
        out += enc_msg(3, bytes(body))
    if target:
        out += enc_str(4, target)
    return bytes(out)


def dec_path(buf: bytes, depth: int = 0) -> dict:
    if depth > _MAX_DEPTH:
        raise ProtoError("path: nesting too deep")
    fields = parse(buf)
    elems: list[PathElem] = []
    for raw in fields.get(3, []):
        ef = parse(raw)
        name = _one(ef, 1, b"") or b""
        keys: dict[str, str] = {}
        for kv in ef.get(2, []):
            kf = parse(kv)
            keys[(_one(kf, 1, b"") or b"").decode("utf-8", "replace")] = \
                (_one(kf, 2, b"") or b"").decode("utf-8", "replace")
        elems.append((name.decode("utf-8", "replace"), keys))
    # `element` (field 1) is the pre-0.4 string form. gnmic never sends it; a
    # client that does gets an honest refusal rather than a silent empty path.
    if not elems and fields.get(1):
        raise ProtoError("path: deprecated string `element` form not served — "
                         "use `elem` (gNMI >= 0.4)")
    return {
        "elem": elems,
        "origin": (_one(fields, 2, b"") or b"").decode("utf-8", "replace"),
        "target": (_one(fields, 4, b"") or b"").decode("utf-8", "replace"),
    }


def parse_path(text: str) -> list[PathElem]:
    """`/interfaces/interface[name=Ethernet1]/state/oper-status` → elems.
    Keys are `[k=v]`, repeatable; `*` is kept verbatim (it is a wildcard to
    the matcher, not a literal)."""
    elems: list[PathElem] = []
    for raw in text.strip("/").split("/"):
        if not raw:
            continue
        name, keys = raw, {}
        while name.endswith("]") and "[" in name:
            head, _, kv = name.rpartition("[")
            k, _, v = kv[:-1].partition("=")
            if not k:
                raise ValueError(f"path element {raw!r}: empty key name")
            keys[k] = v
            name = head
        elems.append((name, keys))
    return elems


def path_str(elems: list[PathElem]) -> str:
    parts = []
    for name, keys in elems:
        parts.append(name + "".join(f"[{k}={v}]"
                                    for k, v in sorted(keys.items())))
    return "/" + "/".join(parts)


def path_matches(sub: list[PathElem], leaf: list[PathElem]) -> bool:
    """True when subscription path `sub` selects leaf path `leaf`.

    `sub` is a PREFIX: subscribing to `/interfaces/interface/state/counters`
    selects every counter leaf under it (the shape gnmic.yaml's `oc-interfaces`
    actually uses). `*` matches one element name; `...` matches any number of
    elements (gNMI wildcards). A key absent from `sub`, or present as `*`,
    matches any value — so `interface[name=*]` selects all interfaces.
    """
    return _match(sub, 0, leaf, 0)


def _match(sub: list[PathElem], i: int, leaf: list[PathElem], j: int) -> bool:
    while i < len(sub):
        name, keys = sub[i]
        if name == "...":
            # multi-level wildcard: try to resume at every remaining position
            return any(_match(sub, i + 1, leaf, k)
                       for k in range(j, len(leaf) + 1))
        if j >= len(leaf):
            return False
        lname, lkeys = leaf[j]
        if name not in ("*", lname):
            return False
        for k, v in keys.items():
            if v != "*" and lkeys.get(k) != v:
                return False
        i += 1
        j += 1
    return True                                  # prefix consumed => selected


# ── TypedValue ──────────────────────────────────────────────────────────────
TV_STRING = 1
TV_INT = 2
TV_UINT = 3
TV_BOOL = 4
TV_JSON_IETF = 11


def enc_typed_json_ietf(json_text: str) -> bytes:
    """`json_ietf_val` (field 11) — the encoding gnmic.yaml declares
    (`encoding: json_ietf`). For a leaf this is the RFC 7951 JSON scalar."""
    return enc_bytes(TV_JSON_IETF, json_text.encode("utf-8"))


# ── Notification / Update ───────────────────────────────────────────────────
# message Update { Path path = 1; TypedValue val = 3; }
# message Notification { int64 timestamp = 1; Path prefix = 2;
#                        repeated Update update = 4; repeated Path delete = 5; }

def enc_update(elems: list[PathElem], typed_value: bytes) -> bytes:
    return enc_msg(1, enc_path(elems)) + enc_msg(3, typed_value)


def enc_notification(timestamp_ns: int, updates: list[bytes],
                     prefix: list[PathElem] | None = None,
                     target: str = "") -> bytes:
    out = enc_uint(1, timestamp_ns)
    if prefix or target:
        out += enc_msg(2, enc_path(prefix or [], target=target))
    for upd in updates:
        out += enc_msg(4, upd)
    return out


# ── SubscribeResponse ───────────────────────────────────────────────────────
# oneof response { Notification update = 1; bool sync_response = 3; }

def enc_subscribe_response_update(notification: bytes) -> bytes:
    return enc_msg(1, notification)


def enc_subscribe_response_sync() -> bytes:
    return enc_bool(3, True)


# ── SubscribeRequest ────────────────────────────────────────────────────────
# oneof request { SubscriptionList subscribe = 1; Poll poll = 3; }
# SubscriptionList: prefix=1 subscription=2 mode=5 encoding=8 updates_only=9
# Subscription:     path=1 mode=2 sample_interval=3 heartbeat_interval=5

LIST_MODE_STREAM, LIST_MODE_ONCE, LIST_MODE_POLL = 0, 1, 2
SUB_MODE_TARGET_DEFINED, SUB_MODE_ON_CHANGE, SUB_MODE_SAMPLE = 0, 1, 2

ENCODING_NAMES = {0: "json", 1: "bytes", 2: "proto", 3: "ascii",
                  4: "json_ietf"}


def dec_subscribe_request(buf: bytes) -> dict:
    """→ {"kind": "subscribe"|"poll", ...}. A SubscriptionList carries
    `prefix`, `mode`, `encoding`, `updates_only` and the subscription list."""
    fields = parse(buf)
    raw_list = _one(fields, 1)
    if raw_list is None:
        if 3 in fields:
            return {"kind": "poll"}
        raise ProtoError("SubscribeRequest: neither `subscribe` nor `poll`")
    lf = parse(raw_list)
    subs = []
    for raw_sub in lf.get(2, []):
        sf = parse(raw_sub)
        raw_path = _one(sf, 1)
        subs.append({
            "path": dec_path(raw_path)["elem"] if raw_path else [],
            "mode": int(_one(sf, 2, SUB_MODE_TARGET_DEFINED)),
            "sample_interval_ns": int(_one(sf, 3, 0)),
            "heartbeat_interval_ns": int(_one(sf, 5, 0)),
        })
    raw_prefix = _one(lf, 1)
    prefix = dec_path(raw_prefix) if raw_prefix else {"elem": [], "target": ""}
    return {
        "kind": "subscribe",
        "prefix": prefix["elem"],
        "target": prefix.get("target", ""),
        "subscriptions": subs,
        "mode": int(_one(lf, 5, LIST_MODE_STREAM)),
        "encoding": int(_one(lf, 8, 0)),
        "updates_only": bool(_one(lf, 9, 0)),
    }


# ── Capabilities ────────────────────────────────────────────────────────────
# CapabilityResponse: supported_models=1 supported_encodings=2 gNMI_version=3
# ModelData: name=1 organization=2 version=3

def enc_capability_response(models: list[tuple[str, str, str]],
                            encodings: list[int], version: str) -> bytes:
    out = bytearray()
    for name, org, ver in models:
        out += enc_msg(1, enc_str(1, name) + enc_str(2, org)
                       + enc_str(3, ver))
    for enc in encodings:
        out += enc_uint(2, enc)
    out += enc_str(3, version)
    return bytes(out)


# ── Get ─────────────────────────────────────────────────────────────────────
# GetRequest: prefix=1 path=2 type=3 encoding=5
# GetResponse: repeated Notification notification = 1

def dec_get_request(buf: bytes) -> dict:
    fields = parse(buf)
    raw_prefix = _one(fields, 1)
    prefix = dec_path(raw_prefix) if raw_prefix else {"elem": [], "target": ""}
    return {
        "prefix": prefix["elem"],
        "target": prefix.get("target", ""),
        "paths": [dec_path(p)["elem"] for p in fields.get(2, [])],
        "encoding": int(_one(fields, 5, 0)),
    }


def enc_get_response(notifications: list[bytes]) -> bytes:
    return b"".join(enc_msg(1, n) for n in notifications)
