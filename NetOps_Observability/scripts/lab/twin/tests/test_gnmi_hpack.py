# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""HPACK codec (gnmi_hpack) — the header layer of the twin gNMI target.

Two jobs: prove the RFC 7541 codec is correct against the RFC's own examples,
and prove the two GENERATED tables still match their source of truth. A single
wrong Huffman entry decodes silently-wrong headers, which would show up as an
unexplained gNMI outage months later; the provenance test makes a hand-edit
fail here instead.
"""
import glob
import hashlib
import re

import pytest
from gnmi_hpack import (
    HUFFMAN,
    STATIC,
    Decoder,
    HpackError,
    _read_int,
    _read_str,
    _write_int,
    encode_headers,
    huffman_decode,
)

GO_HPACK_GLOB = "/home/rao/go/pkg/mod/golang.org/x/net@*/http2/hpack"


# ── table provenance ────────────────────────────────────────────────────────

def _go_hpack_dir():
    hits = sorted(glob.glob(GO_HPACK_GLOB))
    return hits[-1] if hits else None


def test_static_table_is_the_61_entry_rfc7541_appendix_a():
    assert len(STATIC) == 61
    assert STATIC[0] == (":authority", "")
    assert STATIC[1] == (":method", "GET")
    assert STATIC[60] == ("www-authenticate", "")


def test_huffman_table_shape_and_digest_are_pinned():
    """Digest pin: the table is generated, so any edit — deliberate or not —
    has to be re-justified rather than slipping through."""
    assert len(HUFFMAN) == 256
    assert HUFFMAN[0] == (0x1FF8, 13)          # RFC 7541 Appendix B, sym 0
    assert HUFFMAN[ord("0")] == (0x0, 5)
    assert HUFFMAN[ord("a")] == (0x3, 5)
    blob = ";".join(f"{c:x}:{n}" for c, n in HUFFMAN).encode()
    assert (hashlib.sha256(blob).hexdigest()
            == "d3533abf39de5024d0c867d48804f0b069cd4d48c9b083eb5beb7cf8e40b85a8")


def test_huffman_table_matches_the_vendored_go_source_when_present():
    """Re-derive from `golang.org/x/net .../hpack/tables.go` — the module this
    repo pins (CLAUDE.md §6) and the file the table was generated from."""
    go_dir = _go_hpack_dir()
    if not go_dir:
        pytest.skip("go module cache copy of x/net/http2/hpack not present")
    with open(f"{go_dir}/tables.go", encoding="utf-8") as fh:
        src = fh.read()

    def arr(name):
        i = src.index("var " + name)
        body = src[src.index("{", i) + 1:src.index("}", i)]
        return [t.strip() for t in body.replace("\n", ",").split(",")
                if t.strip()]

    codes = [int(x, 16) for x in arr("huffmanCodes")]
    lens = [int(x) for x in arr("huffmanCodeLen")]
    assert list(HUFFMAN) == list(zip(codes, lens))

    with open(f"{go_dir}/static_table.go", encoding="utf-8") as fh:
        static_src = fh.read()
    ents = re.findall(r'\{Name: "([^"]*)", Value: "([^"]*)", Sensitive: false\}',
                      static_src)
    assert list(STATIC) == ents


# ── primitives ──────────────────────────────────────────────────────────────

def test_prefixed_integer_round_trips_rfc_examples():
    # RFC 7541 C.1: 10 in a 5-bit prefix, 1337 in a 5-bit prefix, 42 in 8-bit
    assert _read_int(bytes(_write_int(10, 5, 0)), 0, 5) == (10, 1)
    encoded = bytes(_write_int(1337, 5, 0))
    assert encoded == b"\x1f\x9a\x0a"
    assert _read_int(encoded, 0, 5) == (1337, 3)
    assert _read_int(bytes(_write_int(42, 8, 0)), 0, 8) == (42, 1)


def test_integer_continuation_bomb_is_refused():
    with pytest.raises(HpackError):
        _read_int(b"\x1f" + b"\xff" * 8 + b"\x00", 0, 5)


def test_huffman_decodes_rfc7541_c43_example():
    raw = bytes([0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97,
                 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3])
    assert huffman_decode(raw) == "https://www.example.com"


def test_huffman_rejects_over_long_padding_and_non_ones_padding():
    with pytest.raises(HpackError):
        huffman_decode(b"\x00" * 4)          # padding is not all ones
    # 'a' is 5 bits (0b00011); pad the remaining 3 with zeros -> invalid
    with pytest.raises(HpackError):
        huffman_decode(bytes([0b00011000]))


def test_string_reader_refuses_a_length_past_the_buffer():
    with pytest.raises(HpackError):
        _read_str(b"\x7f", 0)


# ── decoder ─────────────────────────────────────────────────────────────────

def test_indexed_field_resolves_from_the_static_table():
    assert Decoder().decode(b"\x82") == [(":method", "GET")]


def test_literal_with_incremental_indexing_inserts_and_is_reusable():
    """RFC 7541 C.2.1 then an indexed reference to what it inserted."""
    dec = Decoder()
    block = (b"\x40\x0acustom-key\x0dcustom-header")
    assert dec.decode(block) == [("custom-key", "custom-header")]
    assert dec.size == len("custom-key") + len("custom-header") + 32
    assert dec.decode(b"\xbe") == [("custom-key", "custom-header")]


def test_dynamic_table_evicts_oldest_first_when_over_size():
    dec = Decoder(max_size=64)          # room for exactly one small entry
    dec.decode(b"\x40\x01a\x01x")
    dec.decode(b"\x40\x01b\x01y")
    assert [n for n, _v in dec.table] == ["b"]


def test_table_size_update_shrinks_and_evicts():
    dec = Decoder(max_size=4096)
    dec.decode(b"\x40\x01a\x01x")
    dec.decode(b"\x20")                 # 001xxxxx, size 0
    assert dec.table == []
    assert dec.max_size == 0


def test_table_size_update_above_the_advertised_maximum_is_refused():
    """A peer must never be able to pin unbounded memory in our table."""
    dec = Decoder(max_size=4096)
    with pytest.raises(HpackError):
        dec.decode(b"\x3f\xe2\x1f")     # 5-bit prefix, value 4097


def test_index_past_the_dynamic_table_is_refused():
    with pytest.raises(HpackError):
        Decoder().decode(b"\xbe")
    with pytest.raises(HpackError):
        Decoder().decode(b"\x80")       # index 0 is illegal


# ── encoder ─────────────────────────────────────────────────────────────────

def test_encode_headers_round_trips_and_leaves_the_table_empty():
    pairs = [(":status", "200"), ("content-type", "application/grpc"),
             ("grpc-status", "0")]
    dec = Decoder()
    assert dec.decode(encode_headers(pairs)) == pairs
    assert dec.table == [] and dec.size == 0


def test_encode_headers_lowercases_names():
    """HTTP/2 field names MUST be lowercase; a capitalised one is a stream
    error at a conformant client."""
    dec = Decoder()
    assert dec.decode(encode_headers([("Grpc-Status", "0")])) \
        == [("grpc-status", "0")]
