"""HPACK (RFC 7541) codec — the header layer of the twin's gNMI target
(tracker 152, design §4.6).

Why this exists: serving gNMI means serving gRPC, which means speaking HTTP/2,
whose header compression is HPACK. The twin is LAB tooling that must stay
importable from a bare `python3` (design §4.1: no product dependency graph, no
new runtime wheels in the twin image), so the ~120 lines of HPACK we actually
need are implemented here instead of pulling `hpack`/`h2`/`grpcio` into the
lab image. Scope is deliberately the SERVER half of one gRPC conversation:

  * DECODE everything a conformant client may send (indexed, all three literal
    forms, dynamic-table insert + eviction, table-size update, Huffman strings)
    — gnmic's encoder is Go's `x/net/http2/hpack`, which Huffman-codes and
    incrementally indexes, so none of that is optional;
  * ENCODE the minimum that is always legal: literal-without-indexing with a
    literal, non-Huffman name/value. Our dynamic table therefore stays empty,
    which is why no encoder-side eviction logic exists.

TABLE PROVENANCE — the Huffman code table (RFC 7541 Appendix B) and the
61-entry static table (Appendix A) below were GENERATED, not transcribed, from
the Go module cache copy of `golang.org/x/net@v0.56.0/http2/hpack`
(`tables.go: huffmanCodes/huffmanCodeLen`, `static_table.go: ents`) — the same
pinned module version this repo vendors (CLAUDE.md §6). `tests/
test_gnmi_hpack.py` re-derives both from that source when it is present and
pins their digests otherwise, so a hand-edit of a single entry fails the gate.
"""
from __future__ import annotations

HUFFMAN = (
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
)

STATIC = (
    (':authority', ''),
    (':method', 'GET'),
    (':method', 'POST'),
    (':path', '/'),
    (':path', '/index.html'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '200'),
    (':status', '204'),
    (':status', '206'),
    (':status', '304'),
    (':status', '400'),
    (':status', '404'),
    (':status', '500'),
    ('accept-charset', ''),
    ('accept-encoding', 'gzip, deflate'),
    ('accept-language', ''),
    ('accept-ranges', ''),
    ('accept', ''),
    ('access-control-allow-origin', ''),
    ('age', ''),
    ('allow', ''),
    ('authorization', ''),
    ('cache-control', ''),
    ('content-disposition', ''),
    ('content-encoding', ''),
    ('content-language', ''),
    ('content-length', ''),
    ('content-location', ''),
    ('content-range', ''),
    ('content-type', ''),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('expect', ''),
    ('expires', ''),
    ('from', ''),
    ('host', ''),
    ('if-match', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('if-range', ''),
    ('if-unmodified-since', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('max-forwards', ''),
    ('proxy-authenticate', ''),
    ('proxy-authorization', ''),
    ('range', ''),
    ('referer', ''),
    ('refresh', ''),
    ('retry-after', ''),
    ('server', ''),
    ('set-cookie', ''),
    ('strict-transport-security', ''),
    ('transfer-encoding', ''),
    ('user-agent', ''),
    ('vary', ''),
    ('via', ''),
    ('www-authenticate', ''),
)

# (code, bit-length) per symbol 0..255. Symbol 256 (EOS, 30 bits of 1s) is
# deliberately absent: RFC 7541 §5.2 says a decoder MUST treat an encoded EOS
# as a decoding error, and our encoder never emits Huffman at all.
_BY_CODE = {(n, c): sym for sym, (c, n) in enumerate(HUFFMAN)}
_MAX_CODE_BITS = max(n for _c, n in HUFFMAN)

DEFAULT_DYNAMIC_TABLE_SIZE = 4096


class HpackError(ValueError):
    """A header block violated RFC 7541. Fatal for the connection (a decoder
    that guesses past a bad block corrupts every later block on the same
    connection, because the dynamic table is shared state)."""


def huffman_decode(data: bytes) -> str:
    """RFC 7541 §5.2 Huffman string → text. Padding must be the most
    significant bits of the EOS code (all ones) and shorter than one byte."""
    out = bytearray()
    cur = 0
    nbits = 0
    for byte in data:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            cur = (cur << 1) | ((byte >> shift) & 1)
            nbits += 1
            sym = _BY_CODE.get((nbits, cur))
            if sym is not None:
                out.append(sym)
                cur = 0
                nbits = 0
            elif nbits > _MAX_CODE_BITS:
                raise HpackError("huffman: no symbol within the longest code "
                                 "(EOS in the stream, or corrupt input)")
    if nbits >= 8:
        raise HpackError(f"huffman: {nbits} bits of padding (max 7)")
    if nbits and cur != (1 << nbits) - 1:
        raise HpackError("huffman: padding is not all ones")
    # latin-1: HPACK strings are octet strings; header values are not
    # guaranteed UTF-8 and a decode error here would be a DoS lever.
    return out.decode("latin-1")


def _read_int(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    """RFC 7541 §5.1 prefixed integer → (value, next position)."""
    mask = (1 << prefix_bits) - 1
    if pos >= len(buf):
        raise HpackError("integer: truncated prefix")
    value = buf[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(buf):
            raise HpackError("integer: truncated continuation")
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
        if shift > 28:  # >4 continuation octets is a bomb, not a header
            raise HpackError("integer: continuation too long")


def _read_str(buf: bytes, pos: int) -> tuple[str, int]:
    if pos >= len(buf):
        raise HpackError("string: truncated length")
    huff = bool(buf[pos] & 0x80)
    length, pos = _read_int(buf, pos, 7)
    end = pos + length
    if end > len(buf):
        raise HpackError("string: truncated body")
    raw = buf[pos:end]
    return (huffman_decode(raw) if huff else raw.decode("latin-1")), end


def _write_int(value: int, prefix_bits: int, flags: int) -> bytearray:
    mask = (1 << prefix_bits) - 1
    out = bytearray()
    if value < mask:
        out.append(flags | value)
        return out
    out.append(flags | mask)
    value -= mask
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return out


def _write_str(text: str) -> bytearray:
    raw = text.encode("latin-1", "replace")
    out = _write_int(len(raw), 7, 0x00)   # 0x00 = not Huffman-coded
    out += raw
    return out


def encode_headers(pairs: list[tuple[str, str]]) -> bytes:
    """Header list → one HPACK block, every field a literal WITHOUT indexing
    with a literal name (0x00 prefix). Always legal, keeps our dynamic table
    permanently empty, and costs nothing at gRPC header sizes."""
    out = bytearray()
    for name, value in pairs:
        out.append(0x00)
        out += _write_str(name.lower())
        out += _write_str(value)
    return bytes(out)


class Decoder:
    """Per-CONNECTION HPACK decoder. The dynamic table is connection state:
    one instance must serve every header block on one connection, in order."""

    def __init__(self, max_size: int = DEFAULT_DYNAMIC_TABLE_SIZE) -> None:
        self.max_size = max_size
        self._hard_max = max_size
        self.table: list[tuple[str, str]] = []   # newest first
        self.size = 0

    def _entry(self, index: int) -> tuple[str, str]:
        if index <= 0:
            raise HpackError("index 0 is not a header field")
        if index <= len(STATIC):
            return STATIC[index - 1]
        i = index - len(STATIC) - 1
        if i >= len(self.table):
            raise HpackError(f"index {index} past the dynamic table "
                             f"({len(self.table)} entries)")
        return self.table[i]

    def _insert(self, name: str, value: str) -> None:
        entry_size = len(name) + len(value) + 32   # RFC 7541 §4.1
        self.table.insert(0, (name, value))
        self.size += entry_size
        self._evict()

    def _evict(self) -> None:
        while self.size > self.max_size and self.table:
            name, value = self.table.pop()
            self.size -= len(name) + len(value) + 32

    def set_max_size(self, size: int) -> None:
        """Dynamic-table size update (§6.3). A value above the size we
        advertised in SETTINGS_HEADER_TABLE_SIZE is a protocol error — accepting
        it would let a peer pin unbounded memory in our table."""
        if size > self._hard_max:
            raise HpackError(f"dynamic table size update {size} exceeds the "
                             f"advertised maximum {self._hard_max}")
        self.max_size = size
        self._evict()

    def decode(self, block: bytes) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        pos = 0
        while pos < len(block):
            byte = block[pos]
            if byte & 0x80:                      # 1xxxxxxx indexed
                index, pos = _read_int(block, pos, 7)
                out.append(self._entry(index))
            elif byte & 0x40:                    # 01xxxxxx literal, index it
                index, pos = _read_int(block, pos, 6)
                name, pos = ((self._entry(index)[0], pos) if index
                             else _read_str(block, pos))
                value, pos = _read_str(block, pos)
                self._insert(name, value)
                out.append((name, value))
            elif byte & 0x20:                    # 001xxxxx table size update
                size, pos = _read_int(block, pos, 5)
                self.set_max_size(size)
            else:                                # 0000/0001 literal, no index
                index, pos = _read_int(block, pos, 4)
                name, pos = ((self._entry(index)[0], pos) if index
                             else _read_str(block, pos))
                value, pos = _read_str(block, pos)
                out.append((name, value))
        return out
