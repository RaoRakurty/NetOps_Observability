"""Minimal HTTP/2 (h2c) + gRPC server frame layer (tracker 152, design §4.6).

The SERVER half of exactly one conversation: a gRPC client dials plaintext
HTTP/2 with prior knowledge (what `gnmic`'s `insecure: true` targets do — the
cEOS `:6030` rows in `deployment/docker/gnmic/gnmic.yaml`), opens one stream
per RPC, sends one request message, and reads a unary reply or a long-lived
server stream.

Implemented because the alternative is `grpcio` + `protobuf` wheels in the twin
lab image for a lab-only capability (design §4.1 / CLAUDE.md §6 "when in doubt,
stdlib"). NOT implemented, on purpose: TLS, server push, PRIORITY, header
CONTINUATION on the SEND side, trailers-only fast path, client streaming.
Anything unrecognised is refused loudly rather than ignored — a lab target that
silently mis-serves a subscription would poison a labelled accuracy corpus.

Zero-trust framing: every frame length is checked against SETTINGS_MAX_FRAME_SIZE
before a single byte is buffered, per-stream request buffers are capped, the
number of concurrent streams is capped, and flow-control windows are honoured
in BOTH directions (a stream that ignores the peer's window deadlocks a real
client).
"""
from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable, Iterator

import gnmi_hpack as hpack

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5

ERR_NO_ERROR = 0x0
ERR_PROTOCOL_ERROR = 0x1
ERR_INTERNAL_ERROR = 0x2
ERR_FLOW_CONTROL_ERROR = 0x3

GRPC_OK = 0
GRPC_INVALID_ARGUMENT = 3
GRPC_NOT_FOUND = 5
GRPC_UNIMPLEMENTED = 12
GRPC_INTERNAL = 13

# Caps: a lab target still refuses to be a memory sink for a hostile peer.
MAX_FRAME_SIZE = 1 << 14              # 16 KiB, the HTTP/2 default
MAX_REQUEST_BYTES = 1 << 20           # one gNMI request is ~hundreds of bytes
MAX_CONCURRENT_STREAMS = 64
OUR_WINDOW = 1 << 20                  # what we let a peer send us, refreshed


class H2Error(Exception):
    """Connection-fatal protocol violation."""

    def __init__(self, message: str, code: int = ERR_PROTOCOL_ERROR) -> None:
        super().__init__(message)
        self.code = code


class GrpcStatus(Exception):
    """Handler-raised, non-fatal: becomes gRPC trailers on this stream only."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def grpc_frame(payload: bytes) -> bytes:
    """gRPC length-prefixed message: 1 compressed-flag octet + 4-octet length."""
    return b"\x00" + struct.pack("!I", len(payload)) + payload


class StreamContext:
    """What a handler is allowed to know about its stream: the request
    headers, and whether the peer has gone away. `wait()` is the ONLY sleep a
    streaming handler may use — it returns immediately on cancellation, so a
    30 s sample interval never delays teardown by 30 s."""

    def __init__(self, stream_id: int, headers: dict[str, str]) -> None:
        self.stream_id = stream_id
        self.headers = headers
        self.cancelled = threading.Event()

    def wait(self, seconds: float) -> bool:
        """Sleep up to `seconds`; True if still live, False if cancelled."""
        return not self.cancelled.wait(seconds)


class _Stream:
    def __init__(self, stream_id: int, send_window: int) -> None:
        self.id = stream_id
        self.headers: dict[str, str] = {}
        self.buf = bytearray()
        self.send_window = send_window
        self.recv_bytes = 0
        self.started = False
        self.ended = False
        self.ctx: StreamContext | None = None
        self.thread: threading.Thread | None = None


# handler(rpc_path, ctx, request_bytes) -> iterator of response message bytes
Handler = Callable[[str, StreamContext, bytes], Iterator[bytes]]


class Connection:
    """One client connection. The reader loop runs on the calling thread;
    each RPC runs on its own thread so a long Subscribe never blocks PING,
    WINDOW_UPDATE or RST_STREAM processing."""

    def __init__(self, sock: socket.socket, handler: Handler,
                 log: Callable[[str], None] = lambda _m: None) -> None:
        self.sock = sock
        self.handler = handler
        self.log = log
        self.dec = hpack.Decoder(hpack.DEFAULT_DYNAMIC_TABLE_SIZE)
        self.streams: dict[int, _Stream] = {}
        self.peer_initial_window = 65535
        self.peer_max_frame = MAX_FRAME_SIZE
        self.conn_send_window = 65535
        self.window_cv = threading.Condition()
        self.send_lock = threading.Lock()
        self.closed = threading.Event()
        self._rx = bytearray()

    # -- socket plumbing ---------------------------------------------------
    def _recv_exactly(self, n: int) -> bytes:
        while len(self._rx) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed")
            self._rx += chunk
        out = bytes(self._rx[:n])
        del self._rx[:n]
        return out

    def _send_frame(self, ftype: int, flags: int, stream_id: int,
                    payload: bytes = b"") -> None:
        header = struct.pack("!I", len(payload))[1:] + bytes(
            [ftype, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF)
        with self.send_lock:
            if self.closed.is_set():
                return
            try:
                self.sock.sendall(header + payload)
            except OSError as exc:
                self.closed.set()
                raise ConnectionError(f"send failed: {exc}") from exc

    # -- flow control ------------------------------------------------------
    def _claim_window(self, stream: _Stream, want: int) -> int:
        """Reserve up to `want` octets of BOTH windows, blocking until some
        capacity exists. Returns 0 only when the connection is going away."""
        with self.window_cv:
            while not self.closed.is_set():
                n = min(want, self.conn_send_window, stream.send_window,
                        self.peer_max_frame)
                if n > 0:
                    self.conn_send_window -= n
                    stream.send_window -= n
                    return n
                self.window_cv.wait(1.0)
        return 0

    # -- response writing --------------------------------------------------
    def send_headers(self, stream_id: int, pairs: list[tuple[str, str]],
                     end_stream: bool = False) -> None:
        block = hpack.encode_headers(pairs)
        if len(block) > self.peer_max_frame:
            # Our header blocks are a handful of short ASCII fields; exceeding
            # the peer's frame size would mean CONTINUATION, which we do not
            # emit. Fail loudly rather than truncate.
            raise H2Error("response header block exceeds the peer's max frame")
        flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
        self._send_frame(FRAME_HEADERS, flags, stream_id, block)

    def send_message(self, stream: _Stream, payload: bytes) -> None:
        data = grpc_frame(payload)
        pos = 0
        while pos < len(data):
            n = self._claim_window(stream, len(data) - pos)
            if n <= 0:
                raise ConnectionError("connection closing")
            self._send_frame(FRAME_DATA, 0, stream.id, data[pos:pos + n])
            pos += n

    # -- RPC dispatch ------------------------------------------------------
    def _run_rpc(self, stream: _Stream, request: bytes) -> None:
        ctx = stream.ctx
        assert ctx is not None
        path = ctx.headers.get(":path", "")
        status, message = GRPC_OK, ""
        try:
            self.send_headers(stream.id, [
                (":status", "200"),
                ("content-type", "application/grpc"),
            ])
            for payload in self.handler(path, ctx, request):
                if ctx.cancelled.is_set() or self.closed.is_set():
                    return
                self.send_message(stream, payload)
        except GrpcStatus as exc:
            status, message = exc.code, exc.message
        except ConnectionError:
            return
        except Exception as exc:                          # noqa: BLE001
            # A handler bug must not take the target down: report INTERNAL on
            # this stream and keep serving the other devices' subscriptions.
            status, message = GRPC_INTERNAL, f"{type(exc).__name__}: {exc}"
            self.log(f"stream {stream.id}: handler error: {message}")
        try:
            trailers = [("grpc-status", str(status))]
            if message:
                trailers.append(("grpc-message", message.replace("\n", " ")))
            self.send_headers(stream.id, trailers, end_stream=True)
        except (ConnectionError, H2Error):
            pass

    def _maybe_dispatch(self, stream: _Stream) -> None:
        """Start the RPC as soon as ONE complete gRPC message has arrived —
        NOT at END_STREAM. A gNMI Subscribe client keeps its stream open
        (POLL mode may send more requests), so waiting for half-close would
        hang every subscription."""
        if stream.started or len(stream.buf) < 5:
            return
        length = struct.unpack("!I", bytes(stream.buf[1:5]))[0]
        if len(stream.buf) < 5 + length:
            return
        if stream.buf[0] != 0:
            raise H2Error("compressed gRPC messages are not served")
        request = bytes(stream.buf[5:5 + length])
        del stream.buf[:5 + length]
        stream.started = True
        stream.thread = threading.Thread(
            target=self._run_rpc, args=(stream, request),
            name=f"rpc-{stream.id}", daemon=True)
        stream.thread.start()

    # -- frame handlers ----------------------------------------------------
    def _on_settings(self, flags: int, payload: bytes) -> None:
        if flags & FLAG_ACK:
            return
        if len(payload) % 6:
            raise H2Error("SETTINGS length is not a multiple of 6")
        for i in range(0, len(payload), 6):
            ident, value = struct.unpack("!HI", payload[i:i + 6])
            if ident == SETTINGS_INITIAL_WINDOW_SIZE:
                if value > 0x7FFFFFFF:
                    raise H2Error("INITIAL_WINDOW_SIZE too large",
                                  ERR_FLOW_CONTROL_ERROR)
                delta = value - self.peer_initial_window
                self.peer_initial_window = value
                with self.window_cv:
                    for st in self.streams.values():
                        st.send_window += delta
                    self.window_cv.notify_all()
            elif ident == SETTINGS_MAX_FRAME_SIZE:
                if not (1 << 14) <= value <= (1 << 24) - 1:
                    raise H2Error("MAX_FRAME_SIZE out of range")
                self.peer_max_frame = min(value, MAX_FRAME_SIZE)
        self._send_frame(FRAME_SETTINGS, FLAG_ACK, 0)

    def _on_headers(self, stream_id: int, flags: int, payload: bytes) -> None:
        if stream_id == 0 or not stream_id % 2:
            raise H2Error(f"HEADERS on illegal stream {stream_id}")
        body = memoryview(payload)
        if flags & FLAG_PADDED:
            pad = body[0]
            body = body[1:len(body) - pad]
        if flags & FLAG_PRIORITY:
            body = body[5:]
        block = bytes(body)
        while not flags & FLAG_END_HEADERS:
            ftype, cflags, cstream, cpayload = self._read_frame()
            if ftype != FRAME_CONTINUATION or cstream != stream_id:
                raise H2Error("expected CONTINUATION for the open header block")
            block += cpayload
            flags = cflags
        if len(self.streams) >= MAX_CONCURRENT_STREAMS:
            self._send_frame(FRAME_RST_STREAM, 0, stream_id,
                             struct.pack("!I", ERR_PROTOCOL_ERROR))
            return
        stream = _Stream(stream_id, self.peer_initial_window)
        stream.headers = {n: v for n, v in self.dec.decode(block)}
        stream.ctx = StreamContext(stream_id, stream.headers)
        self.streams[stream_id] = stream
        # Give the peer room to send its request body immediately.
        self._send_frame(FRAME_WINDOW_UPDATE, 0, stream_id,
                         struct.pack("!I", OUR_WINDOW))

    def _on_data(self, stream_id: int, flags: int, payload: bytes) -> None:
        stream = self.streams.get(stream_id)
        body = payload
        if flags & FLAG_PADDED and body:
            body = body[1:len(body) - body[0]]
        if stream is None:
            return                                   # already reset/closed
        stream.recv_bytes += len(payload)
        if stream.recv_bytes > MAX_REQUEST_BYTES:
            raise H2Error("request body exceeds the served maximum")
        stream.buf += body
        # Refresh both windows by exactly what was consumed.
        if payload:
            self._send_frame(FRAME_WINDOW_UPDATE, 0, 0,
                             struct.pack("!I", len(payload)))
            self._send_frame(FRAME_WINDOW_UPDATE, 0, stream_id,
                             struct.pack("!I", len(payload)))
        self._maybe_dispatch(stream)
        if flags & FLAG_END_STREAM:
            stream.ended = True

    def _on_window_update(self, stream_id: int, payload: bytes) -> None:
        if len(payload) != 4:
            raise H2Error("WINDOW_UPDATE length is not 4")
        inc = struct.unpack("!I", payload)[0] & 0x7FFFFFFF
        if inc == 0:
            raise H2Error("WINDOW_UPDATE increment 0", ERR_PROTOCOL_ERROR)
        with self.window_cv:
            if stream_id == 0:
                self.conn_send_window += inc
            elif stream_id in self.streams:
                self.streams[stream_id].send_window += inc
            self.window_cv.notify_all()

    def _on_rst(self, stream_id: int) -> None:
        stream = self.streams.pop(stream_id, None)
        if stream and stream.ctx:
            stream.ctx.cancelled.set()
        with self.window_cv:
            self.window_cv.notify_all()

    def _read_frame(self) -> tuple[int, int, int, bytes]:
        head = self._recv_exactly(9)
        length = int.from_bytes(head[0:3], "big")
        ftype, flags = head[3], head[4]
        stream_id = struct.unpack("!I", head[5:9])[0] & 0x7FFFFFFF
        if length > MAX_FRAME_SIZE:
            raise H2Error(f"frame length {length} exceeds our advertised "
                          f"maximum {MAX_FRAME_SIZE}")
        return ftype, flags, stream_id, self._recv_exactly(length)

    # -- main loop ---------------------------------------------------------
    def serve(self) -> None:
        try:
            if self._recv_exactly(len(PREFACE)) != PREFACE:
                raise H2Error("bad HTTP/2 client preface")
            self._send_frame(FRAME_SETTINGS, 0, 0, struct.pack(
                "!HIHIHI",
                SETTINGS_HEADER_TABLE_SIZE, hpack.DEFAULT_DYNAMIC_TABLE_SIZE,
                SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS,
                SETTINGS_MAX_FRAME_SIZE, MAX_FRAME_SIZE))
            # Connection-level receive window above the 65535 default.
            self._send_frame(FRAME_WINDOW_UPDATE, 0, 0,
                             struct.pack("!I", OUR_WINDOW))
            while not self.closed.is_set():
                ftype, flags, stream_id, payload = self._read_frame()
                if ftype == FRAME_SETTINGS:
                    self._on_settings(flags, payload)
                elif ftype == FRAME_HEADERS:
                    self._on_headers(stream_id, flags, payload)
                elif ftype == FRAME_DATA:
                    self._on_data(stream_id, flags, payload)
                elif ftype == FRAME_WINDOW_UPDATE:
                    self._on_window_update(stream_id, payload)
                elif ftype == FRAME_RST_STREAM:
                    self._on_rst(stream_id)
                elif ftype == FRAME_PING:
                    if not flags & FLAG_ACK:
                        self._send_frame(FRAME_PING, FLAG_ACK, 0, payload)
                elif ftype == FRAME_GOAWAY:
                    break
                elif ftype in (FRAME_PRIORITY, FRAME_CONTINUATION):
                    continue          # PRIORITY is advisory; stray CONTINUATION
                elif ftype == FRAME_PUSH_PROMISE:
                    raise H2Error("PUSH_PROMISE from a client is illegal")
                # Unknown frame types are ignored, as RFC 9113 §4.1 requires.
        except (ConnectionError, OSError):
            pass
        except H2Error as exc:
            self.log(f"protocol error: {exc}")
            try:
                self._send_frame(FRAME_GOAWAY, 0, 0,
                                 struct.pack("!II", 0, exc.code))
            except (ConnectionError, OSError):
                pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self.closed.set()
        for stream in list(self.streams.values()):
            if stream.ctx:
                stream.ctx.cancelled.set()
        with self.window_cv:
            self.window_cv.notify_all()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
