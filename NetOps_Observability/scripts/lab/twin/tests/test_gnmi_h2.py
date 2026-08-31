"""HTTP/2 + gRPC frame layer (gnmi_h2), driven over a REAL loopback socket.

A framing bug here is invisible in unit tests of the layers above it, so these
tests speak the wire: client preface, SETTINGS exchange, HPACK HEADERS, a
length-prefixed gRPC request, then the response frames and trailers. The
handler under test is a stub, not the gNMI service — this file proves the
transport, `test_gnmi_server.py` proves the semantics.
"""
import socket
import struct
import threading
import time

import gnmi_hpack as hpack
import pytest
from gnmi_h2 import (
    ERR_PROTOCOL_ERROR,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FRAME_DATA,
    FRAME_GOAWAY,
    FRAME_HEADERS,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    GRPC_OK,
    MAX_REQUEST_BYTES,
    PREFACE,
    Connection,
    GrpcStatus,
    grpc_frame,
)


class Client:
    """The smallest conformant HTTP/2 client that can drive one gRPC call."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = bytearray()
        self.dec = hpack.Decoder()
        self.sock.settimeout(5.0)
        self.sock.sendall(PREFACE)
        self.send(FRAME_SETTINGS, 0, 0, b"")

    def send(self, ftype, flags, stream_id, payload=b""):
        head = struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) \
            + struct.pack("!I", stream_id)
        self.sock.sendall(head + payload)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("server closed")
            self.buf += chunk

    def frame(self):
        self._fill(9)
        length = int.from_bytes(self.buf[0:3], "big")
        ftype, flags = self.buf[3], self.buf[4]
        stream_id = struct.unpack("!I", bytes(self.buf[5:9]))[0] & 0x7FFFFFFF
        self._fill(9 + length)
        payload = bytes(self.buf[9:9 + length])
        del self.buf[:9 + length]
        return ftype, flags, stream_id, payload

    def open_rpc(self, path, body, stream_id=1, end_stream=False):
        block = hpack.encode_headers([
            (":method", "POST"), (":scheme", "http"), (":path", path),
            (":authority", "twin"), ("content-type", "application/grpc"),
            ("te", "trailers")])
        self.send(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, block)
        self.send(FRAME_DATA, FLAG_END_STREAM if end_stream else 0,
                  stream_id, grpc_frame(body))

    def collect(self, n_messages, deadline_s=5.0):
        """Read until `n_messages` DATA messages and the trailers arrive."""
        messages, headers, trailers = [], None, None
        pending = bytearray()
        end = time.monotonic() + deadline_s
        while time.monotonic() < end:
            ftype, flags, _sid, payload = self.frame()
            if ftype == FRAME_SETTINGS and not flags & FLAG_ACK:
                self.send(FRAME_SETTINGS, FLAG_ACK, 0, b"")
            elif ftype == FRAME_HEADERS:
                fields = dict(self.dec.decode(payload))
                if headers is None:
                    headers = fields
                else:
                    trailers = fields
            elif ftype == FRAME_DATA:
                pending += payload
                while len(pending) >= 5:
                    size = struct.unpack("!I", bytes(pending[1:5]))[0]
                    if len(pending) < 5 + size:
                        break
                    messages.append(bytes(pending[5:5 + size]))
                    del pending[:5 + size]
            if trailers is not None and len(messages) >= n_messages:
                return headers, messages, trailers
        raise AssertionError(f"timed out: {len(messages)} msgs, "
                             f"trailers={trailers}")


@pytest.fixture
def server():
    """A live Connection on loopback; the fixture yields (client, state)."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    state = {"handler": None, "conn": None, "ctx": None, "request": None}

    def dispatch(path, ctx, request):
        state["ctx"] = ctx
        state["request"] = request
        yield from state["handler"](path, ctx, request)

    def accept():
        conn_sock, _peer = listener.accept()
        state["conn"] = Connection(conn_sock, dispatch)
        state["conn"].serve()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    client_sock = socket.create_connection(("127.0.0.1", port), 5.0)
    client = Client(client_sock)
    try:
        yield client, state
    finally:
        client_sock.close()
        listener.close()
        thread.join(timeout=3)


def test_unary_rpc_returns_headers_message_and_ok_trailers(server):
    client, state = server
    state["handler"] = lambda path, ctx, req: iter([b"pong:" + req])
    client.open_rpc("/gnmi.gNMI/Capabilities", b"ping", end_stream=True)
    headers, messages, trailers = client.collect(1)
    assert headers[":status"] == "200"
    assert headers["content-type"] == "application/grpc"
    assert messages == [b"pong:ping"]
    assert trailers["grpc-status"] == str(GRPC_OK)
    assert state["request"] == b"ping"


def test_rpc_starts_on_the_first_message_without_half_close(server):
    """A gNMI Subscribe client keeps its stream open; waiting for END_STREAM
    would hang every subscription."""
    client, state = server
    state["handler"] = lambda path, ctx, req: iter([b"a", b"b", b"c"])
    client.open_rpc("/gnmi.gNMI/Subscribe", b"req", end_stream=False)
    _headers, messages, trailers = client.collect(3)
    assert messages == [b"a", b"b", b"c"]
    assert trailers["grpc-status"] == "0"


def test_request_path_reaches_the_handler_context(server):
    client, state = server
    seen = {}

    def handler(path, ctx, req):
        seen["path"] = path
        seen["authority"] = ctx.headers.get(":authority")
        return iter([b""])

    state["handler"] = handler
    client.open_rpc("/gnmi.gNMI/Get", b"", end_stream=True)
    client.collect(1)
    assert seen == {"path": "/gnmi.gNMI/Get", "authority": "twin"}


def test_handler_grpc_status_becomes_trailers_not_a_dropped_stream(server):
    client, state = server

    def handler(path, ctx, req):
        raise GrpcStatus(12, "POLL subscriptions are not served")
        yield  # pragma: no cover - generator marker

    state["handler"] = handler
    client.open_rpc("/gnmi.gNMI/Subscribe", b"", end_stream=True)
    _headers, messages, trailers = client.collect(0)
    assert messages == []
    assert trailers["grpc-status"] == "12"
    assert "POLL" in trailers["grpc-message"]


def test_handler_crash_is_internal_on_that_stream_and_the_target_survives(
        server):
    client, state = server

    def boom(path, ctx, req):
        raise RuntimeError("kaboom")
        yield  # pragma: no cover - generator marker

    state["handler"] = boom
    client.open_rpc("/gnmi.gNMI/Get", b"", stream_id=1, end_stream=True)
    _h, _m, trailers = client.collect(0)
    assert trailers["grpc-status"] == "13"
    assert "kaboom" in trailers["grpc-message"]
    # the connection is still usable for the next stream
    state["handler"] = lambda path, ctx, req: iter([b"ok"])
    client.open_rpc("/gnmi.gNMI/Get", b"", stream_id=3, end_stream=True)
    _h2, messages, trailers2 = client.collect(1)
    assert messages == [b"ok"] and trailers2["grpc-status"] == "0"


def test_rst_stream_cancels_a_streaming_handler_promptly(server):
    """`ctx.wait()` must return on cancellation, not sleep out its interval —
    otherwise a 30 s sample interval delays teardown by 30 s."""
    client, state = server
    started = threading.Event()
    stopped = threading.Event()

    def forever(path, ctx, req):
        started.set()
        while ctx.wait(30.0):
            yield b"tick"
        stopped.set()

    state["handler"] = forever
    client.open_rpc("/gnmi.gNMI/Subscribe", b"", end_stream=False)
    assert started.wait(5.0)
    client.send(FRAME_RST_STREAM, 0, 1, struct.pack("!I", 8))
    assert stopped.wait(5.0)


def test_server_grants_receive_window_beyond_the_65535_default(server):
    """Without connection-level WINDOW_UPDATEs a long stream stalls at 64 KiB.
    The server must advertise more up front."""
    client, state = server
    state["handler"] = lambda path, ctx, req: iter([b""])
    granted = 0
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        ftype, flags, sid, payload = client.frame()
        if ftype == FRAME_SETTINGS and not flags & FLAG_ACK:
            client.send(FRAME_SETTINGS, FLAG_ACK, 0, b"")
        if ftype == FRAME_WINDOW_UPDATE and sid == 0:
            granted = struct.unpack("!I", payload)[0]
            break
    assert granted > 65535


def test_a_body_larger_than_the_served_maximum_is_refused_with_goaway(server):
    """Zero-trust: a peer must not be able to make the lab target buffer
    unbounded request bytes. The connection is torn down with GOAWAY."""
    client, state = server
    state["handler"] = lambda path, ctx, req: iter([b""])
    block = hpack.encode_headers([(":method", "POST"), (":scheme", "http"),
                                  (":path", "/gnmi.gNMI/Get")])
    client.send(FRAME_HEADERS, FLAG_END_HEADERS, 1, block)
    # A gRPC message header declaring far more than will ever arrive, then
    # MAX_REQUEST_BYTES worth of body.
    body = struct.pack("!I", 1 << 30)
    saw_goaway = False
    try:
        client.send(FRAME_DATA, 0, 1, b"\x00" + body)
        for _ in range(1 + (MAX_REQUEST_BYTES // (1 << 14))):
            client.send(FRAME_DATA, 0, 1, b"\x00" * (1 << 14))
    except OSError:
        saw_goaway = True          # server already tore the connection down
    deadline = time.monotonic() + 5.0
    while not saw_goaway and time.monotonic() < deadline:
        try:
            ftype, _flags, _sid, _payload = client.frame()
        except (ConnectionError, OSError):
            break
        if ftype == FRAME_GOAWAY:
            saw_goaway = True
    assert saw_goaway, "server buffered an unbounded request body"


def test_bad_client_preface_is_refused_without_serving_the_rpc():
    """A non-HTTP/2 peer gets nothing but a closed connection — no 200, no
    header block, no handler invocation."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    called = threading.Event()

    def handler(path, ctx, req):
        called.set()
        yield b""

    def accept():
        conn_sock, _peer = listener.accept()
        Connection(conn_sock, handler).serve()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    sock = socket.create_connection(("127.0.0.1", port), 5.0)
    sock.settimeout(5.0)
    sock.sendall(b"GET / HTTP/1.1\r\nHost: twin\r\n\r\n" + b"x" * 64)
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except (TimeoutError, OSError):
        pass
    sock.close()
    listener.close()
    thread.join(timeout=3)
    assert not called.is_set()
    assert b":status" not in data
    # what it DOES get is a GOAWAY(PROTOCOL_ERROR) on stream 0, then a close
    assert data[3] == FRAME_GOAWAY
    assert struct.unpack("!II", data[9:17]) == (0, ERR_PROTOCOL_ERROR)
