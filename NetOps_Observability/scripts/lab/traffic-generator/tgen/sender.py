# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""UDP sender with batched syscalls (sendmmsg) + token-bucket rate control.

The flow-telemetry encoders produce one datagram per batch of flows; this sends
them efficiently. sendmmsg pushes many datagrams in a single syscall (the DPDK
lesson, applied to a normal socket) — when unavailable it falls back to send.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import socket
import time

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True) if hasattr(ctypes, "CDLL") else None


class _iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class _mmsghdr(ctypes.Structure):
    class _msghdr(ctypes.Structure):
        _fields_ = [("msg_name", ctypes.c_void_p), ("msg_namelen", ctypes.c_uint),
                    ("msg_iov", ctypes.c_void_p), ("msg_iovlen", ctypes.c_size_t),
                    ("msg_control", ctypes.c_void_p), ("msg_controllen", ctypes.c_size_t),
                    ("msg_flags", ctypes.c_int)]
    _fields_ = [("msg_hdr", _msghdr), ("msg_len", ctypes.c_uint)]


class UdpSender:
    def __init__(self, host: str, port: int):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
        self._sockaddr = self._build_sockaddr(host, port)
        self._has_mmsg = _libc is not None and hasattr(_libc, "sendmmsg")
        self.sent = 0

    @staticmethod
    def _build_sockaddr(host: str, port: int) -> bytes:
        return struct_sockaddr_in(host, port)

    def send_batch(self, datagrams: list[bytes]) -> int:
        if not datagrams:
            return 0
        if self._has_mmsg and len(datagrams) > 1:
            try:
                return self._sendmmsg(datagrams)
            except OSError:
                pass  # fall back
        for d in datagrams:
            try:
                self.sock.sendto(d, self.addr)
                self.sent += 1
            except OSError:
                pass
        return len(datagrams)

    def _sendmmsg(self, datagrams: list[bytes]) -> int:
        n = len(datagrams)
        iov = (_iovec * n)()
        msgs = (_mmsghdr * n)()
        bufs = [ctypes.create_string_buffer(d, len(d)) for d in datagrams]
        sa = ctypes.create_string_buffer(self._sockaddr, len(self._sockaddr))
        for i, (d, buf) in enumerate(zip(datagrams, bufs)):
            iov[i].iov_base = ctypes.cast(buf, ctypes.c_void_p)
            iov[i].iov_len = len(d)
            msgs[i].msg_hdr.msg_name = ctypes.cast(sa, ctypes.c_void_p)
            msgs[i].msg_hdr.msg_namelen = len(self._sockaddr)
            msgs[i].msg_hdr.msg_iov = ctypes.cast(ctypes.byref(iov[i]), ctypes.c_void_p)
            msgs[i].msg_hdr.msg_iovlen = 1
        r = _libc.sendmmsg(self.sock.fileno(), msgs, n, 0)
        if r < 0:
            raise OSError(ctypes.get_errno(), "sendmmsg failed")
        self.sent += r
        return r


def struct_sockaddr_in(host: str, port: int) -> bytes:
    import struct
    return struct.pack("!H", socket.AF_INET) + struct.pack("!H", port) + socket.inet_aton(host) + b"\x00" * 8


class RateLimiter:
    """Token bucket — `rate` tokens/sec, used to pace flows or packets."""

    def __init__(self, rate: float, burst: float | None = None):
        self.rate = max(rate, 1e-9)
        self.capacity = burst if burst is not None else max(rate, 1.0)
        self.tokens = self.capacity
        self.t = time.monotonic()

    def take(self, n: float = 1.0) -> None:
        while True:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= n:
                self.tokens -= n
                return
            time.sleep(max((n - self.tokens) / self.rate, 0.0005))
