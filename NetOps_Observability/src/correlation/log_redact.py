# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Credential backstop for the correlation engine's logs (tracker 367, §8).

The Python twin of src/backend/internal/logredact: the same patterns, tested
against the same corpus (src/contracts/log_redaction_corpus.json), so the two
redactors cannot drift. It is a BACKSTOP — credentials should never reach a log
— that masks one if it does: URL userinfo, Authorization headers, bearer
tokens, password/secret/token key=value and JSON pairs, PEM private keys.

`install()` wraps every handler's formatter on the root and uvicorn loggers, so
the redaction applies to the FINAL text — message, args and traceback alike.
"""

from __future__ import annotations

import logging
import re

MASK = "***"

_TRIGGERS = ("://", "assword", "asswd", "ecret", "oken", "pi_key", "pikey",
             "uthorization", "earer", "begin", "redential")

_PEM = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END ([A-Z ]*)PRIVATE KEY-----")
_USERPASS = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)([^/@\s:\"'<>]+):([^/@\s\"'<>]+)@")
_USERONLY = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)([^/@\s:\"'<>]+)@")
_AUTHZ = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)(basic|bearer|token)\s+[A-Za-z0-9._~+/=\-]+")
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{8,}=*")
_JSON = re.compile(r"(?i)(\"[A-Za-z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|credentials?)\"\s*:\s*)\"(?:[^\"\\]|\\.)*\"")
_KV = re.compile(r"(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|credentials?))(\s*[=:]\s*)(\"?)([^\s\"&,;'}]+)")


def _may_contain(s: str) -> bool:
    low = s.lower()
    return any(t in low for t in _TRIGGERS)


def _kv(m: re.Match[str]) -> str:
    if m.group(4) == MASK:
        return m.group(0)
    return m.group(1) + m.group(2) + m.group(3) + MASK


def redact(s: str) -> str:
    """`s` with every recognised credential masked; idempotent."""
    if not s or not _may_contain(s):
        return s
    s = _PEM.sub(lambda m: f"-----BEGIN {m.group(1)}PRIVATE KEY----- {MASK} -----END {m.group(2)}PRIVATE KEY-----", s)
    s = _USERPASS.sub(lambda m: f"{m.group(1)}{m.group(2)}:{MASK}@", s)
    s = _USERONLY.sub(lambda m: f"{m.group(1)}{MASK}@", s)
    s = _AUTHZ.sub(lambda m: f"{m.group(1)}{m.group(2)} {MASK}", s)
    s = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", s)
    s = _JSON.sub(lambda m: f'{m.group(1)}"{MASK}"', s)
    return _KV.sub(_kv, s)


class RedactingFormatter(logging.Formatter):
    """Wraps another formatter and redacts its FINAL output (incl. tracebacks)."""

    def __init__(self, inner: logging.Formatter | None) -> None:
        super().__init__()
        self._inner = inner or logging.Formatter()

    def format(self, record: logging.LogRecord) -> str:
        return redact(self._inner.format(record))


_LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access")


def install() -> int:
    """Wrap every handler on the root and uvicorn loggers; returns how many.

    Idempotent: a handler already wrapped is left alone. Call it after
    logging.basicConfig (and again after uvicorn configures its loggers).
    """
    n = 0
    for name in _LOGGERS:
        for h in logging.getLogger(name).handlers:
            if isinstance(h.formatter, RedactingFormatter):
                continue
            h.setFormatter(RedactingFormatter(h.formatter))
            n += 1
    return n
