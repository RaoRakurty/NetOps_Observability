# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Iris progress streaming (tracker 337 N-E2) through nginx.

The api marks a streamed answer `X-Accel-Buffering: no`. Every `/api/`
location must pass that header on (nginx hides X-Accel-* by default), so the
TLS front can stop buffering too, and nothing may gzip an event stream.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_GATEWAYS = [
    ROOT / "deployment/docker/nginx/default.conf",
    ROOT / "deployment/docker/nginx/default-mtls.conf",
    ROOT / "deployment/helm/correlix/files/nginx/default.conf",
]


def _api_block(text: str) -> str:
    start = text.index("location /api/ {")
    depth, i = 0, start
    while True:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1


def test_every_api_location_passes_the_buffering_header_on():
    for path in API_GATEWAYS:
        block = _api_block(path.read_text())
        assert re.search(r"^\s*proxy_pass_header\s+X-Accel-Buffering;", block, re.M), path


def test_no_gzip_of_event_streams():
    nginx = (ROOT / "deployment/docker/nginx/nginx.conf").read_text()
    m = re.search(r"gzip_types([^;]*);", nginx)
    assert m is None or "text/event-stream" not in m.group(1)
