"""ClickHouse's own server log is bounded — the copy that lives in the CONTAINER.

WHY (2026-09-03, host at 94% disk against OpenSearch's 95% flood stage):

    docker exec netops-clickhouse-1 du -sh /var/log/clickhouse-server
    1.8G

    clickhouse-server.log      924 MiB   (live)
    clickhouse-server.err.log  109 MiB   (live)
    clickhouse-server.log.N.gz  10 x ~90 MiB

Neither of the two mechanisms that are supposed to bound storage could see it:

  * the compose `x-logging` anchor caps **stdout** (json-file driver). The
    ClickHouse image leaves `<console>` commented out in
    docker_related_config.xml, so the server writes to FILES and `docker logs`
    holds only the startup banner;
  * `data/clickhouse` is bind-mounted at /var/lib/clickhouse, but
    /var/log/clickhouse-server is **not mounted at all** — the bytes land in
    the container's writable layer, invisible to `du -sh data/`.

Stock 24.8 defaults are trace / 1000M / 10 on each of the two channels: an
~11 GiB per-server ceiling. `clickhouse/logger.xml` replaces them.

This is a STATIC contract guard over the committed files (no docker, no running
server), matching tests/test_clickhouse_system_log_merges.py in spirit:
system-logs.xml bounds the system.* TABLES, logger.xml bounds the server's TEXT
log, and a config that is not mounted bounds nothing at all — so the mount is
asserted here too.

Run:  python3 -m pytest tests/test_clickhouse_server_log_bounded.py -v
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = ROOT / "deployment" / "docker"
COMPOSE = DOCKER_DIR / "docker-compose.yml"
LOGGER_XML = DOCKER_DIR / "clickhouse" / "logger.xml"

CONTAINER_PATH = "/etc/clickhouse-server/config.d/logger.xml"
MOUNT = f"./clickhouse/logger.xml:{CONTAINER_PATH}:ro"

# Poco levels, most→least verbose. `trace` is what produced ~90 MiB of gzip
# every few hours; `information` is the production level.
TOO_VERBOSE = frozenset({"test", "trace", "debug"})

_SIZE_RE = re.compile(r"^(\d+)([KMG])$", re.IGNORECASE)
_UNIT = {"K": 1024, "M": 1024**2, "G": 1024**3}

# Ceilings this guard enforces. 100M x 3 rotations x 2 channels is ~0.3 GiB
# worst case; anything at or above these numbers is back in outage territory.
MAX_SIZE_BYTES = 200 * 1024**2
MAX_COUNT = 5


def _logger() -> ET.Element:
    assert LOGGER_XML.is_file(), f"{LOGGER_XML} is missing"
    root = ET.parse(LOGGER_XML).getroot()
    assert root.tag == "clickhouse", f"unexpected root element {root.tag!r}"
    logger = root.find("logger")
    assert logger is not None, "logger.xml has no <logger> element"
    return logger


def _text(logger: ET.Element, child: str) -> str:
    el = logger.find(child)
    assert el is not None and (el.text or "").strip(), (
        f"<logger> is missing <{child}> — the stock default would apply instead"
    )
    return (el.text or "").strip()


def test_logger_xml_bounds_the_rotation_size() -> None:
    raw = _text(_logger(), "size")
    m = _SIZE_RE.match(raw)
    assert m, f"<size> must be a Poco size like '100M', got {raw!r}"
    as_bytes = int(m.group(1)) * _UNIT[m.group(2).upper()]
    assert as_bytes <= MAX_SIZE_BYTES, (
        f"<size> {raw} exceeds the {MAX_SIZE_BYTES // 1024**2}M ceiling; the "
        "stock 1000M is what filled the container layer"
    )


def test_logger_xml_bounds_the_rotation_count() -> None:
    raw = _text(_logger(), "count")
    assert raw.isdigit(), f"<count> must be an integer, got {raw!r}"
    count = int(raw)
    assert 1 <= count <= MAX_COUNT, (
        f"<count> {count} is outside 1..{MAX_COUNT}; <size> alone bounds only "
        "the live file, <count> bounds the archive"
    )


def test_logger_xml_is_not_left_at_a_debugging_level() -> None:
    level = _text(_logger(), "level").lower()
    assert level not in TOO_VERBOSE, (
        f"<level>{level}</level> is a debugging level. It is fine to set it "
        "temporarily to chase a server-side bug, but it must not be committed: "
        "trace is what wrote ~90 MiB of gzip every few hours."
    )
    assert level != "none", (
        "silencing the server log entirely removes the only record of "
        "background-thread failures; use 'information' or 'warning'"
    )


def test_logger_xml_does_not_turn_on_console_logging() -> None:
    """Console + file would pay for every line twice, the second time uncapped-by-us."""
    console = _logger().find("console")
    assert console is None or (console.text or "").strip() in ("", "0"), (
        "<console>1</console> duplicates every server line into the json-file "
        "driver as well as the container-layer file"
    )


def test_compose_mounts_logger_xml_read_only() -> None:
    text = COMPOSE.read_text()
    assert MOUNT in text, (
        f"docker-compose.yml does not mount logger.xml as `{MOUNT}` — an "
        "unmounted config bounds nothing"
    )
    # config.d (server config), not users.d (settings profiles): <logger> in
    # users.d is silently ignored.
    assert "users.d/logger.xml" not in text, "logger.xml belongs in config.d"


def test_logger_mount_sits_on_the_clickhouse_service() -> None:
    """A mount in the wrong service block is a mount on the wrong container."""
    lines = COMPOSE.read_text().split("\n")
    start = next(i for i, l in enumerate(lines) if l == "  clickhouse:")
    end = next(
        (
            i
            for i in range(start + 1, len(lines))
            if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", lines[i])
        ),
        len(lines),
    )
    block = "\n".join(lines[start:end])
    assert MOUNT in block, "logger.xml is mounted, but not on the clickhouse service"
