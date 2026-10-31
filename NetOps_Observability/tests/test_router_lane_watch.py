# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Router kafka-lane self-heal (cx-lane-watch.sh) — 2026-10-30 lab incident.

The defect: during a disk-flood event the broker expired the heartbeat of every
netops-router-* member at once (2026-10-30 08:07:38Z). Every lane rejoined
within 12 s; applogs, flows and snmptrap came back as a group member that owns
its partitions and hands nothing to the pipeline. The committed offset froze
(applogs lag reached 35 M), vector_component_received_events_total stayed flat,
the container read `healthy`, and KafkaConsumerStalled fired for ~30 h with no
actor to act on it. Vector 0.40's kafka source does not recover in-process.

What these tests pin:
  * the detector (`--evaluate`) calls a lane WEDGED only for lag > 0 AND a flat
    received counter for N consecutive polls AND no sink back-pressure — and
    stays quiet for a quiet lane, an unknown lag, a moving lane, a counter
    reset, and a storage outage (full sink buffer);
  * the detector runs under BUSYBOX sh/awk, the shell actually in the image;
  * the wrapper turns a heal into container exit 75 with a loud reason, and a
    back-pressured lane is NOT restarted (end to end, real HTTP exporter);
  * the config contract: every router kafka source exports its lag, the router
    (and only the router) enables the watcher, compose and helm agree.
"""

import http.server
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
VEC_DIR = ROOT / "deployment" / "docker" / "vector"
WATCH = VEC_DIR / "cx-lane-watch.sh"
WRAPPER = VEC_DIR / "cx-enrichment-reload.sh"
ROUTER_CFG = ROOT / "deployment" / "docker" / "vector-router" / "vector.yaml"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
HELM_PIPELINE = ROOT / "deployment" / "helm" / "correlix" / "templates" / "pipeline.yaml"
HELM_FILES = ROOT / "deployment" / "helm" / "correlix" / "files"

BUSYBOX = shutil.which("busybox")


# ---------------------------------------------------------------- fixtures ---

def _src(cid, received=None, lags=(), partition="0"):
    """Exporter lines for one kafka source, in vector 0.40's exact shape."""
    out = []
    if received is not None:
        out.append(
            f'vector_component_received_events_total{{component_id="{cid}",'
            f'component_kind="source",component_type="kafka",host="h",'
            f'partition="{partition}",topic="t"}} {received} 1793458190359')
    for pid, lag in lags:
        out.append(
            f'vector_kafka_consumer_lag{{component_id="{cid}",component_kind="source",'
            f'component_type="kafka",host="h",partition_id="{pid}",topic_id="t"}} '
            f'{lag} 1793458190359')
    return out


def _buf(sink, events, cap=500):
    return [
        f'vector_buffer_events{{buffer_type="memory",component_id="{sink}",'
        f'component_kind="sink",component_type="elasticsearch",host="h",stage="0"}} '
        f'{events} 1793458190359',
        f'vector_buffer_max_event_size{{buffer_type="memory",component_id="{sink}",'
        f'component_kind="sink",component_type="elasticsearch",host="h",stage="0"}} '
        f'{cap} 1793458190359',
    ]


def _exporter(*groups):
    lines = ["# HELP vector_component_received_events_total x",
             "# TYPE vector_component_received_events_total counter"]
    for g in groups:
        lines += g
    # Unrelated series the parser must ignore (a transform with the same name
    # family, a sink counter, an internal gauge without component_id).
    lines += [
        'vector_component_received_events_total{component_id="applogs_tagged",'
        'component_kind="transform",component_type="remap",host="h"} 5 1',
        'vector_kafka_consumer_lag{component_id="kafka_flows_keyed",'
        'component_kind="sink",component_type="kafka",host="h",partition_id="0",'
        'topic_id="t"} 999 1',
        "vector_uptime_seconds 123 1",
    ]
    return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def bb_path(tmp_path_factory):
    """A PATH dir whose awk/sleep/... ARE busybox — the image's userland.

    wget is deliberately NOT shimmed: the host busybox (Ubuntu 1.30) wget
    segfaults when stdin is /dev/null, which is how pytest runs children; the
    image's alpine busybox wget does not, and `wget -q -T <s> -O - <url>`
    against the router's own exporter was run inside the live router
    (2026-10-31). The e2e tests use the host's wget with the same flags."""
    if not BUSYBOX:
        return None
    d = tmp_path_factory.mktemp("bb")
    for applet in ("awk", "sleep", "kill", "md5sum", "cut", "dirname", "cat"):
        (d / applet).symlink_to(BUSYBOX)
    return d


needs_wget = pytest.mark.skipif(shutil.which("wget") is None,
                                reason="wget not on PATH (the image ships busybox wget)")


SHELLS = ["dash"] + (["busybox"] if BUSYBOX else [])


def _evaluate(shell, bb_path, state, metrics, **env_over):
    env = dict(os.environ)
    env.update({k: str(v) for k, v in env_over.items()})
    if shell == "busybox":
        env["PATH"] = f"{bb_path}:{env['PATH']}"
        argv = [BUSYBOX, "sh", str(WATCH), "--evaluate", state]
    else:
        argv = ["dash", str(WATCH), "--evaluate", state]
    p = subprocess.run(argv, input=metrics, capture_output=True, text=True,
                       env=env, timeout=30, check=False)
    return p


def _parse(out):
    state, wedged, bp = "", [], []
    for line in out.splitlines():
        if line.startswith("STATE "):
            state = line.split(" ", 1)[1]
        elif line.startswith("STATE"):
            state = ""
        elif line.startswith("WEDGED "):
            wedged.append(line.split()[1])
        elif line.startswith("BACKPRESSURE "):
            bp.append(line.split()[1])
    return state, wedged, bp


def _strikes(state, cid):
    for ent in state.split(","):
        if ent.startswith(cid + ":"):
            return int(ent.rsplit(":", 1)[1])
    raise AssertionError(f"{cid} missing from state {state!r}")


# ------------------------------------------------------------ the detector ---

@pytest.mark.parametrize("shell", SHELLS)
def test_incident_shape_is_wedged_after_n_flat_polls(shell, bb_path):
    """The 2026-10-30 snapshot: applogs + flows hold lag, receive nothing, and
    every sink buffer is empty; syslog keeps moving. Only the two stuck lanes
    are flagged, and only once the strike budget is spent."""
    def snap(syslog_received):
        return _exporter(
            _src("kafka_applogs", 97877, [("0", 34977231), ("-1", -1)]),
            _src("kafka_flows", 4245124, [("0", 2241)]),
            _src("kafka_syslog", syslog_received, [("0", 0)]),
            _buf("opensearch_applogs", 0), _buf("clickhouse_flows", 0),
        )

    state = ""
    for poll in range(1, 6):
        p = _evaluate(shell, bb_path, state, snap(1000 + poll), CX_LANE_WATCH_STRIKES=4)
        assert p.returncode == 0, p.stderr
        state, wedged, bp = _parse(p.stdout)
        assert bp == []
        expect = max(poll - 1, 0)
        assert _strikes(state, "kafka_applogs") == expect
        assert _strikes(state, "kafka_flows") == expect
        assert _strikes(state, "kafka_syslog") == 0, "a moving lane never strikes"
        if expect >= 4:
            assert sorted(wedged) == ["kafka_applogs", "kafka_flows"]
        else:
            assert wedged == [], f"flagged early at poll {poll}"
    # Values survive the round trip as integers (no %g truncation of 4,245,124).
    assert "kafka_flows:4245124:" in state


@pytest.mark.parametrize("shell", SHELLS)
def test_quiet_lane_and_unknown_lag_never_strike(shell, bb_path):
    """A lane with nothing to read (lag 0) or whose lag librdkafka cannot yet
    compute (-1) is not a wedge, however long its counter is flat."""
    m = _exporter(_src("kafka_snmptrap", 10, [("0", 0)]),
                  _src("kafka_cloudlogs", None, [("0", -1)]),
                  _src("kafka_deadletter", 0, []))
    state = "kafka_snmptrap:10:3,kafka_cloudlogs:0:3,kafka_deadletter:0:3"
    p = _evaluate(shell, bb_path, state, m, CX_LANE_WATCH_STRIKES=4)
    assert p.returncode == 0, p.stderr
    state, wedged, _ = _parse(p.stdout)
    assert wedged == []
    for cid in ("kafka_snmptrap", "kafka_cloudlogs", "kafka_deadletter"):
        assert _strikes(state, cid) == 0


@pytest.mark.parametrize("shell", SHELLS)
def test_backpressure_suppresses_the_heal(shell, bb_path):
    """Storage outage: a sink buffer at >= 90 % of capacity blocks the source.
    That source is doing its job (Kafka is the buffer) — restarting it would
    not help, so the wedge is suppressed and the reason is reported."""
    m = _exporter(_src("kafka_applogs", 500, [("0", 9000)]),
                  _buf("opensearch_applogs", 450))
    p = _evaluate(shell, bb_path, "kafka_applogs:500:9", m, CX_LANE_WATCH_STRIKES=2)
    assert p.returncode == 0, p.stderr
    state, wedged, bp = _parse(p.stdout)
    assert wedged == []
    assert bp == ["opensearch_applogs"]
    assert _strikes(state, "kafka_applogs") == 0
    # Just under the gate is NOT back-pressure.
    m2 = _exporter(_src("kafka_applogs", 500, [("0", 9000)]),
                   _buf("opensearch_applogs", 449))
    p2 = _evaluate(shell, bb_path, "kafka_applogs:500:1", m2, CX_LANE_WATCH_STRIKES=2)
    _, wedged2, bp2 = _parse(p2.stdout)
    assert bp2 == [] and wedged2 == ["kafka_applogs"]


@pytest.mark.parametrize("shell", SHELLS)
def test_counter_movement_or_reset_clears_strikes(shell, bb_path):
    m_up = _exporter(_src("kafka_applogs", 501, [("0", 9000)]))
    s, w, _ = _parse(_evaluate(shell, bb_path, "kafka_applogs:500:4", m_up,
                               CX_LANE_WATCH_STRIKES=5).stdout)
    assert w == [] and _strikes(s, "kafka_applogs") == 0
    m_reset = _exporter(_src("kafka_applogs", 3, [("0", 9000)]))
    s, w, _ = _parse(_evaluate(shell, bb_path, "kafka_applogs:500:4", m_reset,
                               CX_LANE_WATCH_STRIKES=5).stdout)
    assert w == [] and _strikes(s, "kafka_applogs") == 0


@pytest.mark.parametrize("shell", SHELLS)
def test_multi_partition_sums(shell, bb_path):
    """Received and lag are summed across partitions: one partition moving
    means the source is alive."""
    m = _exporter(_src("kafka_flows", 100, [("0", 50), ("1", 70)], partition="0"),
                  _src("kafka_flows", 7, [], partition="1"))
    s, _, _ = _parse(_evaluate(shell, bb_path, "kafka_flows:106:0", m).stdout)
    assert "kafka_flows:107:0" in s.split(",")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("var,val", [
    ("CX_LANE_WATCH_STRIKES", "x"), ("CX_LANE_WATCH_STRIKES", "0"),
    ("CX_LANE_WATCH_POLL_SECONDS", "-5"), ("CX_LANE_WATCH_BACKPRESSURE_PCT", "101"),
    ("CX_LANE_WATCH_FETCH_TIMEOUT_SECONDS", "10s"),
])
def test_invalid_config_refuses_loudly(shell, bb_path, var, val):
    p = _evaluate(shell, bb_path, "", _exporter(), **{var: val})
    assert p.returncode == 64
    assert "INVALID CONFIG" in p.stderr and var in p.stderr


# ------------------------------------------------- wrapper, end to end ---

class _Exporter(http.server.BaseHTTPRequestHandler):
    body = b""

    def do_GET(self):  # noqa: N802 — http.server API
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_):
        pass


def _serve(body):
    handler = type("H", (_Exporter,), {"body": body.encode()})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_wrapper(tmp_path, bb_path, url):
    stub = tmp_path / "vector-stub"
    mark = tmp_path / "vector-got-term"
    stub.write_text(
        "#!/bin/sh\n"
        f"trap 'echo term > {mark}; exit 0' TERM\n"
        "while :; do sleep 1; done\n")
    stub.chmod(0o755)
    csv = tmp_path / "device_tenant.csv"
    csv.write_text("identity,tenant_id\n")
    env = dict(os.environ)
    env.update({
        "CX_VECTOR_BIN": str(stub),
        "CX_ENRICHMENT_CSV": str(csv),
        # Short, so the enrichment poller (an orphan holding our stderr pipe
        # once the wrapper exits) lets communicate() finish promptly.
        "CX_ENRICHMENT_POLL_SECONDS": "1",
        "CX_LANE_WATCH": "1",
        "CX_LANE_WATCH_POLL_SECONDS": "1",
        "CX_LANE_WATCH_STRIKES": "2",
        "CX_LANE_WATCH_METRICS_URL": url,
        "CX_LANE_WATCH_FETCH_TIMEOUT_SECONDS": "3",
    })
    if bb_path is not None:
        env["PATH"] = f"{bb_path}:{env['PATH']}"
        argv = [BUSYBOX, "sh", str(WRAPPER)]
    else:
        argv = ["dash", str(WRAPPER)]
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc, mark


@needs_wget
def test_wrapper_exits_75_and_says_why_on_a_wedged_lane(tmp_path, bb_path):
    srv = _serve(_exporter(_src("kafka_applogs", 97877, [("0", 34977231)]),
                           _buf("opensearch_applogs", 0)))
    try:
        proc, mark = _start_wrapper(tmp_path, bb_path, f"http://127.0.0.1:{srv.server_port}/metrics")
        try:
            _, err = proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
    finally:
        srv.shutdown()
    assert proc.returncode == 75, err
    assert mark.exists(), "vector was not signalled (graceful TERM expected)"
    assert "LANE WEDGED: kafka_applogs lag=34977231" in err
    assert "exiting 75" in err


@needs_wget
def test_wrapper_leaves_a_backpressured_lane_alone(tmp_path, bb_path):
    srv = _serve(_exporter(_src("kafka_applogs", 500, [("0", 9000)]),
                           _buf("opensearch_applogs", 500)))
    try:
        proc, mark = _start_wrapper(tmp_path, bb_path, f"http://127.0.0.1:{srv.server_port}/metrics")
        time.sleep(6)  # 6 polls at 1 s against a 2-strike budget
        assert proc.poll() is None, proc.communicate()[1]
        proc.send_signal(signal.SIGTERM)  # container stop
        _, err = proc.communicate(timeout=30)
    finally:
        srv.shutdown()
    assert proc.returncode == 0, err
    assert mark.exists(), "PID 1 must still forward TERM to vector"
    assert "LANE WEDGED" not in err and "exiting 75" not in err


@needs_wget
def test_wrapper_reports_an_unreadable_exporter(tmp_path, bb_path):
    """§16.1: a watcher that cannot read the exporter says so (once)."""
    proc, _ = _start_wrapper(tmp_path, bb_path, "http://127.0.0.1:9/metrics")
    time.sleep(4)
    proc.send_signal(signal.SIGTERM)
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 0, err
    assert err.count("lane checks paused") == 1, err


# --------------------------------------------------------- config contract ---

def test_every_router_kafka_source_exports_its_lag():
    cfg = yaml.safe_load(ROUTER_CFG.read_text())
    kafka_sources = {k: v for k, v in cfg["sources"].items() if v.get("type") == "kafka"}
    assert len(kafka_sources) >= 10
    missing = [k for k, v in kafka_sources.items()
               if not (v.get("metrics") or {}).get("topic_lag_metric") is True]
    assert not missing, (
        f"router kafka sources without metrics.topic_lag_metric: {missing} — "
        "cx-lane-watch sees no lag for them and can never heal a wedge")


def test_router_and_only_router_runs_the_watcher():
    compose = yaml.safe_load(COMPOSE.read_text())
    svc = compose["services"]
    assert str(svc["vector-router"]["environment"].get("CX_LANE_WATCH")) == "1"
    assert "CX_LANE_WATCH" not in (svc["vector-aggregator"].get("environment") or {})
    vols = " ".join(svc["vector-router"]["volumes"])
    assert "./vector:/etc/vector/shared" in vols, "watcher script would not be reachable"
    wrapper = WRAPPER.read_text()
    assert '"$HERE/cx-lane-watch.sh" --watch "$VECTOR_PID"' in wrapper
    helm = HELM_PIPELINE.read_text()
    router_block = helm[helm.index("name: vector-router"):]
    assert '{name: CX_LANE_WATCH, value: "1"}' in router_block.split("\n---")[0]


def test_helm_copies_match_canonical():
    for rel in ("vector/cx-lane-watch.sh", "vector/cx-enrichment-reload.sh"):
        assert (HELM_FILES / rel).read_text() == (VEC_DIR / rel.split("/", 1)[1]).read_text(), rel
    assert (HELM_FILES / "vector-router" / "vector.yaml").read_text() == ROUTER_CFG.read_text()
