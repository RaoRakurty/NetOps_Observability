# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tgen control server — stats + control HTTP API + static dashboard.

`python -m tgen serve` (the container default) starts:
  - a Supervisor that runs the generator workers and can start/stop/reconfigure
    them live,
  - an HTTP API:  GET /api/stats · GET /api/config · GET /api/catalog ·
    POST /api/control {action: start|stop, config:{...}},
  - the React dashboard served from webui/dist at / .
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .catalog import CATALOG, by_names
from .encoders.ipfix import IpfixEncoder
from .encoders.netflow9 import NetflowV9Encoder
from .encoders.sflow import SflowEncoder
from .flow import realize
from .sender import RateLimiter, UdpSender
from .stats import Aggregator, WorkerStat

PORTS = {"ipfix": 4739, "netflow9": 2055, "sflow": 6343}
WEBROOT = Path(__file__).parent.parent / "webui" / "dist"


def _telemetry_worker(mode, collector, port, app_names, fps, batch, shared, wid):
    rnd = random.Random(hash(wid) & 0xFFFFFFFF)
    apps = by_names(app_names) if app_names else CATALOG
    enc = {"ipfix": IpfixEncoder, "netflow9": NetflowV9Encoder, "sflow": SflowEncoder}[mode]()
    sender = UdpSender(collector, port)
    rl = RateLimiter(rate=max(fps, 1), burst=max(fps, batch * 2))
    ws = WorkerStat(shared, wid, mode)
    weights = [a.weight for a in apps]
    while True:
        rl.take(batch)
        flows = [realize(rnd.choices(apps, weights=weights, k=1)[0], rnd) for _ in range(batch)]
        sender.send_batch([enc.encode(flows)])
        for f in flows:
            ws.add_flow(f.app, f.proto, f.fwd_bytes, f.rev_bytes, f.fwd_pkts + f.rev_pkts)
        ws.flush()


class Supervisor:
    def __init__(self, collector: str):
        self.mgr = mp.Manager()
        self.shared = self.mgr.dict()
        self.agg = Aggregator(self.shared)
        self.procs: list[mp.Process] = []
        self.lock = threading.Lock()
        self.config = {
            "collector": collector, "modes": ["ipfix", "netflow9", "sflow"],
            "apps": [], "fps": 1500, "batch": 32, "workers": 2, "running": False,
        }

    def start(self, cfg: dict | None = None):
        with self.lock:
            self._stop_locked()
            if cfg:
                self.config.update({k: v for k, v in cfg.items() if k in self.config})
            self.shared.clear()
            c = self.config
            modes = c["modes"] if isinstance(c["modes"], list) else [c["modes"]]
            for m in modes:
                if m not in PORTS:
                    continue
                for w in range(int(c["workers"])):
                    wid = f"{m}-{w}"
                    fps = max(1, int(c["fps"]) // int(c["workers"]) // max(1, len(modes)))
                    p = mp.Process(target=_telemetry_worker, daemon=True,
                                   args=(m, c["collector"], PORTS[m], c["apps"], fps, int(c["batch"]),
                                         self.shared, wid))
                    p.start()
                    self.procs.append(p)
            self.config["running"] = True

    def _stop_locked(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            p.join(timeout=2)
        self.procs = []
        self.config["running"] = False

    def stop(self):
        with self.lock:
            self._stop_locked()

    def stats(self) -> dict:
        s = self.agg.snapshot()
        s["config"] = self.config
        return s


def _make_handler(sup: Supervisor):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/api/stats"):
                return self._json(sup.stats())
            if self.path.startswith("/api/config"):
                return self._json(sup.config)
            if self.path.startswith("/api/catalog"):
                return self._json([{"name": a.name, "category": a.category, "proto": a.proto,
                                    "ports": list(a.dst_ports), "weight": a.weight} for a in CATALOG])
            return self._serve_static()

        def do_POST(self):
            if not self.path.startswith("/api/control"):
                return self._json({"error": "not found"}, 404)
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._json({"error": "bad json"}, 400)
            action = req.get("action")
            if action == "start":
                sup.start(req.get("config"))
            elif action == "stop":
                sup.stop()
            elif action == "update":
                sup.start(req.get("config"))  # restart with new config
            else:
                return self._json({"error": "unknown action"}, 400)
            return self._json({"ok": True, "config": sup.config})

        def _serve_static(self):
            rel = self.path.split("?", 1)[0].lstrip("/") or "index.html"
            fp = (WEBROOT / rel).resolve()
            if not str(fp).startswith(str(WEBROOT.resolve())) or not fp.is_file():
                fp = WEBROOT / "index.html"   # SPA fallback
            if not fp.is_file():
                return self._json({"error": "dashboard not built", "hint": "npm run build in webui/"}, 404)
            ctype = {"html": "text/html", "js": "text/javascript", "css": "text/css",
                     "json": "application/json", "svg": "image/svg+xml"}.get(fp.suffix[1:], "application/octet-stream")
            data = fp.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return H


def serve(collector: str, api_port: int, autostart: bool, overrides: dict | None = None):
    sup = Supervisor(collector)
    if overrides:
        sup.config.update({k: v for k, v in overrides.items() if k in sup.config and k != "running"})
    if autostart:
        sup.start()
    httpd = ThreadingHTTPServer(("0.0.0.0", api_port), _make_handler(sup))
    print(f"tgen control API + dashboard on :{api_port} (collector={collector}, autostart={autostart})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sup.stop()
