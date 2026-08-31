#!/usr/bin/env python3
"""Twin gNMI target — a minimal OpenConfig fake (tracker 152, design §4.6).

DESIGN DECISION (§4.6 left it open: "gnmic target mode vs a small OpenConfig
fake"): this is the small OpenConfig fake. gnmic has no device-emulation mode —
its `gnmi-server` serves its own CACHE, which would need upstream targets to
fill, i.e. the thing we are trying to create. So the twin serves gNMI itself,
over a stdlib gRPC/HTTP2 stack (`gnmi_h2.py`, `gnmi_proto.py`) rather than new
wheels in the lab image.

WHERE IT RUNS — a deliberate deviation from §4.6's "whatever serves gNMI lives
in the twin container", flagged rather than silent. The boundary §4.6 is
protecting is "not in a product service", and this process is twin lab tooling
either way. Because it turned out to need NO dependency at all, it needs no
image: running it as a host process makes the gNMI lane usable with no twin
overlay container built — unlike the snmpsim fleet, which genuinely needs the
image's pinned wheels. One code path, and it is the one that is proven
end-to-end. The cost is addressing: a container on the stack network reaches
the host at the `<project>_netops` bridge gateway, which is what `twin.py`
renders into the gnmic targets file (never `127.0.0.1`, which would resolve to
gnmic's own container).

SCOPE — exactly the surface OUR collector consumes. `deployment/docker/gnmic/
gnmic.yaml` subscribes its Arista/OpenConfig targets to:

    oc-interfaces  /interfaces/interface/state/counters      sample 30s
                   /interfaces/interface/state/oper-status
                   /interfaces/interface/state/admin-status
    oc-bgp         .../bgp/neighbors/neighbor/state/session-state          on-change
                   .../bgp/neighbors/neighbor/state/established-transitions
                   .../neighbor/afi-safis/afi-safi/state/prefixes/received

so those are the leaves this target serves, in OpenConfig shape and with the
enum spellings the canonical lane's `canon-status-enums` / `canon-bgp-enums`
processors expect (UP/DOWN, ESTABLISHED/IDLE/...). Nothing else: no SR Linux
native model, no platform/CPU tree, no config surface, no Set RPC.

IDENTITY: gnmic labels every sample `source: <target name>`, so a twin device's
gNMI identity is its TARGET NAME, not its address — which is why one listener
per device (its own port) is enough for per-device attribution, and why the
run-prefixed name `twx-<runid>-<device>` rides through to VictoriaMetrics.

FAULTS: the server holds no schedule of its own. It applies ops appended to a
FAULT JOURNAL by the twin's emission loop (`emitters.GnmiLane`), so a story's
gNMI manifestation is emitted from the same deterministic plan, at the same
instant, and with the same `story_id` as its syslog/trap manifestations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator

import gnmi_h2
import gnmi_proto as gp

GNMI_VERSION = "0.8.0"
DEFAULT_PORT = 57400

# Paths served, as (path template, kind). `{if}` / `{peer}` are filled per key.
IF_COUNTERS = ("in-octets", "out-octets", "in-unicast-pkts",
               "out-unicast-pkts", "in-errors", "out-errors",
               "in-discards", "out-discards")

_BGP_PREFIX = ("/network-instances/network-instance[name=default]"
               "/protocols/protocol[identifier=BGP][name=BGP]/bgp")


def _log(msg: str) -> None:
    sys.stderr.write(f"[gnmi-target] {msg}\n")
    sys.stderr.flush()


def _rate_for(device: str, ifname: str) -> float:
    """Deterministic per-interface octet rate (B/s). Seeded by name so a
    target restart replays the same traffic profile — the twin's determinism
    rule (design §3.3) applies to served state, not just emitted events."""
    digest = hashlib.sha256(f"{device}|{ifname}".encode()).digest()
    return 40_000.0 + (int.from_bytes(digest[:4], "big") % 360_000)


class DeviceTarget:
    """One simulated device's gNMI-visible state.

    Counters are a pure function of ACTIVE time: while an interface is down or
    stalled, time stops accruing to it, so a fault shows up as a flat counter —
    which is exactly the signature the raw `gnmi_*` lane can carry into
    VictoriaMetrics (a string oper-status enum cannot; see the report/README).
    """

    def __init__(self, spec: dict, clock=time.monotonic) -> None:
        self.name = str(spec["name"])
        self.tenant = str(spec.get("tenant") or "")
        self.port = int(spec["port"])
        self.clock = clock
        self._lock = threading.Lock()
        t0 = clock()
        self.ifaces: dict[str, dict] = {}
        for i, iface in enumerate(spec.get("interfaces") or []):
            name = str(iface["name"])
            self.ifaces[name] = {
                "ifindex": int(iface.get("ifindex") or (i + 1)),
                "oper": "UP", "admin": "UP",
                "rate": float(iface.get("rate_bytes_s")
                              or _rate_for(self.name, name)),
                "active_since": t0, "active_s": 0.0,
                "errors": 0, "discards": 0,
            }
        self.peers: dict[str, dict] = {}
        for nb in spec.get("bgp_neighbors") or []:
            self.peers[str(nb["peer_ip"])] = {
                "state": "ESTABLISHED", "transitions": 1,
                "prefixes": int(nb.get("prefixes") or 120),
            }
        self.generation = 0        # bumped on every fault op (change detection)

    # -- state model -------------------------------------------------------
    def _active_s(self, iface: dict, now: float) -> float:
        if iface["active_since"] is None:
            return iface["active_s"]
        return iface["active_s"] + (now - iface["active_since"])

    def _set_active(self, iface: dict, active: bool, now: float) -> None:
        if active and iface["active_since"] is None:
            iface["active_since"] = now
        elif not active and iface["active_since"] is not None:
            iface["active_s"] += now - iface["active_since"]
            iface["active_since"] = None

    def apply(self, op: dict) -> str:
        """Apply one fault-journal op. Returns a human line for the log; raises
        KeyError/ValueError on an op that names something this device has not
        got (silently ignoring it would leave a story labelled but unemitted)."""
        kind = str(op.get("op") or "")
        now = self.clock()
        with self._lock:
            if kind in ("if_down", "if_up", "counter_stall", "counter_resume"):
                ifname = str(op["ifname"])
                if ifname not in self.ifaces:
                    raise KeyError(f"{self.name}: no interface {ifname!r}")
                iface = self.ifaces[ifname]
                if kind == "if_down":
                    iface["oper"] = "DOWN"
                    self._set_active(iface, False, now)
                elif kind == "if_up":
                    iface["oper"] = "UP"
                    self._set_active(iface, True, now)
                elif kind == "counter_stall":
                    self._set_active(iface, False, now)
                else:
                    self._set_active(iface, True, now)
            elif kind in ("bgp_down", "bgp_up"):
                peer = str(op["peer_ip"])
                if peer not in self.peers:
                    raise KeyError(f"{self.name}: no bgp neighbor {peer!r}")
                entry = self.peers[peer]
                if kind == "bgp_down":
                    entry["state"] = str(op.get("state") or "IDLE")
                    entry["prefixes"] = 0
                else:
                    entry["state"] = "ESTABLISHED"
                    entry["prefixes"] = int(op.get("prefixes") or 120)
                    entry["transitions"] += 1
            elif kind == "if_errors":
                ifname = str(op["ifname"])
                if ifname not in self.ifaces:
                    raise KeyError(f"{self.name}: no interface {ifname!r}")
                self.ifaces[ifname]["errors"] += int(op.get("count") or 1)
            else:
                raise ValueError(f"unknown gnmi fault op {kind!r}")
            self.generation += 1
        return f"{self.name}: {kind} {op.get('ifname') or op.get('peer_ip')}"

    # -- served leaves -----------------------------------------------------
    def leaves(self) -> list[tuple[list[gp.PathElem], object]]:
        """Every served leaf as (path elems, python value). Values are JSON
        (RFC 7951) scalars: enums are strings, counters are numbers."""
        now = self.clock()
        out: list[tuple[list[gp.PathElem], object]] = []
        with self._lock:
            for ifname, iface in sorted(self.ifaces.items()):
                base = f"/interfaces/interface[name={ifname}]/state"
                out.append((gp.parse_path(f"{base}/oper-status"),
                            iface["oper"]))
                out.append((gp.parse_path(f"{base}/admin-status"),
                            iface["admin"]))
                octets = int(self._active_s(iface, now) * iface["rate"])
                pkts = octets // 800
                values = {
                    "in-octets": octets, "out-octets": int(octets * 0.87),
                    "in-unicast-pkts": pkts,
                    "out-unicast-pkts": int(pkts * 0.87),
                    "in-errors": iface["errors"], "out-errors": 0,
                    "in-discards": iface["discards"], "out-discards": 0,
                }
                for leaf in IF_COUNTERS:
                    out.append((gp.parse_path(f"{base}/counters/{leaf}"),
                                values[leaf]))
            for peer, entry in sorted(self.peers.items()):
                nb = f"{_BGP_PREFIX}/neighbors/neighbor[neighbor-address={peer}]"
                out.append((gp.parse_path(f"{nb}/state/session-state"),
                            entry["state"]))
                out.append((gp.parse_path(
                    f"{nb}/state/established-transitions"),
                    entry["transitions"]))
                out.append((gp.parse_path(
                    f"{nb}/afi-safis/afi-safi[afi-safi-name=IPV4_UNICAST]"
                    f"/state/prefixes/received"), entry["prefixes"]))
        return out

    def select(self, paths: list[list[gp.PathElem]]
               ) -> list[tuple[list[gp.PathElem], object]]:
        return [(leaf, value) for leaf, value in self.leaves()
                if any(gp.path_matches(p, leaf) for p in paths)]


def _notification(pairs: list[tuple[list[gp.PathElem], object]],
                  now_ns: int) -> bytes:
    updates = [gp.enc_update(path, gp.enc_typed_json_ietf(json.dumps(value)))
               for path, value in pairs]
    return gp.enc_notification(now_ns, updates)


class TargetService:
    """The gNMI RPC surface for one device."""

    def __init__(self, device: DeviceTarget,
                 min_sample_s: float = 1.0) -> None:
        self.device = device
        self.min_sample_s = min_sample_s

    def handle(self, path: str, ctx: gnmi_h2.StreamContext,
               request: bytes) -> Iterator[bytes]:
        if path == "/gnmi.gNMI/Capabilities":
            yield gp.enc_capability_response(
                models=[("openconfig-interfaces", "OpenConfig working group",
                         "3.0.0"),
                        ("openconfig-network-instance",
                         "OpenConfig working group", "1.1.0")],
                encodings=[0, 4],          # JSON, JSON_IETF
                version=GNMI_VERSION)
            return
        if path == "/gnmi.gNMI/Get":
            yield from self._get(request)
            return
        if path == "/gnmi.gNMI/Subscribe":
            yield from self._subscribe(ctx, request)
            return
        raise gnmi_h2.GrpcStatus(
            gnmi_h2.GRPC_UNIMPLEMENTED,
            f"{path} is not served by the twin gNMI target (Capabilities, "
            f"Get and Subscribe only)")

    def _get(self, request: bytes) -> Iterator[bytes]:
        req = gp.dec_get_request(request)
        paths = [req["prefix"] + p for p in req["paths"]] or [[]]
        pairs = self.device.select(paths)
        if not pairs:
            raise gnmi_h2.GrpcStatus(
                gnmi_h2.GRPC_NOT_FOUND,
                "no served leaf matches the requested path(s)")
        yield gp.enc_get_response([_notification(pairs, time.time_ns())])

    def _subscribe(self, ctx: gnmi_h2.StreamContext,
                   request: bytes) -> Iterator[bytes]:
        req = gp.dec_subscribe_request(request)
        if req["kind"] == "poll":
            raise gnmi_h2.GrpcStatus(
                gnmi_h2.GRPC_UNIMPLEMENTED,
                "POLL subscriptions are not served (gnmic.yaml uses STREAM)")
        if req["mode"] == gp.LIST_MODE_POLL:
            raise gnmi_h2.GrpcStatus(
                gnmi_h2.GRPC_UNIMPLEMENTED,
                "POLL subscriptions are not served (gnmic.yaml uses STREAM)")
        subs = req["subscriptions"]
        if not subs:
            raise gnmi_h2.GrpcStatus(gnmi_h2.GRPC_INVALID_ARGUMENT,
                                     "SubscriptionList carries no subscription")
        prefix = req["prefix"]
        selectors = [prefix + s["path"] for s in subs]

        if req["mode"] == gp.LIST_MODE_ONCE:
            pairs = self.device.select(selectors)
            if pairs:
                yield gp.enc_subscribe_response_update(
                    _notification(pairs, time.time_ns()))
            yield gp.enc_subscribe_response_sync()
            return

        # STREAM. Initial dump then sync_response, per gNMI 3.5.1.4.
        last: dict[str, object] = {}
        if not req["updates_only"]:
            pairs = self.device.select(selectors)
            for leaf, value in pairs:
                last[gp.path_str(leaf)] = value
            if pairs:
                yield gp.enc_subscribe_response_update(
                    _notification(pairs, time.time_ns()))
        yield gp.enc_subscribe_response_sync()

        state = []
        now = time.monotonic()
        for sub in subs:
            interval = max(self.min_sample_s,
                           (sub["sample_interval_ns"] or 30_000_000_000)
                           / 1e9)
            heartbeat = ((sub["heartbeat_interval_ns"] / 1e9)
                         if sub["heartbeat_interval_ns"] else 0.0)
            on_change = sub["mode"] == gp.SUB_MODE_ON_CHANGE
            state.append({"sel": [prefix + sub["path"]],
                          "interval": interval, "heartbeat": heartbeat,
                          "on_change": on_change,
                          "next": now + (0.25 if on_change else interval),
                          "next_hb": now + heartbeat if heartbeat else None})
        tick = min([s["interval"] for s in state] + [0.25])
        while ctx.wait(tick):
            now = time.monotonic()
            for sub_state in state:
                if now < sub_state["next"]:
                    continue
                pairs = self.device.select(sub_state["sel"])
                if sub_state["on_change"]:
                    sub_state["next"] = now + 0.25
                    changed = [(p, v) for p, v in pairs
                               if last.get(gp.path_str(p)) != v]
                    due_hb = (sub_state["next_hb"] is not None
                              and now >= sub_state["next_hb"])
                    if due_hb:
                        sub_state["next_hb"] = now + sub_state["heartbeat"]
                        changed = pairs
                    if not changed:
                        continue
                    for p, v in changed:
                        last[gp.path_str(p)] = v
                    pairs = changed
                else:
                    sub_state["next"] = now + sub_state["interval"]
                    for p, v in pairs:
                        last[gp.path_str(p)] = v
                if pairs:
                    yield gp.enc_subscribe_response_update(
                        _notification(pairs, time.time_ns()))


class TargetServer:
    """One listening socket per device — gnmic addresses a target by
    `host:port`, and one port per device is what makes `source` (the target
    name) a faithful per-device label."""

    def __init__(self, devices: list[DeviceTarget], listen_host: str,
                 min_sample_s: float = 1.0) -> None:
        self.devices = devices
        self.listen_host = listen_host
        self.min_sample_s = min_sample_s
        self.socks: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        for device in self.devices:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_host, device.port))
            sock.listen(16)
            self.socks.append(sock)
            thread = threading.Thread(target=self._accept_loop,
                                      args=(sock, device), daemon=True,
                                      name=f"gnmi-{device.name}")
            thread.start()
            self.threads.append(thread)
        _log(f"serving {len(self.devices)} gNMI targets on "
             f"{self.listen_host}:{sorted(d.port for d in self.devices)}")

    def _accept_loop(self, sock: socket.socket, device: DeviceTarget) -> None:
        service = TargetService(device, self.min_sample_s)
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(
                target=self._serve_conn, args=(conn, service, peer),
                daemon=True, name=f"gnmi-conn-{device.name}").start()

    def _serve_conn(self, conn: socket.socket, service: TargetService,
                    peer) -> None:
        _log(f"{service.device.name}: connection from {peer[0]}:{peer[1]}")
        gnmi_h2.Connection(conn, service.handle,
                           log=lambda m: _log(f"{service.device.name}: {m}")
                           ).serve()

    def stop(self) -> None:
        self._stop.set()
        for sock in self.socks:
            try:
                sock.close()
            except OSError:
                pass


class FaultJournalWatcher:
    """Tails the twin's gNMI fault journal and applies each op to its device.

    A journal (append-only JSONL on the shared run volume) rather than a
    control PORT: no new listener, no new credential, and the file IS the
    audit trail — every applied op is replayable next to `events.jsonl`.
    """

    def __init__(self, path: str, devices: dict[str, DeviceTarget],
                 poll_s: float = 0.2) -> None:
        self.path = path
        self.devices = devices
        self.poll_s = poll_s
        self.applied = 0
        self.rejected = 0
        self._offset = 0
        self._stop = threading.Event()

    def poll_once(self) -> int:
        """Apply every complete line appended since the last poll. Returns the
        number applied. A partial trailing line is left for the next poll."""
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
        except FileNotFoundError:
            return 0
        if not chunk:
            return 0
        text = chunk.decode("utf-8", "replace")
        if not text.endswith("\n"):
            text, _, _partial = text.rpartition("\n")
            if not text:
                return 0
            text += "\n"
        self._offset += len(text.encode("utf-8"))
        applied = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                op = json.loads(line)
                device = self.devices[str(op["device"])]
                _log(device.apply(op) + f" (story {op.get('story_id')})")
                applied += 1
                self.applied += 1
            except (ValueError, KeyError) as exc:
                # LOUD: a dropped fault op means a story is labelled but its
                # gNMI manifestation never happened — a silent accuracy lie.
                self.rejected += 1
                _log(f"REJECTED fault op {line[:200]!r}: {exc}")
        return applied

    def run(self) -> None:
        while not self._stop.wait(self.poll_s):
            self.poll_once()

    def stop(self) -> None:
        self._stop.set()


# ── manifest + gnmic targets rendering ──────────────────────────────────────

def generate_manifest(sc: dict, prefix: str, device_ports: dict[str, int],
                      listen_host: str, advertise_host: str,
                      generation: str = "") -> dict:
    """Scenario + run prefix → the target manifest the server serves and the
    gnmic targets file references. Device NAMES carry the run prefix (that is
    the gnmic target name, hence the `source`/`device` label in
    VictoriaMetrics, hence teardown-by-prefix)."""
    devices = []
    for dev in sc["devices"]:
        name = str(dev["name"])
        devices.append({
            "name": prefix + name,
            "scenario_name": name,
            "tenant": str(dev["tenant"]),
            "port": int(device_ports[name]),
            "interfaces": [{"name": str(i["name"]), "ifindex": k + 1}
                           for k, i in enumerate(dev.get("interfaces") or [])],
            "bgp_neighbors": [{"peer_ip": str(nb["peer_ip"])}
                              for nb in dev.get("bgp_neighbors") or []],
        })
    return {"generation": generation, "listen_host": listen_host,
            "advertise_host": advertise_host, "devices": devices}


def render_gnmic_targets(manifest: dict, username: str = "admin",
                         password: str = "twin",
                         subscriptions: tuple[str, ...] = ("oc-interfaces",
                                                           "oc-bgp")) -> str:
    """The targets fragment an operator MERGES into
    `deployment/docker/gnmic/gnmic.yaml` (design §4.6: gnmic has no dynamic
    target discovery in our pinned config, so the merge is manual and the
    twin's job is to render it exactly)."""
    host = manifest["advertise_host"]
    lines = [
        "# GENERATED by scripts/lab/twin/gnmi_server.py — twin gNMI targets",
        f"# generation: {manifest.get('generation') or 'n/a'}",
        "# Merge these rows under `targets:` in deployment/docker/gnmic/",
        "# gnmic.yaml, then restart gnmic. Remove them at twin teardown —",
        "# they reference run-scoped device names (twx-<runid>-*).",
        "targets:",
    ]
    for dev in manifest["devices"]:
        lines += [
            f"  {host}:{dev['port']}:",
            f"    name: {dev['name']}",
            f"    username: {username}",
            f"    password: {password}",
            "    insecure: true",
            f"    subscriptions: [{', '.join(subscriptions)}]",
        ]
    return "\n".join(lines) + "\n"


# ── CLI ─────────────────────────────────────────────────────────────────────

def build_targets(manifest: dict) -> list[DeviceTarget]:
    return [DeviceTarget(spec) for spec in manifest["devices"]]


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Twin gNMI target server (minimal OpenConfig fake)")
    ap.add_argument("--manifest", required=True,
                    help="target manifest JSON (generate_manifest output)")
    ap.add_argument("--fault-journal", default="",
                    help="JSONL fault-op journal to tail (twin emission side)")
    ap.add_argument("--listen-host", default="",
                    help="bind address (default: the manifest's listen_host)")
    ap.add_argument("--min-sample-s", type=float, default=1.0,
                    help="floor for a client's sample interval (lab guard)")
    ap.add_argument("--ready-file", default="",
                    help="write a readiness JSON here once listeners are up")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    devices = build_targets(manifest)
    if not devices:
        _log("manifest carries no devices — nothing to serve")
        return 2
    listen = args.listen_host or manifest.get("listen_host") or "127.0.0.1"
    server = TargetServer(devices, listen, args.min_sample_s)
    server.start()
    watcher = None
    if args.fault_journal:
        watcher = FaultJournalWatcher(
            args.fault_journal, {d.name: d for d in devices})
        threading.Thread(target=watcher.run, daemon=True,
                         name="fault-journal").start()
        _log(f"tailing fault journal {args.fault_journal}")
    if args.ready_file:
        tmp = args.ready_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(), "listen_host": listen,
                       "generation": manifest.get("generation"),
                       "targets": [{"name": d.name, "port": d.port}
                                   for d in devices]}, fh, indent=2)
        os.replace(tmp, args.ready_file)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        _log("shutting down")
    finally:
        server.stop()
        if watcher:
            watcher.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
