"""Wire-payload builders + bus injector (tracker 152, design §4).

Bus lanes (T1 core): syslog, probes, cloud, metrics — injected bus-direct via
the broker's console producer over the TLS listener (the PROVEN
`correlation_e2e.py` / mini-ladder path), byte-shaped after the live-proven
builders there and keyed by tenant id (Java-murmur2 partitioner contract,
design §6).

UDP lanes (FIDELITY WAVE, design §4.4/§4.5): `trap` (SNMPv2c → the api trap
receiver) and `flows` (NetFlow v5 / IPFIX → goflow2), encoded by `wire.py`
and carried by a `UdpLanes` transport —

  * hostname fidelity: traps go from the twin HOST to the published :162
    (attribution = community + sysName varbind, `trapIdentityTrusted`);
    flows are SKIPPED LOUDLY (a host-sourced flow's `sampler_address` could
    never match a registered device — design §3.4);
  * source_ip fidelity: both lanes send from inside the twin container,
    per-device source addresses (198.19.x.y aliases), straight to the
    intake's twinnet address — trap source-IP attribution and flow
    `sampler_address` → registry rekey are then genuinely per-device.

Every hostname / target / device / sysName field carries the `twx-<runid>-`
prefixed name, which is what makes verified teardown (purge by entity LIKE)
possible.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import time
from datetime import datetime, timedelta, timezone

import gnmi_h2
import wire
from stack import Stack, log, warn

# An empty SETTINGS frame: length 0, type SETTINGS, no flags, stream 0. Sent
# after the client preface by GnmiLane.live()'s HTTP/2 liveness probe.
_EMPTY_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

LANE_TOPIC = {
    "syslog": "netops.syslog",
    "probes": "netops.probes",
    "metrics": "netops.metrics",
    "cloud": "netops.cloud",
    # UDP lanes: the value is the topic the intake eventually produces to —
    # journal/report vocabulary only, the twin never writes these topics.
    "trap": "netops.snmptrap",
    "flows": "netops.flows.raw",
    # gNMI is a PULL lane and never reaches the bus at all: gnmic streams the
    # twin target's state and remote-writes it to VictoriaMetrics. The "topic"
    # here is journal vocabulary naming that SINK, not a Kafka topic.
    "gnmi": "victoria:gnmi",
}

UDP_LANES = ("trap", "flows")
GNMI_LANE = "gnmi"

TRAP_NAME_TO_OID = {
    "coldStart": wire.TRAP_COLDSTART,
    "warmStart": wire.TRAP_WARMSTART,
    "linkDown": wire.TRAP_LINKDOWN,
    "linkUp": wire.TRAP_LINKUP,
    "bgpEstablished": wire.TRAP_BGP_ESTABLISHED,
    "bgpBackwardTransition": wire.TRAP_BGP_BACKWARD,
}


def iso(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)
            ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_payload(item: dict, prefix: str, tenant_ids: dict[str, str]) -> str:
    """One schedule item (stories.py shape) → the wire JSON string.

    `prefix` is the run's `twx-<runid>-`; `tenant_ids` maps scenario aliases →
    real opaque tenant ids (cloud events carry the tenant EXPLICITLY — the
    engine drops untenanted cloud events by design)."""
    lane = item["lane"]
    if lane == "syslog":
        return json.dumps({
            "hostname": prefix + item["device"],
            "appname": item["appname"],
            "message": item["message"],
            "severity": item["severity"],
            "timestamp": iso(),
        })
    if lane == "probes":
        loss = float(item["loss_pct"])
        return json.dumps({
            "kind": "icmp",
            "prober": prefix + item["prober"],
            "target": prefix + item["device"],
            "ts": iso(),
            "rtt_ms": float(item.get("rtt_ms") or 0.0),
            "loss_pct": loss,
            "ok": loss < 100,
            "probe_intent": item["probe_intent"],
            "vantage_type": item["vantage_type"],
        })
    if lane == "metrics":
        return json.dumps({
            "device": prefix + item["device"],
            "metric": item.get("metric", "cpu"),
            "value": float(item["value"]),
            "signal_family": item["signal_family"],
            "collection_path": "snmp_poll",
            "ts": iso(float(item.get("ts_off") or 0.0)),
        })
    if lane == "cloud":
        return json.dumps({
            "kind": item["kind"],
            "tenant_id": tenant_ids[item["tenant"]],
            "resource_id": prefix + item["resource_id"],
            "account": item["account"],
            "region": item["region"],
            "severity": item["severity"],
            "value": float(item.get("value") or 0.0),
            "metric_name": item.get("metric_name") or "",
            "ts": iso(),
        })
    raise ValueError(
        f"unknown bus lane {lane!r} — bus lanes are "
        f"{sorted(set(LANE_TOPIC) - set(UDP_LANES) - {GNMI_LANE})} "
        f"(trap/flows are UDP lanes, built by build_trap_bytes/"
        f"build_flow_packets; gnmi is a PULL lane, applied by GnmiLane)")


# ── UDP lane payload builders (pure functions — unit-tested sans sockets) ──

def build_trap_bytes(item: dict, prefix: str, community: str,
                     uptime_ticks: int) -> bytes:
    """One schedule trap item → the SNMPv2c datagram. Always carries a
    sysName.0 varbind (= prefixed device name) so hostname-mode attribution
    can rescue identity via `trapIdentityTrusted` (community + sysName)."""
    trap = item["trap"]
    oid = TRAP_NAME_TO_OID.get(trap)
    if oid is None:
        raise ValueError(f"unknown trap {trap!r} — one of "
                         f"{sorted(TRAP_NAME_TO_OID)}")
    varbinds: list[tuple[str, int, object]] = []
    ifindex = item.get("ifindex")
    if trap in ("linkDown", "linkUp"):
        idx = int(ifindex or 1)
        varbinds.append((f"{wire.VB_IFINDEX}.{idx}", wire.TAG_INT, idx))
        if item.get("ifdescr"):
            varbinds.append((f"{wire.VB_IFDESCR}.{idx}", wire.TAG_OCTETSTR,
                             item["ifdescr"]))
        if item.get("ifname"):
            varbinds.append((f"{wire.VB_IFNAME}.{idx}", wire.TAG_OCTETSTR,
                             item["ifname"]))
    if trap in ("bgpEstablished", "bgpBackwardTransition"):
        peer = str(item.get("peer_ip") or "")
        if not peer:
            raise ValueError(f"bgp trap item without peer_ip: {item}")
        varbinds.append((f"{wire.VB_BGP_PEER_ADDR}.{peer}", wire.TAG_IPADDR,
                         peer))
    varbinds.append((wire.SYSNAME_OID, wire.TAG_OCTETSTR,
                     prefix + item["device"]))
    return wire.encode_trap_v2c(community, uptime_ticks, oid, varbinds)


# Flow conversation palette (deterministic draw per flow_seed; internal nets
# use the twin's own benchmark space so synthetic flows are self-evidently
# lab traffic).
_FLOW_NETS = ["198.19.100.", "198.19.101.", "10.60.10.", "10.60.20."]
_FLOW_EXTERNAL = ["8.8.8.8", "1.1.1.1", "52.94.236.248", "13.107.42.14"]
_FLOW_PROTOS = [(6, [443, 22, 8080, 5432]), (17, [53, 123, 514]), (1, [0])]


def flows_from_seed(flow_seed: str, count: int) -> list[dict]:
    """Expand a compact flow item into `count` deterministic flow tuples."""
    rng = random.Random(flow_seed)
    out = []
    for _ in range(count):
        proto, ports = rng.choice(_FLOW_PROTOS)
        pkts = rng.randint(1, 4000)
        avg = {6: 800, 17: 300, 1: 84}[proto]
        out.append({
            "src": rng.choice(_FLOW_NETS) + str(rng.randint(2, 250)),
            "dst": (rng.choice(_FLOW_EXTERNAL) if rng.random() < 0.4
                    else rng.choice(_FLOW_NETS) + str(rng.randint(2, 250))),
            "sport": rng.randint(1024, 65535) if proto != 1 else 0,
            "dport": rng.choice(ports) if proto != 1 else 0,
            "proto": proto, "pkts": pkts,
            "octets": pkts * rng.randint(int(avg * 0.5), int(avg * 1.5)),
            "in_if": rng.randint(1, 8), "out_if": rng.randint(1, 8),
            "tcp_flags": rng.choice([0x02, 0x10, 0x18]) if proto == 6 else 0,
        })
    return out


def build_flow_packets(item: dict, protocol: str, seq: int, domain: int,
                       uptime_ms: int) -> tuple[list[bytes], int]:
    """One schedule flow item → wire packets (chunked to ≤30 records for v5,
    ≤20 for IPFIX). Returns (packets, records_encoded); the caller advances
    the exporter's sequence by records (v5) / packets (IPFIX counts records
    too per RFC 7011 §3.1 for data records)."""
    flows = flows_from_seed(item["flow_seed"], int(item["count"]))
    if not flows:
        return [], 0
    packets: list[bytes] = []
    if protocol == "netflow5":
        for i in range(0, len(flows), 30):
            chunk = flows[i:i + 30]
            packets.append(wire.encode_netflow_v5(chunk, uptime_ms, seq))
            seq += len(chunk)
    elif protocol == "ipfix":
        for i in range(0, len(flows), 20):
            chunk = flows[i:i + 20]
            # template rides in EVERY packet — goflow2 keeps templates per
            # (exporter, domain) in memory only; always-inline is the
            # restart-proof choice at twin rates.
            packets.append(wire.encode_ipfix(chunk, seq, domain,
                                             with_template=True))
            seq += len(chunk)
    else:
        raise ValueError(f"unknown flow protocol {protocol!r}")
    return packets, len(flows)


class UdpLanes:
    """Transport for the trap/flows lanes. `container_send` (from
    fidelity.send_batch, curried with the twin cid) routes datagrams through
    the twin container with per-device source binds; without it, datagrams
    leave a plain host socket (hostname fidelity — traps only)."""

    NETFLOW5_PORT = 2055
    IPFIX_PORT = 4739

    def __init__(self, trap_target: tuple[str, int] | None = None,
                 flow_host: str | None = None,
                 flow_protocol: str = "netflow5",
                 community: str = "public",
                 src_ips: dict[str, str] | None = None,
                 container_send=None):
        self.trap_target = trap_target
        self.flow_host = flow_host
        self.flow_protocol = flow_protocol
        self.community = community
        self.src_ips = src_ips or {}
        self.container_send = container_send
        self._sock: socket.socket | None = None
        self._t0 = time.monotonic()
        self._flow_seq: dict[str, int] = {}
        self._flow_domain: dict[str, int] = {}

    def uptime_ticks(self) -> int:
        return int((time.monotonic() - self._t0) * 100)

    def _domain(self, device: str) -> int:
        if device not in self._flow_domain:
            self._flow_domain[device] = 1 + len(self._flow_domain)
        return self._flow_domain[device]

    def build_item(self, it: dict, prefix: str
                   ) -> tuple[list[tuple[str | None, str, int, bytes]], int] | None:
        """One UDP-lane item → ([(src, host, port, payload)], record_count),
        or None when this fidelity mode cannot deliver the lane (the caller
        counts + warns the skip)."""
        src = self.src_ips.get(it["device"])
        if it["lane"] == "trap":
            if self.trap_target is None:
                return None
            pkt = build_trap_bytes(it, prefix, self.community,
                                   self.uptime_ticks())
            return [(src, self.trap_target[0], self.trap_target[1], pkt)], 1
        if it["lane"] == "flows":
            if self.flow_host is None or src is None:
                return None
            dev = it["device"]
            seq = self._flow_seq.get(dev, 0)
            pkts, n = build_flow_packets(
                it, self.flow_protocol, seq, self._domain(dev),
                uptime_ms=int((time.monotonic() - self._t0) * 1000))
            self._flow_seq[dev] = seq + n
            port = (self.NETFLOW5_PORT if self.flow_protocol == "netflow5"
                    else self.IPFIX_PORT)
            return [(src, self.flow_host, port, p) for p in pkts], n
        raise ValueError(f"not a UDP lane: {it['lane']!r}")

    def send(self, datagrams: list[tuple[str | None, str, int, bytes]]
             ) -> tuple[bool, str]:
        if not datagrams:
            return True, ""
        if self.container_send is not None:
            return self.container_send(datagrams)
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for src, host, port, payload in datagrams:
                # host mode cannot source-bind 198.19 addresses; src is
                # ignored by design (hostname fidelity).
                self._sock.sendto(payload, (host, port))
            return True, ""
        except OSError as exc:
            return False, f"host UDP send failed: {exc}"


class GnmiLane:
    """Transport for the `gnmi` lane (design §4.6).

    Inverted with respect to every other lane: nothing is SENT. A gNMI item is
    a state op appended to the twin gNMI target server's FAULT JOURNAL
    (`gnmi_server.FaultJournalWatcher` tails it), after which the platform's
    `gnmic` collector observes the change on its own subscriptions. The
    journal is the transport AND the audit trail — every applied op sits next
    to `events.jsonl` in the run dir, replayable.

    `live()` probes the target ports so an unreachable target SKIPS LOUDLY
    (the §3.4 contract the trap/flows lanes already follow) instead of
    labelling a story whose gNMI half never happened.
    """

    def __init__(self, journal_path: str,
                 targets: list[tuple[str, int]] | None = None,
                 connect_timeout: float = 1.5) -> None:
        self.journal_path = journal_path
        self.targets = targets or []
        self.connect_timeout = connect_timeout

    def live(self) -> bool:
        """True when EVERY declared target answers as an HTTP/2 server. All,
        not any: a half-up fleet would silently under-emit a story's gNMI half.

        The probe speaks: it sends the HTTP/2 client preface and requires a
        SETTINGS frame back. A bare `connect()` is NOT enough — the twin's
        target ports sit inside the kernel's ephemeral range
        (`ip_local_port_range`), where a loopback connect can pick the
        destination port as its own source port and SELF-CONNECT, succeeding
        against a target that is not running at all (observed, and the reason
        this check exists in this form).
        """
        if not self.targets:
            return False
        for host, port in self.targets:
            try:
                with socket.create_connection((host, port),
                                              self.connect_timeout) as sock:
                    sock.settimeout(self.connect_timeout)
                    sock.sendall(gnmi_h2.PREFACE + _EMPTY_SETTINGS)
                    head = b""
                    while len(head) < 9:
                        chunk = sock.recv(9 - len(head))
                        if not chunk:
                            return False
                        head += chunk
                    if head[3] != gnmi_h2.FRAME_SETTINGS:
                        return False       # not our target (or a self-connect)
            except OSError:
                return False
        return True

    def apply(self, items: list[dict], prefix: str) -> tuple[bool, str]:
        """Append one batch of ops. fsync'd: the target process is a separate
        reader, and a buffered op is an unemitted fault."""
        if not items:
            return True, ""
        try:
            with open(self.journal_path, "a", encoding="utf-8") as fh:
                fh.writelines(json.dumps({
                    "ts": iso(),
                    "device": prefix + it["device"],
                    "story_id": it.get("story_id"),
                    "op": it["op"],
                    "ifname": it.get("ifname") or "",
                    "peer_ip": it.get("peer_ip") or "",
                    "state": it.get("state") or "",
                }) + "\n" for it in items)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            return False, f"gnmi fault journal write failed: {exc}"
        return True, ""


class Injector:
    """Paced, journaled injection of a deterministic plan.

    Chunks due items every `tick_s`, groups per topic, produces each group
    KEYED by tenant id, journals every produced event to events.jsonl and
    tallies per-lane / per-tenant counts (the emission-side half of the
    design's accounting). Produce failures are counted AND fatal after a small
    tolerance — a run that cannot inject honestly has no verdict."""

    def __init__(self, stack: Stack, prefix: str, tenant_ids: dict[str, str],
                 journal_path: str, tick_s: float = 5.0,
                 udp: UdpLanes | None = None,
                 gnmi: GnmiLane | None = None):
        self.stack = stack
        self.prefix = prefix
        self.tenant_ids = tenant_ids
        self.journal_path = journal_path
        self.tick_s = tick_s
        self.udp = udp
        self.gnmi = gnmi
        self.emitted: dict[str, int] = {}          # lane -> count
        self.emitted_by_tenant: dict[str, dict[str, int]] = {}  # lane->tenant->n
        self.emitted_by_story: dict[str, dict[str, int]] = {}   # story->lane->n
        self.skipped: dict[str, int] = {}          # lane -> undeliverable count
        self._skip_warned: set[str] = set()
        self.produce_failures: list[str] = []

    def _journal(self, fh, item: dict, payload: str) -> None:
        fh.write(json.dumps({
            "ts": iso(),
            "lane": item["lane"],
            "topic": LANE_TOPIC[item["lane"]],
            "story_id": item.get("story_id"),
            "device": self.prefix + item["device"],
            "tenant": item["tenant"],
            "payload_digest": hashlib.sha256(payload.encode()).hexdigest()[:16],
        }) + "\n")

    def _count(self, it: dict, n: int = 1) -> None:
        self.emitted[it["lane"]] = self.emitted.get(it["lane"], 0) + n
        lt = self.emitted_by_tenant.setdefault(it["lane"], {})
        lt[it["tenant"]] = lt.get(it["tenant"], 0) + n
        sid = it.get("story_id")
        if sid:
            ls = self.emitted_by_story.setdefault(sid, {})
            ls[it["lane"]] = ls.get(it["lane"], 0) + n

    def _emit_udp(self, items: list[dict], fh) -> bool:
        """The trap/flows half of a batch. An unconfigured lane SKIPS LOUDLY
        (counted + warned once — design §3.4 hostname-mode contract); a
        configured lane that fails to SEND is a produce failure like any
        other."""
        def skip(it: dict) -> None:
            lane = it["lane"]
            self.skipped[lane] = self.skipped.get(lane, 0) \
                + int(it.get("count") or 1)
            if lane not in self._skip_warned:
                self._skip_warned.add(lane)
                warn(f"{lane} lane undeliverable in this run configuration — "
                     f"SKIPPED (counted in the report); trap needs the "
                     f"FEATURE_SNMP_TRAPS intake, flows need --fidelity "
                     f"source_ip")

        datagrams: list[tuple[str | None, str, int, bytes]] = []
        built: list[tuple[dict, int]] = []
        for it in items:
            res = self.udp.build_item(it, self.prefix) if self.udp else None
            if res is None:
                skip(it)
                continue
            dgs, n = res
            datagrams += dgs
            built.append((it, n))
        if self.udp is not None:
            ok, err = self.udp.send(datagrams)
            if not ok:
                self.produce_failures.append(f"udp: {err}")
                return len(self.produce_failures) < 3
        for it, n in built:
            self._count(it, n)
            self._journal(fh, it,
                          f"{it['lane']}:{it.get('trap') or it.get('flow_seed')}")
        return True

    def _emit_gnmi(self, items: list[dict], fh) -> bool:
        """The gNMI half of a batch: state ops handed to the twin's gNMI
        target server. No running target ⇒ SKIP LOUDLY (same contract as the
        trap/flows lanes); a target that is up but rejects the write is a
        produce failure like any other."""
        if self.gnmi is None:
            for it in items:
                self.skipped["gnmi"] = self.skipped.get("gnmi", 0) + 1
            if "gnmi" not in self._skip_warned:
                self._skip_warned.add("gnmi")
                warn("gnmi lane undeliverable in this run configuration — "
                     "SKIPPED (counted in the report); it needs the twin gNMI "
                     "target server up (scripts/lab/twin/gnmi_server.py) and "
                     "gnmic subscribed to the rendered targets file")
            return True
        ok, err = self.gnmi.apply(items, self.prefix)
        if not ok:
            self.produce_failures.append(f"gnmi: {err}")
            return len(self.produce_failures) < 3
        for it in items:
            self._count(it)
            self._journal(fh, it, f"gnmi:{it['op']}:"
                                  f"{it.get('ifname') or it.get('peer_ip')}")
        return True

    def emit_batch(self, items: list[dict], fh) -> bool:
        """Produce one due batch. Returns False when failures exceed
        tolerance (caller aborts the emission loop loudly)."""
        udp_items = [it for it in items if it["lane"] in UDP_LANES]
        if udp_items and not self._emit_udp(udp_items, fh):
            return False
        gnmi_items = [it for it in items if it["lane"] == GNMI_LANE]
        if gnmi_items and not self._emit_gnmi(gnmi_items, fh):
            return False
        by_topic: dict[str, list[tuple[str, str, dict]]] = {}
        for it in items:
            if it["lane"] in UDP_LANES or it["lane"] == GNMI_LANE:
                continue
            payload = build_payload(it, self.prefix, self.tenant_ids)
            key = self.tenant_ids[it["tenant"]]
            by_topic.setdefault(LANE_TOPIC[it["lane"]], []).append(
                (key, payload, it))
        for topic, rows in sorted(by_topic.items()):
            ok, err = self.stack.produce_keyed(
                topic, [(k, p) for k, p, _ in rows])
            if not ok:
                self.produce_failures.append(f"{topic}: {err}")
                if len(self.produce_failures) >= 3:
                    return False
                continue
            for _k, payload, it in rows:
                self._count(it)
                self._journal(fh, it, payload)
        return True

    def run_schedule(self, items: list[dict], t_start: float,
                     ground_truth_cb=None,
                     heartbeat_cb=None) -> bool:
        """Emit `items` (sorted by relative t) paced against wall clock
        anchored at `t_start` (time.monotonic value). Returns overall
        success. `ground_truth_cb(story_id)` fires when a story's FIRST event
        is emitted (records fired-at)."""
        idx = 0
        fired: set[str] = set()
        with open(self.journal_path, "a", encoding="utf-8") as fh:
            while idx < len(items):
                now_rel = time.monotonic() - t_start
                due = []
                while idx < len(items) and items[idx]["t"] <= now_rel:
                    due.append(items[idx])
                    idx += 1
                if due:
                    for it in due:
                        sid = it.get("story_id")
                        if sid and sid not in fired and ground_truth_cb:
                            fired.add(sid)
                            ground_truth_cb(sid)
                    if not self.emit_batch(due, fh):
                        log(f"ABORTING emission: {len(self.produce_failures)} "
                            f"produce failures (first: "
                            f"{self.produce_failures[0][:160]})")
                        return False
                    fh.flush()
                if heartbeat_cb:
                    heartbeat_cb()
                if idx < len(items):
                    ahead = items[idx]["t"] - (time.monotonic() - t_start)
                    if ahead > 0:
                        time.sleep(min(ahead, self.tick_s))
        return not self.produce_failures
