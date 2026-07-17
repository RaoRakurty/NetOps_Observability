"""GCP log-fidelity lane tests (#105 parity) — python3 -m pytest test_gcp_log_lanes.py

Fixture-driven, no live GCP calls. Covers the program's hard rules in this layer:
  * Bounded rollups only — per-key aggregation, MAX_ROLLUP_KEYS cardinality cap,
    truncation is stamped on the events (never silent).
  * GCP VPC flow logs have NO reject records — the flow lane can only ever emit
    volume; the REJECT lane is Firewall Rules Logging DENIED.
  * Cloud Armor rides the LB request log — one batch feeds two rollups.
  * The shared entries:list reader keeps the audit lane's checkpoint discipline
    (overlap + insertId dedup + advance-over-everything-seen + bounded pages).
  * poll_log_lanes: lanes are opt-in, tenant is stamped, one bad lane never
    kills the others or rolls back their checkpoints.
"""
from __future__ import annotations

import json

import gcp
import gcp_log_lanes as lanes

PROJECT = "test-proj"


def _flow_entry(vm="web-1", zone="us-central1-a", reporter="SRC", bytes_sent="1000",
                packets="10", subnet="app-subnet", ts="2026-07-15T10:00:00Z",
                insert_id="f1"):
    side = "src_instance" if reporter == "SRC" else "dest_instance"
    vpc_side = "src_vpc" if reporter == "SRC" else "dest_vpc"
    payload = {
        "connection": {"src_ip": "10.0.0.5", "dest_ip": "10.0.1.9",
                       "src_port": 41000, "dest_port": 443, "protocol": 6},
        "reporter": reporter,
        "bytes_sent": bytes_sent, "packets_sent": packets,
        "end_time": ts,
        vpc_side: {"project_id": PROJECT, "subnetwork_name": subnet, "vpc_name": "vpc-1"},
    }
    if vm:
        payload[side] = {"project_id": PROJECT, "vm_name": vm, "zone": zone}
    return {
        "insertId": insert_id, "timestamp": ts,
        "resource": {"type": "gce_subnetwork",
                     "labels": {"project_id": PROJECT, "location": "us-central1"}},
        "jsonPayload": payload,
    }


def _fw_entry(rule="deny-ssh", disposition="DENIED", ts="2026-07-15T10:00:00Z",
              vm="web-1", src="203.0.113.9", dport=22, insert_id="w1"):
    return {
        "insertId": insert_id, "timestamp": ts,
        "resource": {"type": "gce_subnetwork", "labels": {"location": "us-central1"}},
        "jsonPayload": {
            "disposition": disposition,
            "connection": {"src_ip": src, "dest_ip": "10.0.0.5",
                           "src_port": 55555, "dest_port": dport, "protocol": 6},
            "rule_details": {"reference": f"network:vpc-1/firewall:{rule}",
                             "priority": 1000, "action": "DENY", "direction": "INGRESS"},
            "instance": {"vm_name": vm, "project_id": PROJECT},
        },
    }


def _lb_entry(status=502, url_map="web-map", ts="2026-07-15T10:00:00Z",
              status_details="failed_to_pick_backend", armor_outcome="",
              armor_policy="edge-policy", armor_priority=100, insert_id="l1"):
    payload = {"statusDetails": status_details}
    if armor_outcome:
        payload["enforcedSecurityPolicy"] = {
            "name": armor_policy, "outcome": armor_outcome,
            "priority": armor_priority, "configuredAction": "DENY",
        }
    return {
        "insertId": insert_id, "timestamp": ts,
        "resource": {"type": "http_load_balancer",
                     "labels": {"project_id": PROJECT, "url_map_name": url_map,
                                "forwarding_rule_name": "web-fr",
                                "backend_service_name": "web-be"}},
        "httpRequest": {"requestMethod": "GET", "requestUrl": "https://shop.example/cart",
                        "status": status, "remoteIp": "198.51.100.7"},
        "jsonPayload": payload,
    }


def _dns_entry(name="api.internal.example.", rcode="NXDOMAIN", ts="2026-07-15T10:00:00Z",
               insert_id="d1"):
    return {
        "insertId": insert_id, "timestamp": ts,
        "resource": {"type": "dns_query", "labels": {"location": "us-central1"}},
        "jsonPayload": {"queryName": name, "queryType": "A", "responseCode": rcode,
                        "sourceIP": "10.0.0.5", "sourceNetwork": "vpc-1",
                        "vmInstanceName": "web-1"},
    }


# ── flow lane ─────────────────────────────────────────────────────────────────


def test_flow_rollup_aggregates_per_instance():
    entries = [
        _flow_entry(bytes_sent="1000", packets="10", insert_id="a"),
        _flow_entry(bytes_sent="500", packets="5", ts="2026-07-15T10:02:00Z", insert_id="b"),
        _flow_entry(vm="db-1", bytes_sent="42", packets="1", insert_id="c"),
    ]
    out = lanes.flow_volume_rollup(entries, PROJECT)
    assert len(out) == 2
    by_id = {e["resource_id"]: e for e in out}
    web = by_id[f"projects/{PROJECT}/zones/us-central1-a/instances/web-1"]
    assert web["kind"] == "cloud_flow_volume"
    assert web["value"] == 1500.0
    assert web["attrs"]["flows"] == "2"
    assert web["attrs"]["packets"] == "15"
    assert web["ts"] == "2026-07-15T10:02:00Z"          # newest window end
    assert web["attrs"]["provider"] == "gcp"
    assert web["region"] == "us-central1"


def test_flow_rollup_never_fabricates_a_reject():
    # THE verified GCP fact: vpc_flows has no accept/reject field — every record
    # is accepted traffic. The rollup can only ever emit volume.
    out = lanes.flow_volume_rollup([_flow_entry(insert_id=str(i)) for i in range(5)], PROJECT)
    assert {e["kind"] for e in out} == {"cloud_flow_volume"}
    assert all(e["metric_name"] == "accepted_flow_bytes" for e in out)


def test_flow_rollup_dest_reporter_and_subnet_fallback():
    dest = _flow_entry(reporter="DEST", vm="db-1", insert_id="a")
    no_vm = _flow_entry(vm="", insert_id="b")           # external endpoint: subnet fallback
    out = lanes.flow_volume_rollup([dest, no_vm], PROJECT)
    ids = {e["resource_id"] for e in out}
    assert f"projects/{PROJECT}/zones/us-central1-a/instances/db-1" in ids
    assert "subnetwork:app-subnet" in ids


def test_flow_rollup_empty_batch_is_empty():
    assert lanes.flow_volume_rollup([], PROJECT) == []


# ── flow PAIR lane (#9 service dependency map talks_to edges) ─────────────────


def test_flow_pair_rollup_keeps_the_peer():
    entries = [
        _flow_entry(bytes_sent="1000", packets="10", insert_id="a"),
        _flow_entry(bytes_sent="500", packets="5", ts="2026-07-15T10:02:00Z", insert_id="b"),
    ]
    out = lanes.flow_pair_rollup(entries, PROJECT)
    assert len(out) == 1                                  # one signal per pair, not per record
    pair = out[0]
    assert pair["kind"] == "cloud_flow_pair"
    assert pair["resource_id"] == "10.0.0.5->10.0.1.9"
    assert pair["value"] == 1500.0
    assert pair["metric_name"] == "flow_pair_bytes"
    assert pair["attrs"]["srcaddr"] == "10.0.0.5"
    assert pair["attrs"]["dstaddr"] == "10.0.1.9"
    assert pair["attrs"]["action"] == "ACCEPT" and pair["attrs"]["flows"] == "2"
    assert pair["attrs"]["provider"] == "gcp"
    assert pair["ts"] == "2026-07-15T10:02:00Z"           # newest window end
    assert f"projects/{PROJECT}/zones/us-central1-a/instances/web-1" in pair["entity_tokens"]
    assert "10.0.0.5" in pair["entity_tokens"] and "10.0.1.9" in pair["entity_tokens"]


def test_flow_pair_rollup_is_topk_bounded_and_stamped():
    entries = []
    for i in range(30):
        e = _flow_entry(bytes_sent=str(5000 - i), insert_id=str(i))
        e["jsonPayload"]["connection"]["dest_ip"] = f"10.0.9.{i}"
        entries.append(e)
    out = lanes.flow_pair_rollup(entries, PROJECT, top_k=4)
    assert len(out) == 4                                  # bounded, largest bytes win
    assert [e["value"] for e in out] == [5000.0, 4999.0, 4998.0, 4997.0]
    # truncation is observable, never silent (§10)
    assert all(e["attrs"]["rollup_truncated"] == "26" for e in out)


def test_flow_pair_rollup_skips_missing_or_self_peers():
    no_conn = _flow_entry(insert_id="a")
    del no_conn["jsonPayload"]["connection"]
    self_talk = _flow_entry(insert_id="b")
    self_talk["jsonPayload"]["connection"]["dest_ip"] = "10.0.0.5"
    assert lanes.flow_pair_rollup([no_conn, self_talk], PROJECT) == []


# ── firewall lane (the GCP REJECT lane) ───────────────────────────────────────


def test_firewall_rollup_denied_only_per_rule():
    entries = [
        _fw_entry(insert_id="a"),
        _fw_entry(insert_id="b", ts="2026-07-15T10:03:00Z"),
        _fw_entry(rule="allow-web", disposition="ALLOWED", insert_id="c"),
    ]
    out = lanes.firewall_reject_rollup(entries, PROJECT)
    assert len(out) == 1
    ev = out[0]
    assert ev["kind"] == "cloud_flow_log"               # the shared REJECT fault kind
    assert ev["metric_name"] == "rejected_flow"
    assert ev["resource_id"] == "network:vpc-1/firewall:deny-ssh"
    assert ev["value"] == 2.0
    assert ev["ts"] == "2026-07-15T10:03:00Z"
    assert ev["attrs"]["action"] == "REJECT"            # cross-provider vocabulary
    assert ev["attrs"]["disposition"] == "DENIED"       # the native term, kept
    assert ev["attrs"]["rule"] == "deny-ssh"
    assert ev["attrs"]["dstport"] == "22"
    assert ev["attrs"]["protocol"] == "tcp"


def test_firewall_rollup_skips_ruleless_records():
    e = _fw_entry()
    e["jsonPayload"]["rule_details"] = {}
    assert lanes.firewall_reject_rollup([e], PROJECT) == []


# ── LB lane (5xx + Cloud Armor off one batch) ────────────────────────────────


def test_lb_rollup_5xx_only_per_lb_and_status():
    entries = [
        _lb_entry(status=502, insert_id="a"),
        _lb_entry(status=502, ts="2026-07-15T10:05:00Z", insert_id="b"),
        _lb_entry(status=503, insert_id="c"),
        _lb_entry(status=200, insert_id="d"),
        _lb_entry(status=404, insert_id="e"),
    ]
    out = lanes.lb_5xx_rollup(entries, PROJECT)
    assert len(out) == 2
    by_status = {e["attrs"]["status"]: e for e in out}
    assert by_status["502"]["value"] == 2.0
    assert by_status["502"]["kind"] == "cloud_lb_log"
    assert by_status["502"]["resource_id"] == "web-map"
    assert by_status["502"]["severity"] == "high"
    assert by_status["502"]["attrs"]["status_details"] == "failed_to_pick_backend"
    assert by_status["502"]["ts"] == "2026-07-15T10:05:00Z"
    assert by_status["503"]["value"] == 1.0


def test_armor_rollup_rides_the_same_batch_deny_only():
    entries = [
        _lb_entry(status=403, armor_outcome="DENY", insert_id="a"),
        _lb_entry(status=403, armor_outcome="DENY", ts="2026-07-15T10:06:00Z", insert_id="b"),
        _lb_entry(status=200, armor_outcome="ACCEPT", insert_id="c"),
        _lb_entry(status=502, insert_id="d"),           # no Armor block on it
    ]
    waf = lanes.armor_block_rollup(entries, PROJECT)
    assert len(waf) == 1
    ev = waf[0]
    assert ev["kind"] == "cloud_waf_log"
    assert ev["metric_name"] == "waf_blocked_requests"
    assert ev["resource_id"] == "edge-policy"
    assert ev["attrs"]["rule"] == "100"
    assert ev["attrs"]["action"] == "BLOCK"
    assert ev["value"] == 2.0
    # and the SAME batch still yields the 5xx signal — one fetch, two rollups
    assert len(lanes.lb_5xx_rollup(entries, PROJECT)) == 1


# ── DNS lane ──────────────────────────────────────────────────────────────────


def test_dns_rollup_errors_only_name_entity():
    entries = [
        _dns_entry(insert_id="a"),
        _dns_entry(insert_id="b", ts="2026-07-15T10:07:00Z"),
        _dns_entry(rcode="SERVFAIL", insert_id="c"),
        _dns_entry(name="ok.example.", rcode="NOERROR", insert_id="d"),
    ]
    out = lanes.dns_error_rollup(entries, PROJECT)
    assert len(out) == 2
    by_rcode = {e["attrs"]["rcode"]: e for e in out}
    nx = by_rcode["NXDOMAIN"]
    assert nx["kind"] == "cloud_dns_log"
    assert nx["resource_id"] == "api.internal.example"  # trailing dot stripped
    assert nx["value"] == 2.0
    assert nx["ts"] == "2026-07-15T10:07:00Z"
    assert nx["attrs"]["query_type"] == "A"
    assert nx["attrs"]["sample_client"] == "10.0.0.5"


# ── cardinality cap ───────────────────────────────────────────────────────────


def test_rollup_cardinality_is_capped_and_stamped():
    entries = []
    # one high-count name that must survive the cap + 150 singletons
    for i in range(3):
        entries.append(_dns_entry(name="hot.example.", insert_id=f"h{i}"))
    for i in range(150):
        entries.append(_dns_entry(name=f"n{i:03d}.example.", insert_id=f"s{i}"))
    out = lanes.dns_error_rollup(entries, PROJECT)
    assert len(out) == lanes.MAX_ROLLUP_KEYS
    assert out[0]["resource_id"] == "hot.example"        # top-count key kept first
    dropped = 151 - lanes.MAX_ROLLUP_KEYS
    assert all(e["attrs"]["rollup_truncated"] == str(dropped) for e in out)


def test_uncapped_rollup_has_no_truncation_stamp():
    out = lanes.dns_error_rollup([_dns_entry()], PROJECT)
    assert "rollup_truncated" not in out[0]["attrs"]


# ── shared entries:list reader ────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_reader_dedups_and_checkpoints_on_everything_seen(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(json.loads(req.data.decode()))
        return _FakeResp({"entries": [
            _dns_entry(insert_id="dup", ts="2026-07-15T10:00:00Z"),
            _dns_entry(insert_id="new", ts="2026-07-15T10:01:00Z"),
        ]})

    monkeypatch.setattr(gcp.urllib.request, "urlopen", fake_urlopen)
    fresh, newest, seen = gcp.list_log_entries(
        "tok", 'logName="x"', "2026-07-15T09:59:00Z", seen_ids=["dup"])
    assert [e["insertId"] for e in fresh] == ["new"]     # dup suppressed
    assert newest == "2026-07-15T10:01:00Z"              # anchored on ALL seen
    assert set(seen) == {"dup", "new"}                   # next overlap window
    # the request carried the 120s overlap, not the bare cursor
    assert 'timestamp>"2026-07-15T09:57:00' in calls[0]["filter"]


def test_reader_empty_window_still_advances(monkeypatch):
    monkeypatch.setattr(gcp.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp({}))
    since = "2020-01-01T00:00:00Z"
    fresh, newest, seen = gcp.list_log_entries("tok", 'logName="x"', since)
    assert fresh == [] and seen == []
    assert newest > since                                # delivery-lagged now, never pinned


def test_reader_page_ceiling_is_bounded(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        return _FakeResp({"entries": [_dns_entry(insert_id=f"i{len(calls)}")],
                          "nextPageToken": "more"})      # claims more forever

    monkeypatch.setattr(gcp.urllib.request, "urlopen", fake_urlopen)
    fresh, _, _ = gcp.list_log_entries("tok", 'logName="x"', "2026-07-15T09:00:00Z")
    assert len(calls) == 5                               # _LOG_MAX_PAGES, never unbounded
    assert len(fresh) == 5


# ── poll_log_lanes wiring ─────────────────────────────────────────────────────


class _FakeProducer:
    def __init__(self):
        self.sent: list[tuple[str, dict]] = []

    def send(self, topic: str, ev: dict):
        self.sent.append((topic, ev))


def test_poll_log_lanes_off_by_default(monkeypatch):
    # No gate set → no lanes, no fetches, nothing produced (honest lanes).
    def boom(*a, **k):
        raise AssertionError("no lane may fetch when all gates are off")
    monkeypatch.setattr(gcp, "list_log_entries", boom)
    prod = _FakeProducer()
    assert gcp.poll_log_lanes("tok", prod, "t1", {}, "2026-07-15T09:45:00Z") == 0
    assert prod.sent == []


def test_poll_log_lanes_stamps_tenant_and_checkpoints(monkeypatch):
    monkeypatch.setattr(gcp, "GCP_DNS_LOGS", True)
    monkeypatch.setattr(gcp, "GCP_FIREWALL_LOGS", True)
    monkeypatch.setattr(gcp, "PROJECT", PROJECT)

    def fake_reader(tok, log_filter, since, seen_ids=None, **kw):
        if "dns_queries" in log_filter:
            return [_dns_entry()], "2026-07-15T10:00:00Z", ["d1"]
        return [_fw_entry()], "2026-07-15T10:00:30Z", ["w1"]

    monkeypatch.setattr(gcp, "list_log_entries", fake_reader)
    prod, st = _FakeProducer(), {}
    n = gcp.poll_log_lanes("tok", prod, "tenant-a", st, "2026-07-15T09:45:00Z")
    assert n == 2
    by_kind = {ev["kind"]: (topic, ev) for topic, ev in prod.sent}
    assert set(by_kind) == {"cloud_dns_log", "cloud_flow_log"}
    for topic, ev in prod.sent:
        assert topic == "netops.cloud"
        assert ev["tenant_id"] == "tenant-a"             # tenancy stamped, never guessed
        assert ev["attrs"]["provider"] == "gcp"
    assert st["gcp_dns_ts"] == "2026-07-15T10:00:00Z"
    assert st["gcp_dns_seen"] == ["d1"]
    assert st["gcp_fw_ts"] == "2026-07-15T10:00:30Z"


def test_poll_log_lanes_lb_batch_feeds_both_rollups(monkeypatch):
    monkeypatch.setattr(gcp, "GCP_LB_LOGS", True)
    monkeypatch.setattr(gcp, "PROJECT", PROJECT)
    entries = [_lb_entry(status=502, insert_id="a"),
               _lb_entry(status=403, armor_outcome="DENY", insert_id="b")]
    monkeypatch.setattr(gcp, "list_log_entries",
                        lambda *a, **k: (entries, "2026-07-15T10:01:00Z", ["a", "b"]))
    prod, st = _FakeProducer(), {}
    n = gcp.poll_log_lanes("tok", prod, "t1", st, "2026-07-15T09:45:00Z")
    assert n == 2
    kinds = {ev["kind"] for _, ev in prod.sent}
    assert kinds == {"cloud_lb_log", "cloud_waf_log"}    # one fetch, two matrix rows


def test_poll_log_lanes_flow_batch_feeds_volume_and_pairs(monkeypatch):
    monkeypatch.setattr(gcp, "GCP_VPC_FLOW_LOGS", True)
    monkeypatch.setattr(gcp, "PROJECT", PROJECT)
    entries = [_flow_entry(insert_id="a")]
    monkeypatch.setattr(gcp, "list_log_entries",
                        lambda *a, **k: (entries, "2026-07-15T10:01:00Z", ["a"]))
    prod, st = _FakeProducer(), {}
    n = gcp.poll_log_lanes("tok", prod, "t1", st, "2026-07-15T09:45:00Z")
    assert n == 2
    kinds = {ev["kind"] for _, ev in prod.sent}
    assert kinds == {"cloud_flow_volume", "cloud_flow_pair"}  # one fetch, peer kept (#9)


def test_poll_log_lanes_one_bad_lane_never_kills_the_rest(monkeypatch):
    monkeypatch.setattr(gcp, "GCP_VPC_FLOW_LOGS", True)
    monkeypatch.setattr(gcp, "GCP_DNS_LOGS", True)
    monkeypatch.setattr(gcp, "PROJECT", PROJECT)

    def fake_reader(tok, log_filter, since, seen_ids=None, **kw):
        if "vpc_flows" in log_filter:
            raise RuntimeError("quota exceeded")
        return [_dns_entry()], "2026-07-15T10:00:00Z", ["d1"]

    monkeypatch.setattr(gcp, "list_log_entries", fake_reader)
    prod, st = _FakeProducer(), {"gcp_flow_ts": "keep-me"}
    n = gcp.poll_log_lanes("tok", prod, "t1", st, "2026-07-15T09:45:00Z")
    assert n == 1                                        # DNS lane still ran
    assert prod.sent[0][1]["kind"] == "cloud_dns_log"
    assert st["gcp_flow_ts"] == "keep-me"                # failed lane's checkpoint untouched
    assert st["gcp_dns_ts"] == "2026-07-15T10:00:00Z"
