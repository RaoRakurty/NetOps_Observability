"""Azure storage-log lane tests (#105 build order #2) — python3 -m pytest test_azure_logs.py

Fixture-driven, NO live Azure calls anywhere. Covers the prompt's hard rules:
  * incremental block-blob reads: the offset checkpoint never crosses into the
    mutable `]}` tail, appended fragments parse, truncated tails re-read.
  * VNet flow tuples: flowState D → cloud_flow_log deny rollup; B/C/E →
    cloud_flow_volume per NIC; malformed tuples skipped; NSG-era shapes ignored.
  * LB / WAF / DNS rollups: bounded, per-key, observe-mode noise excluded.
  * P1-6: cardinality is CAPPED — a high-cardinality batch can never firehose.
  * Every emitted kind is in the correlation contract; URLs percent-encode.
"""
from __future__ import annotations

import json

import azure_logs

T = "2026-07-15T09:00:00Z"

# Kinds declared in src/correlation/cloud_producers.py CLOUD_KINDS. The Azure
# lanes reuse the canonical (provider-blind) kinds — if this set ever needs a
# NEW member, it must be declared there first.
CONTRACT_KINDS = {"cloud_flow_log", "cloud_flow_volume", "cloud_flow_pair",
                  "cloud_lb_log", "cloud_waf_log", "cloud_dns_log"}


# ── incremental JSON record extraction ───────────────────────────────────────

def _wrap(records: list[dict]) -> bytes:
    return json.dumps({"records": records}).encode()


def test_scan_whole_document():
    blob = _wrap([{"a": 1}, {"b": 2}])
    recs, consumed = azure_logs.scan_json_records(blob)
    assert recs == [{"a": 1}, {"b": 2}]
    # consumed ends at the LAST RECORD, never inside the mutable ']}' tail
    assert 0 < consumed < len(blob)


def test_scan_appended_fragment_roundtrip():
    """Simulate Azure's block-append behavior: read at t0, blob grows (tail
    ']}' replaced with ',{…}]}'), read the delta from the checkpoint — the new
    record parses, nothing is dropped or duplicated."""
    blob1 = _wrap([{"n": 1}])
    recs1, consumed1 = azure_logs.scan_json_records(blob1)
    assert [r["n"] for r in recs1] == [1]
    blob2 = blob1[:consumed1] + b',{"n": 2}]}'
    recs2, consumed2 = azure_logs.scan_json_records(blob2[consumed1:])
    assert [r["n"] for r in recs2] == [2]
    assert consumed1 + consumed2 <= len(blob2)


def test_scan_truncated_tail_not_consumed():
    blob = _wrap([{"n": 1}])
    cut = blob[:len(blob) - 6]  # slice into the middle of the record
    recs, consumed = azure_logs.scan_json_records(cut)
    assert recs == [] and consumed == 0  # nothing complete → re-read next cycle


def test_scan_json_lines():
    recs, consumed = azure_logs.scan_json_records(b'{"n": 1}\n{"n": 2}\n')
    assert [r["n"] for r in recs] == [1, 2]
    assert consumed == len(b'{"n": 1}\n{"n": 2}')


def test_scan_split_multibyte_utf8_tail():
    payload = _wrap([{"n": 1}]) + "→".encode()[:1]  # dangling utf-8 lead byte
    recs, consumed = azure_logs.scan_json_records(payload)
    assert [r["n"] for r in recs] == [1] and consumed > 0


# ── VNet flow lane ────────────────────────────────────────────────────────────

def _flow_record(tuples: list[str], mac: str = "000D3AF87856",
                 rule: str = "BlockHighRisk") -> dict:
    return {
        "time": T, "flowLogVersion": 4, "macAddress": mac,
        "category": "FlowLogFlowEvent",
        "targetResourceID": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
        "flowRecords": {"flows": [{"aclID": "acl-1", "flowGroups": [
            {"rule": rule, "flowTuples": tuples}]}]},
    }


DENY = "1768467600000,10.0.0.6,10.0.1.9,4242,443,6,I,D,NX,0,0,0,0"
BEGIN = "1768467600000,10.0.0.6,52.239.184.180,23956,443,6,O,B,NX,0,0,0,0"
END = "1768467660000,10.0.0.6,52.239.184.180,23956,443,6,O,E,NX,3,767,2,1580"


def test_vnet_deny_and_accept_rollups():
    evs = azure_logs.vnet_flow_rollups([_flow_record([DENY, DENY, BEGIN, END])])
    by_kind = {e["kind"]: e for e in evs}
    assert set(by_kind) == {"cloud_flow_log", "cloud_flow_volume", "cloud_flow_pair"}

    deny = by_kind["cloud_flow_log"]
    assert deny["value"] == 2.0                       # rolled up, not per-record
    assert deny["resource_id"] == "000D3AF87856"      # NIC MAC = the ENI analog
    assert deny["metric_name"] == "rejected_flow"
    assert deny["severity"] == "warn"
    assert deny["attrs"]["action"] == "REJECT"
    assert deny["attrs"]["rule"] == "BlockHighRisk"
    assert deny["attrs"]["provider"] == "azure"
    assert deny["attrs"]["dstport"] == "443"
    assert deny["attrs"]["protocol"] == "tcp"
    assert deny["ts"].startswith("2026-01-15T")       # tuple epoch-ms, not ingest time

    vol = by_kind["cloud_flow_volume"]
    assert vol["value"] == float(767 + 1580)          # both directions summed
    assert vol["attrs"]["flows"] == "2"               # B + E tuples
    assert vol["attrs"]["packets"] == str(3 + 2)
    assert vol["severity"] == "info"
    # grounding tokens carry NIC + target VNet
    assert "000D3AF87856" in vol["entity_tokens"]
    assert any("virtualNetworks/vnet1" in t for t in vol["entity_tokens"])

    # the peer-preserving pair rollup (#9 talks_to edges): src→dst kept, denied
    # tuples excluded, bytes both directions summed onto the pair
    pair = by_kind["cloud_flow_pair"]
    assert pair["resource_id"] == "10.0.0.6->52.239.184.180"
    assert pair["value"] == float(767 + 1580)
    assert pair["metric_name"] == "flow_pair_bytes"
    assert pair["attrs"]["srcaddr"] == "10.0.0.6"
    assert pair["attrs"]["dstaddr"] == "52.239.184.180"
    assert pair["attrs"]["action"] == "ACCEPT" and pair["attrs"]["flows"] == "2"
    assert pair["severity"] == "info"
    assert "000D3AF87856" in pair["entity_tokens"]
    assert "10.0.0.6" in pair["entity_tokens"] and "52.239.184.180" in pair["entity_tokens"]


def test_vnet_pair_rollup_is_topk_bounded(monkeypatch):
    # 50 distinct destinations from one NIC, volume descending — only the K
    # largest pairs survive (bounded per cycle, never one signal per tuple).
    monkeypatch.setattr(azure_logs, "PAIR_TOP_K", 5)
    tuples = [f"1768467600000,10.0.0.6,10.0.1.{i},1000,443,6,O,E,NX,1,{2000 - i},0,0"
              for i in range(50)]
    pairs = [e for e in azure_logs.vnet_flow_rollups([_flow_record(tuples)])
             if e["kind"] == "cloud_flow_pair"]
    assert len(pairs) == 5
    assert [p["value"] for p in pairs] == [2000.0, 1999.0, 1998.0, 1997.0, 1996.0]


def test_vnet_malformed_tuples_and_records_skipped():
    evs = azure_logs.vnet_flow_rollups([
        _flow_record(["not,a,tuple", ""]),            # short tuples → skipped
        {"category": "FlowLogFlowEvent", "macAddress": "AA"},  # no flowRecords
        {"records": "junk"},                          # NSG-era / foreign shape
    ])
    assert evs == []


def test_vnet_deny_cardinality_capped():
    # 500 distinct rules on one NIC: the rollup must stay bounded, biggest first.
    recs = [_flow_record([DENY] * (2 if i < 10 else 1), rule=f"rule-{i:03d}")
            for i in range(500)]
    evs = [e for e in azure_logs.vnet_flow_rollups(recs) if e["kind"] == "cloud_flow_log"]
    assert len(evs) == azure_logs.MAX_ROLLUP_KEYS
    assert evs[0]["value"] == 2.0                     # largest counts survive


# ── LB access lane ───────────────────────────────────────────────────────────

def _appgw_access(status: int) -> dict:
    return {
        "time": T, "category": "ApplicationGatewayAccessLog",
        "resourceId": "/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/AGW1",
        "properties": {"httpStatus": status, "requestUri": "/api/pay",
                       "host": "shop.example.com", "serverStatus": "502",
                       "clientIP": "203.0.113.9"},
    }


def _fd_access(status: str) -> dict:
    return {
        "time": T, "category": "FrontDoorAccessLog",
        "resourceId": "/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.CDN/PROFILES/FD1",
        "properties": {"httpStatusCode": status, "requestUri": "https://x/api",
                       "hostName": "x.azurefd.net", "httpStatusDetails": "504.0"},
    }


def test_lb_5xx_rollup_mirrors_alb_lane():
    evs = azure_logs.lb_5xx_rollups(
        [_appgw_access(502), _appgw_access(502), _appgw_access(200),
         _fd_access("504"), _fd_access("301")])
    assert {e["kind"] for e in evs} == {"cloud_lb_log"}
    assert len(evs) == 2                              # (AGW1,502) + (FD1,504)
    agw = [e for e in evs if "APPLICATIONGATEWAYS" in e["resource_id"]][0]
    assert agw["value"] == 2.0 and agw["metric_name"] == "lb_5xx"
    assert agw["severity"] == "high"
    assert agw["attrs"]["status_code"] == "502"
    assert agw["attrs"]["backend_status"] == "502"    # LB-vs-target blame split
    assert agw["attrs"]["provider"] == "azure"
    fd = [e for e in evs if "PROFILES/FD1" in e["resource_id"]][0]
    assert fd["attrs"]["domain"] == "x.azurefd.net"


# ── WAF lane ─────────────────────────────────────────────────────────────────

def _appgw_waf(action: str, rule: str = "942100") -> dict:
    return {
        "time": T, "category": "ApplicationGatewayFirewallLog",
        "resourceId": "/SUBSCRIPTIONS/S/.../APPLICATIONGATEWAYS/AGW1",
        "properties": {"action": action, "ruleId": rule, "requestUri": "/login",
                       "clientIp": "198.51.100.7", "hostname": "shop.example.com",
                       "policyId": "/subscriptions/s/rg/policies/waf-pol-1"},
    }


def _fd_waf(action: str) -> dict:
    return {
        "time": T, "category": "FrontDoorWebApplicationFirewallLog",
        "resourceId": "/SUBSCRIPTIONS/S/.../PROFILES/FD1",
        "properties": {"action": action, "ruleName": "RateLimitRule",
                       "policy": "fdwafpolicy", "requestUri": "https://x/api",
                       "clientIP": "198.51.100.8", "host": "x.azurefd.net"},
    }


def test_waf_block_rollup_per_policy_rule():
    evs = azure_logs.waf_block_rollups(
        [_appgw_waf("Blocked"), _appgw_waf("Blocked"), _appgw_waf("Detected"),
         _fd_waf("Block"), _fd_waf("Log")])
    assert len(evs) == 2                              # Detected/Log-mode excluded
    agw = [e for e in evs if "waf-pol-1" in e["resource_id"]][0]
    assert agw["kind"] == "cloud_waf_log"
    assert agw["value"] == 2.0
    assert agw["metric_name"] == "waf_blocked_requests"
    assert agw["attrs"]["rule"] == "942100"
    assert agw["attrs"]["action"] == "BLOCK"
    assert agw["attrs"]["sample_client"] == "198.51.100.7"
    fd = [e for e in evs if e["resource_id"] == "fdwafpolicy"][0]
    assert fd["attrs"]["rule"] == "RateLimitRule" and fd["value"] == 1.0


# ── DNS lane ─────────────────────────────────────────────────────────────────

def _dns(rcode: str, name: str = "db.internal.example.com.", pascal: bool = False) -> dict:
    key = (lambda s: s[:1].upper() + s[1:]) if pascal else (lambda s: s)
    return {
        "time": T, "category": "DnsResponse",
        "properties": {key("queryName"): name, key("responseCode"): rcode,
                       key("sourceIpAddress"): "10.0.0.6", key("queryType"): "A",
                       key("virtualNetworkId"): "/subs/s/vnets/vnet1"},
    }


def test_dns_error_rollup_entity_is_the_name():
    evs = azure_logs.dns_error_rollups(
        [_dns("NXDOMAIN"), _dns("NXDOMAIN", pascal=True), _dns("NOERROR")])
    assert len(evs) == 1                              # NOERROR = volume, ignored
    ev = evs[0]
    assert ev["kind"] == "cloud_dns_log"
    assert ev["resource_id"] == "db.internal.example.com"   # trailing dot stripped
    assert ev["value"] == 2.0                         # camelCase + PascalCase both parse
    assert ev["metric_name"] == "dns_resolution_failed"
    assert ev["attrs"]["rcode"] == "NXDOMAIN"
    assert ev["attrs"]["query_type"] == "A"
    assert ev["attrs"]["vnet"] == "/subs/s/vnets/vnet1"


# ── contract + URL encoding + gating ─────────────────────────────────────────

def test_all_emitted_kinds_are_in_the_correlation_contract():
    evs = (azure_logs.vnet_flow_rollups([_flow_record([DENY, BEGIN, END])])
           + azure_logs.lb_5xx_rollups([_appgw_access(502)])
           + azure_logs.waf_block_rollups([_appgw_waf("Blocked")])
           + azure_logs.dns_error_rollups([_dns("SERVFAIL")]))
    assert {e["kind"] for e in evs} <= CONTRACT_KINDS
    for e in evs:  # the wire fields cloud_signal_from_event requires
        assert e["resource_id"]
        assert e["severity"] in ("info", "warn", "high", "crit")
        assert isinstance(e["value"], float)
        assert e["attrs"]["provider"] == "azure"


def test_urls_percent_encode_every_parameter(monkeypatch):
    monkeypatch.setattr(azure_logs, "STORAGE_ACCOUNT", "acct1")
    lu = azure_logs.list_url("insights-logs-flownetworkflowevent", marker="a b/c=d")
    assert " " not in lu and "a+b%2Fc%3Dd" in lu
    bu = azure_logs.blob_url(
        "insights-logs-flownetworkflowevent",
        "flowLogResourceID=/SUBSCRIPTIONS/S 1/y=2026/m=07/PT1H.json")
    assert " " not in bu and "SUBSCRIPTIONS/S%201" in bu and "y%3D2026" in bu


def test_lanes_off_when_unconfigured(monkeypatch):
    monkeypatch.setattr(azure_logs, "STORAGE_ACCOUNT", "")
    assert not azure_logs.configured()
    assert azure_logs.lanes() == {}                   # nothing guessed, nothing faked


def test_fidelity_lanes_need_explicit_containers(monkeypatch):
    monkeypatch.setattr(azure_logs, "STORAGE_ACCOUNT", "acct1")
    monkeypatch.setattr(azure_logs, "LB_CONTAINERS", "")
    monkeypatch.setattr(azure_logs, "WAF_CONTAINERS", "insights-logs-applicationgatewayfirewalllog")
    monkeypatch.setattr(azure_logs, "DNS_CONTAINERS", "")
    got = azure_logs.lanes()
    # flow lane rides the account opt-in; only the explicitly named fidelity lane exists
    assert set(got) == {"vnet_flow", "waf"}
    assert got["waf"] == ["insights-logs-applicationgatewayfirewalllog"]


# ── run(): scheduling seam, lane isolation, offset state ─────────────────────

class _Producer:
    def __init__(self):
        self.sent: list[tuple[str, dict]] = []

    def send(self, topic, ev):
        self.sent.append((topic, ev))


def test_run_polls_lanes_and_stamps_tenant(monkeypatch):
    monkeypatch.setattr(azure_logs, "STORAGE_ACCOUNT", "acct1")
    monkeypatch.setattr(azure_logs, "LB_CONTAINERS", "insights-logs-applicationgatewayaccesslog")
    monkeypatch.setattr(azure_logs, "WAF_CONTAINERS", "")
    monkeypatch.setattr(azure_logs, "DNS_CONTAINERS", "")

    blobs = {
        "insights-logs-flownetworkflowevent": {"mac=AA/PT1H.json": _wrap([_flow_record([DENY])])},
        "insights-logs-applicationgatewayaccesslog": {"agw/PT1H.json": _wrap([_appgw_access(502)])},
    }

    def fake_list(tok, container, newer_than):
        return [{"name": n, "size": len(b), "modified": newer_than}
                for n, b in blobs.get(container, {}).items()]

    def fake_read(tok, container, name, offset):
        return blobs[container][name][offset:]

    monkeypatch.setattr(azure_logs, "list_blobs", fake_list)
    monkeypatch.setattr(azure_logs, "read_range", fake_read)

    st: dict = {}
    prod = _Producer()
    counts = azure_logs.run("tok", prod, "t_lab", st)
    assert counts["vnet_flow"] == 1 and counts["lb"] == 1
    assert all(topic == "netops.cloud" for topic, _ in prod.sent)
    assert all(ev["tenant_id"] == "t_lab" for _, ev in prod.sent)

    # offsets checkpointed → a second run over unchanged blobs emits NOTHING
    prod2 = _Producer()
    counts2 = azure_logs.run("tok", prod2, "t_lab", st)
    assert prod2.sent == [] and counts2["vnet_flow"] == 0


def test_run_one_bad_container_never_kills_the_cycle(monkeypatch):
    monkeypatch.setattr(azure_logs, "STORAGE_ACCOUNT", "acct1")
    monkeypatch.setattr(azure_logs, "LB_CONTAINERS", "insights-logs-applicationgatewayaccesslog")
    monkeypatch.setattr(azure_logs, "WAF_CONTAINERS", "")
    monkeypatch.setattr(azure_logs, "DNS_CONTAINERS", "")

    def fake_list(tok, container, newer_than):
        if container == "insights-logs-flownetworkflowevent":
            raise RuntimeError("boom: storage 500")
        return [{"name": "agw/PT1H.json", "size": 10_000, "modified": newer_than}]

    def fake_read(tok, container, name, offset):
        return _wrap([_appgw_access(503)])[offset:]

    monkeypatch.setattr(azure_logs, "list_blobs", fake_list)
    monkeypatch.setattr(azure_logs, "read_range", fake_read)

    prod = _Producer()
    counts = azure_logs.run("tok", prod, "t_lab", {})
    assert counts["errors"] == 1
    assert counts["lb"] == 1                          # the healthy lane still fed


def test_offset_state_prunes_blobs_outside_lookback(monkeypatch):
    monkeypatch.setattr(azure_logs, "list_blobs",
                        lambda tok, c, newer: [])     # old blobs no longer listed
    offsets = {"stale/PT1H.json": 123}
    recs = azure_logs.poll_container("tok", "c", offsets)
    assert recs == [] and offsets == {}               # bounded state, pruned
