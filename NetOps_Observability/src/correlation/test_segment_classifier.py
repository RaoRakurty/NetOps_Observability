"""Contract tests for segment_classifier (path-causality RCA P0).

One test per pattern (research Area 2 signal list), plus the two honesty invariants:
`unknown` + reason when nothing matches, and "a single weak signal never yields a confident
classification." Offline: uses ONLY the bundled snapshot, no network.
"""

from segment_classifier import (
    Confidence, DeviceRole, SegmentClassifier, SegmentType, classify_hop,
)

C = SegmentClassifier()


def _c(**hop) -> dict:
    return C.classify(hop).to_dict()


# ── provider-CIDR feed → cloud + provider (Signal 2.1) ───────────────────────

def test_aws_cidr_is_cloud_aws():
    r = _c(ip="52.216.100.5")  # inside 52.216.0.0/15 (AWS S3, us-east-1)
    assert r["segment_type"] == SegmentType.CLOUD.value
    assert r["provider"] == "aws"
    assert r["confidence"] == Confidence.STRONG.value
    assert r["boundary"] == "CLOUD"
    assert any(s["signal"] == "provider_cidr" for s in r["signals"])


def test_azure_cidr_is_cloud_azure():
    r = _c(ip="40.65.0.10")  # inside 40.64.0.0/10 (AzureCloud)
    assert r["segment_type"] == SegmentType.CLOUD.value
    assert r["provider"] == "azure"
    assert r["confidence"] == Confidence.STRONG.value


def test_gcp_cidr_is_cloud_gcp():
    r = _c(ip="35.190.10.10")  # inside 35.184.0.0/13 (Google Cloud, us-central1)
    assert r["segment_type"] == SegmentType.CLOUD.value
    assert r["provider"] == "gcp"
    assert r["confidence"] == Confidence.STRONG.value


def test_gcp_ipv6_cidr_is_cloud():
    r = _c(ip="2600:1900:4000::1")  # inside 2600:1900::/28 (GCP)
    assert r["segment_type"] == SegmentType.CLOUD.value
    assert r["provider"] == "gcp"


def test_longest_prefix_match_wins():
    # 52.216.0.0/15 (S3) is more specific than the surrounding /12-ish AMAZON blocks; the
    # trie must return the most specific service.
    r = _c(ip="52.216.0.1")
    assert r["service"] == "S3"


# ── RFC1918 → lan/dc (Signal 2.3) ────────────────────────────────────────────

def test_rfc1918_is_private_lan():
    r = _c(ip="10.20.30.40")
    assert r["segment_type"] in (SegmentType.LAN.value, SegmentType.DC.value)
    # ambiguous alone → not strong
    assert r["confidence"] == Confidence.MEDIUM.value
    assert any(s["signal"] == "rfc1918_private" for s in r["signals"])


def test_rfc1918_plus_fabric_role_becomes_dc_strong():
    # private space + a declared DC-fabric role = two independent signals → confident DC.
    r = _c(ip="10.20.30.40", device_role_hint="dc-spine-01")
    assert r["segment_type"] == SegmentType.DC.value
    assert r["device_role"] == DeviceRole.SWITCH.value
    assert r["confidence"] == Confidence.STRONG.value


# ── RFC6598 CGNAT → wan (Signal 2.3) ─────────────────────────────────────────

def test_cgnat_is_wan():
    r = _c(ip="100.64.12.9")
    assert r["segment_type"] == SegmentType.WAN.value
    assert r["confidence"] == Confidence.STRONG.value
    assert any(s["signal"] == "rfc6598_cgnat" for s in r["signals"])


# ── transit ASN → wan (Signal 2.2) ───────────────────────────────────────────

def test_transit_asn_is_wan():
    # A public IP with no provider-CIDR hit, but a curated transit ASN. Address-space says
    # "internet", transit ASN says "wan" — independent signals; transit is the stronger of
    # the equal-tier votes and address-space corroborates a public/transit path.
    r = _c(ip="154.54.1.1", asn=174)  # AS174 Cogent (transit)
    assert r["segment_type"] == SegmentType.WAN.value
    assert any(s["signal"] == "asn_transit" for s in r["signals"])


def test_cloud_asn_corroborates_cloud():
    r = _c(ip="52.216.100.5", asn=16509)  # AWS CIDR + AWS ASN
    assert r["segment_type"] == SegmentType.CLOUD.value
    assert r["confidence"] == Confidence.STRONG.value


# ── device-role hints → the right role (Signal 2.6) ──────────────────────────

def test_load_balancer_role():
    r = _c(ip="52.216.100.5", device_role_hint="prod application load balancer")
    assert r["device_role"] == DeviceRole.LOAD_BALANCER.value


def test_waf_role():
    r = _c(ip="52.216.100.5", device_role_hint="azure app gateway WAF")
    assert r["device_role"] == DeviceRole.WAF.value


def test_firewall_role():
    r = _c(ip="10.0.0.1", device_role_hint="edge-fw fortigate")
    assert r["device_role"] == DeviceRole.FIREWALL.value


def test_tunnel_gw_role_marks_wan_seam():
    r = _c(ip="10.0.0.1", device_role_hint="ipsec vpn gateway")
    assert r["device_role"] == DeviceRole.TUNNEL_GW.value
    assert r["segment_type"] == SegmentType.WAN_SEAM.value
    assert r["seam_kind"] == "VPN"


def test_dx_role_marks_wan_seam_dx():
    r = _c(ip="10.0.0.1", device_role_hint="AWS Direct Connect gateway")
    assert r["seam_kind"] == "DX"
    assert r["segment_type"] == SegmentType.WAN_SEAM.value


# ── unknown + reason when nothing matches ────────────────────────────────────

def test_unknown_when_nothing_matches():
    # A non-topological address supplies no usable segment signal.
    r = _c(ip="127.0.0.1")
    assert r["segment_type"] == SegmentType.UNKNOWN.value
    assert r["confidence"] == Confidence.NONE.value
    assert r["reason"]  # human-readable, non-empty


def test_unknown_on_unparseable_ip():
    r = _c(ip="not-an-ip")
    assert r["segment_type"] == SegmentType.UNKNOWN.value
    assert "unparseable" in r["reason"]


def test_unknown_on_missing_ip():
    r = _c(rdns="whatever.example.com")
    assert r["segment_type"] == SegmentType.UNKNOWN.value
    assert r["reason"]


# ── the honesty rule: a single weak signal never yields confident ────────────

def test_single_weak_rdns_never_confident():
    # rDNS alone LOOKS like AWS, but rDNS is a weak/spoofable hint. It may produce a
    # low-confidence label, but NEVER strong/medium.
    r = _c(ip="203.0.113.7", rdns="ec2-203-0-113-7.compute.amazonaws.com")
    assert r["confidence"] not in (Confidence.STRONG.value, Confidence.MEDIUM.value)
    assert r["confidence"] in (Confidence.WEAK.value, Confidence.NONE.value)


def test_single_weak_ttl_never_confident():
    r = _c(ip="203.0.113.7", ttl=52, latency=80.0)
    assert r["confidence"] not in (Confidence.STRONG.value, Confidence.MEDIUM.value)


def test_weak_role_hint_without_segment_stays_unknown_segment():
    # A weak rDNS role hint identifies a role but must not manufacture a confident segment.
    r = _c(ip="203.0.113.7", rdns="lb01.example.net")
    assert r["device_role"] == DeviceRole.LOAD_BALANCER.value
    assert r["confidence"] not in (Confidence.STRONG.value, Confidence.MEDIUM.value)


# ── malformed / untrusted feed data must not crash (CLAUDE.md §8) ─────────────

def test_malformed_feed_entries_are_skipped_not_fatal(tmp_path):
    import json as _json

    from segment_classifier import ProviderTrie

    snap = tmp_path / "bad.json"
    snap.write_text(_json.dumps({
        "prefixes": [
            {"prefix": "not-a-cidr", "provider": "aws"},   # malformed → skipped
            "a-bare-string",                                 # not an object → skipped
            {"prefix": "198.51.100.0/24", "provider": "aws", "region": "us-east-1"},  # good
        ]
    }))
    trie = ProviderTrie.from_snapshot(str(snap))
    assert trie.count == 1  # only the valid prefix loaded
    c = SegmentClassifier(trie=trie)
    r = c.classify({"ip": "198.51.100.5"}).to_dict()
    assert r["segment_type"] == SegmentType.CLOUD.value


def test_missing_snapshot_is_not_fatal(tmp_path):
    from segment_classifier import ProviderTrie
    trie = ProviderTrie.from_snapshot(str(tmp_path / "nope.json"))
    assert trie.count == 0
    # classifier still runs (CIDR-blind), private space still classifies.
    r = SegmentClassifier(trie=trie).classify({"ip": "10.1.1.1"}).to_dict()
    assert r["segment_type"] == SegmentType.LAN.value


# ── module-level convenience ─────────────────────────────────────────────────

def test_classify_hop_convenience():
    r = classify_hop({"ip": "52.216.100.5"})
    assert r["segment_type"] == SegmentType.CLOUD.value
