# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""goflow2 field mapping — exporter application identity (IE 95/96).

Pins the rules proven against the pinned goflow2 v2.2.1 image on 2026-10-11:
  * every deployment path passes the SAME `-mapping` file, mounted as a
    directory (F-51);
  * `fields` is the full v2.2.1 built-in list in struct order plus the two
    custom fields — a shorter list silently drops fields;
  * no `render:` entry: goflow2's string renderer splices raw exporter bytes
    into the JSON unescaped (field injection); hex is immune.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAPPING = ROOT / "deployment/docker/goflow2/mapping.yaml"
STAGED = ROOT / "deployment/helm/correlix/files/goflow2/mapping.yaml"
COMPOSE = ROOT / "deployment/docker/docker-compose.yml"
TLS = ROOT / "deployment/docker/compose.tls.yml"
HELM_PIPELINE = ROOT / "deployment/helm/correlix/templates/pipeline.yaml"

PINNED_IMAGE = "netsampler/goflow2:v2.2.1@sha256:bc7aafd6d724cd0a21b17b3c67f22d514c431021c3531914d964bef8cdd79dbb"
# goflow2 v2.2.1 built-in fields in struct order (producer/proto, tag v2.2.1).
BUILTIN_V221 = [
    "type", "time_received_ns", "sequence_num", "sampling_rate", "sampler_address",
    "time_flow_start_ns", "time_flow_end_ns", "bytes", "packets", "src_addr", "dst_addr",
    "etype", "proto", "src_port", "dst_port", "in_if", "out_if", "src_mac", "dst_mac",
    "src_vlan", "dst_vlan", "vlan_id", "ip_tos", "forwarding_status", "ip_ttl", "ip_flags",
    "tcp_flags", "icmp_type", "icmp_code", "ipv6_flow_label", "fragment_id",
    "fragment_offset", "src_as", "dst_as", "next_hop", "next_hop_as", "src_net", "dst_net",
    "bgp_next_hop", "bgp_communities", "as_path", "mpls_ttl", "mpls_label", "mpls_ip",
    "observation_domain_id", "observation_point_id", "layer_stack", "layer_size",
    "ipv6_routing_header_addresses", "ipv6_routing_header_seg_left",
]
CUSTOM = ["application_id", "application_name"]


def _mapping():
    return yaml.safe_load(MAPPING.read_text())


def _goflow2_block(compose_path):
    """The goflow2 service block as text (the compose files use custom YAML
    tags that safe_load refuses, so this reads the block, not the document)."""
    text = compose_path.read_text()
    start = text.index("\n  goflow2:\n")
    nxt = re.search(r"\n  [a-z0-9-]+:\n", text[start + 1:])
    return text[start: start + 1 + (nxt.start() if nxt else len(text))]


def _image():
    m = re.search(r"^\s+image:\s*(\S+)", _goflow2_block(COMPOSE), re.M)
    return m.group(1)


def test_fields_are_the_full_builtin_list_plus_the_custom_ones():
    m = _mapping()
    assert len(BUILTIN_V221) == 50
    assert m["formatter"]["fields"] == BUILTIN_V221 + CUSTOM


def test_image_is_still_the_version_the_list_was_proven_on():
    assert _image() == PINNED_IMAGE, (
        "goflow2 image changed — re-prove the mapping field list and the hex "
        "encoding on the new version, then update BUILTIN_V221 and PINNED_IMAGE"
    )


def test_ie95_and_ie96_map_to_bytes_fields_on_both_protocols():
    m = _mapping()
    proto = {p["name"]: p for p in m["formatter"]["protobuf"]}
    for name in CUSTOM:
        assert proto[name]["type"] == "bytes"
    for section in ("ipfix", "netflowv9"):
        got = {e["field"]: e["destination"] for e in m[section]["mapping"]}
        assert got == {95: "application_id", 96: "application_name"}


def test_nothing_is_rendered_as_a_raw_string():
    m = _mapping()
    assert "render" not in m["formatter"], (
        "a render entry would splice exporter bytes into the JSON unescaped "
        "(proven: an IE 96 value injected a tenant_id key) — keep them hex"
    )
    assert "string" not in MAPPING.read_text().split("formatter:")[1].split("ipfix:")[0].replace(
        "type: bytes", ""
    )


def test_every_deployment_path_passes_the_same_mapping_file():
    for path in (COMPOSE, TLS):
        block = _goflow2_block(path)
        assert '- "-mapping"\n      - "/etc/goflow2/mapping.yaml"' in block, path
    assert "- ./goflow2:/etc/goflow2:ro" in _goflow2_block(COMPOSE), "mount the DIRECTORY (F-51)"
    helm = HELM_PIPELINE.read_text()
    assert "- -mapping\n            - /etc/goflow2/mapping.yaml" in helm
    assert "mountPath: /etc/goflow2" in helm and "correlix-goflow2" in helm


def test_helm_copy_is_identical():
    assert STAGED.read_text() == MAPPING.read_text()
