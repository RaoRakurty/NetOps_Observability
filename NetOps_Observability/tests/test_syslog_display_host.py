# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A syslog title names the device by its hostname, never its address.

Owner rule 2026-11-23: show hostnames, never addresses or internal ids, as a
device's name. An rfc3164 IOS sender writes no hostname, so syslog-ng's host is the
source address and every pack title read "… on 192.168.222.107 …" although the
registry knew the device (lab, 2026-11-25). The registry row now carries the
device's display name (`name`, telemetry_enrichment.go); the aggregator stamps it as
`device_name` and the title's `%host` uses it — only for a frame whose host IS its
source address. The engine's executor (syslog_packs.display_host) and the generated
VRL (cx_pk_dname) must agree; the shipped transform is exercised by the
inventory-vendor.yaml cases (tests/test_inventory_vendor.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "correlation"))

import syslog_packs  # noqa: E402

AGG = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
HELM = ROOT / "deployment" / "helm" / "correlix" / "files" / "vector" / "vector.yaml"


def test_a_frame_with_no_hostname_is_named_by_the_inventory():
    ev = {"hostname": "192.168.222.107", "source_ip": "192.168.222.107", "device_name": "cEDGE-40"}
    assert syslog_packs.display_host(ev, ev["hostname"]) == "cEDGE-40"


def test_a_hostname_the_device_sent_is_never_replaced():
    ev = {"hostname": "cisco-edge1", "source_ip": "10.1.1.1", "device_name": "Edge-One-Inventory"}
    assert syslog_packs.display_host(ev, ev["hostname"]) == "cisco-edge1"


def test_an_unknown_sender_keeps_its_address():
    ev = {"hostname": "192.168.250.250", "source_ip": "192.168.250.250"}
    assert syslog_packs.display_host(ev, ev["hostname"]) == "192.168.250.250"


def test_no_source_address_means_no_substitution():
    # A record without source_ip cannot prove its host is an address: no guess.
    ev = {"hostname": "192.168.222.107", "device_name": "cEDGE-40"}
    assert syslog_packs.display_host(ev, ev["hostname"]) == "192.168.222.107"


def test_the_generated_vrl_applies_the_same_rule_in_both_configs():
    rule = 'if cx_pk_dname != "" && cx_pk_host == (string(.source_ip) ?? "") { cx_pk_host = cx_pk_dname }'
    for cfg in (AGG, HELM):
        text = cfg.read_text(encoding="utf-8")
        assert 'cx_pk_dname = string(cx_inv.name) ?? ""' in text, cfg
        assert rule in text, cfg
        # %device and the registry key stay on the raw host: the device fallback is
        # computed BEFORE the display substitution.
        assert text.index("if cx_pk_device == \"\" { cx_pk_device = cx_pk_host }") < text.index(rule), cfg


def test_the_display_name_never_becomes_the_registry_key():
    # .hostname is what the engine re-derives the tenant from (verified_tenant); the
    # display name is a separate field and the lane never assigns it to .hostname.
    text = AGG.read_text(encoding="utf-8")
    start = text.index("  syslog_normalized:")
    end = text.index("\n  snmptrap_normalized:", start) if "\n  snmptrap_normalized:" in text else len(text)
    lane = text[start:end]
    assert ".device_name = cx_inv_v" in lane
    assert ".hostname = cx_inv" not in lane and ".hostname = cx_pk_dname" not in lane
