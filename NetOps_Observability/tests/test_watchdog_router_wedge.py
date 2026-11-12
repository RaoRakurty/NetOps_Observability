# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Watchdog layer for tracker 353 — a router lane JOINED but NOT CONSUMING.

2026-10-17 (and again 2026-10-30): after an OpenSearch flood-stage event a
vector-router member stayed joined and heartbeating while it read nothing —
Vector 0.40's kafka source loses its per-partition consumer task across a
rebalance (upstream vectordotdev/vector#22006, open). The watchdog's router
probe asked only "does every lane have a member?", which was TRUE throughout.

What these tests pin:
  * the watchdog and the in-stack page rule RouterConsumerWedged ask the SAME
    question — the URL-encoded constant decodes to the readable comment above
    it, and that equals the vmalert expression minus its one-page-per-fault
    `unless` (which only the paging layer needs);
  * the parser names every wedged partition whatever the label order;
  * the block reports a wedge as the critical ENGINE_NOT_CONSUMING class, stays
    quiet on an empty result, and reports a failed query as SKIPPED with its
    reason — never as a quiet stack (§16.1).
These run the SHIPPED block, extracted from the script, with docker stubbed.
"""

from __future__ import annotations

import re
import subprocess
import urllib.parse
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT / "scripts" / "stack-watchdog.sh"
SCALE_RULES = ROOT / "src" / "config" / "rules-scale-slo.yaml"


def _src() -> str:
    return WATCHDOG.read_text(encoding="utf-8")


def _norm(q: str) -> str:
    return re.sub(r"\s+", " ", q).strip()


def _constant_and_comment() -> tuple[str, str]:
    m = re.search(r"^\s*# (max by \(consumergroup, topic, partition\).*)\n"
                  r"\s*eng_wedged_q='([^']+)'", _src(), re.M)
    assert m, "eng_wedged_q (with its readable comment directly above) not found"
    return m.group(2), m.group(1)


def test_the_encoded_query_is_the_readable_one() -> None:
    encoded, readable = _constant_and_comment()
    assert urllib.parse.unquote(encoded) == readable, (
        "the pre-encoded query and its readable comment have drifted — the "
        "comment is what a reviewer reads, the constant is what runs")


def test_the_watchdog_asks_what_the_page_rule_asks() -> None:
    _, readable = _constant_and_comment()
    rules = yaml.safe_load(SCALE_RULES.read_text(encoding="utf-8"))
    expr = next(r["expr"] for g in rules["groups"] for r in g["rules"]
                if r.get("alert") == "RouterConsumerWedged")
    core = _norm(expr.split("unless on (consumergroup)")[0])
    assert _norm(readable) == core, (
        "the watchdog's wedge query no longer matches RouterConsumerWedged — "
        "two layers that are meant to be independent copies of one check now "
        f"check different things.\n watchdog: {_norm(readable)}\n rule:     {core}")


def _fn() -> str:
    src = _src()
    return src[src.index("eng_wedged_lanes() {"):src.index('if [ "${ENGINE_CONSUMER_CHECK:-1}" = "1" ]; then\n  if [ -z "$eng_cid" ]')]


def test_the_parser_names_every_wedged_partition_in_any_label_order() -> None:
    body = ('{"status":"success","data":{"resultType":"vector","result":['
            '{"metric":{"consumergroup":"netops-router-applogs","partition":"0",'
            '"topic":"netops.applogs"},"value":[1,"22643"]},'
            '{"metric":{"topic":"netops.snmptrap","partition":"3",'
            '"consumergroup":"netops-router-snmptrap"},"value":[1,"12"]}]}}')
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + _fn() + "\neng_wedged_lanes\n"],
                       input=body, capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ("netops-router-applogs/netops.applogs[0] "
                        "netops-router-snmptrap/netops.snmptrap[3] "), r.stdout


def _block() -> str:
    src = _src()
    start = src.index("eng_wedged_lanes() {")
    end = src.index("# -- 3. Alert-delivery heartbeat", start)
    # Close the two `if`s the cut leaves open (the ENGINE_CONSUMER_CHECK gate
    # and the eng_cid branch); the heartbeat half is out of scope here.
    return src[start:end] + "\n  fi\nfi\n"


def _run(tmp_path: Path, wedged_body: str, wedged_rc: int = 0) -> list[str]:
    stub = (
        "set -uo pipefail\n"
        "problems=()\neng_cid=victoria\nPROJECT=netops\n"
        "logerr() { printf 'LOG %s\\n' \"$*\" >&2; }\n"
        # One correlation member, no lag: the membership half is healthy.
        'eng_query() { eng_err=""; eng_val=1; return 0; }\n'
        "dkr() {\n"
        '  case "$*" in\n'
        '    *"kafka_consumergroup_members%7Bconsumergroup%3D~%22netops-router-.%2A%22%7D%20%3D%3D%200"*)\n'
        "      printf '{\"status\":\"success\",\"data\":{\"result\":[]}}' ;;\n"
        '    *"delta%28kafka_topic_partition_current_offset"*)\n'
        '      printf "%s" "$WEDGED_BODY"; return "$WEDGED_RC" ;;\n'
        "    *) return 0 ;;\n"
        "  esac\n"
        "}\n")
    script = stub + _block() + '\nprintf "%s\\n" "${problems[@]}"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       check=False,
                       env={"PATH": "/usr/bin:/bin", "WEDGED_BODY": wedged_body,
                            "WEDGED_RC": str(wedged_rc)})
    assert r.returncode == 0, r.stderr
    return [ln for ln in r.stdout.splitlines() if ln]


WEDGED = ('{"status":"success","data":{"resultType":"vector","result":['
          '{"metric":{"consumergroup":"netops-router-applogs","partition":"0",'
          '"topic":"netops.applogs"},"value":[1,"22643"]}]}}')


def test_a_wedged_lane_is_the_critical_class_and_named(tmp_path) -> None:
    probs = _run(tmp_path, WEDGED)
    assert len(probs) == 1, probs
    p = probs[0]
    assert p.startswith("ENGINE_NOT_CONSUMING: router lane(s) JOINED but NOT CONSUMING"), p
    assert "netops-router-applogs/netops.applogs[0]" in p
    assert "storage block" in p and "cx-lane-watch" in p
    src = _src()
    crit = src[src.index("problem_is_critical() {"):]
    assert "*ENGINE_NOT_CONSUMING*" in crit[:800], "the class must stay critical"


def test_no_wedge_is_quiet(tmp_path) -> None:
    assert _run(tmp_path, '{"status":"success","data":{"result":[]}}') == []


def test_a_failed_query_is_skipped_with_its_reason_never_quiet(tmp_path) -> None:
    probs = _run(tmp_path, "wget: download timed out", wedged_rc=1)
    assert len(probs) == 1 and "SKIPPED" in probs[0], probs
    assert "download timed out" in probs[0], (
        "the reason must be carried into the problem text, not erased")
