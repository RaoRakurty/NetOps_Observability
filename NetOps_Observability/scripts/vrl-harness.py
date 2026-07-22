#!/usr/bin/env python3
"""vrl-harness.py — replay fixture events through the REAL Vector transforms.

Why this exists
---------------
Every ingest defect in the 2026-07-21 audit lived in VRL: the DEF-6 `ts`
mapping loss (F-01/F-09), the four lanes that never learned normalisation
(F-02), the dead-letter record that captured no reason (F-14), the merge that
grows the mapping without bound (F-05). None of it was caught, because `vector
validate` only proves a config COMPILES — it never runs a single event through
it. The failure path of the whole ingest tier was untested by construction.

This harness closes that: it lifts a transform's `source:` verbatim out of
deployment/docker/*/vector.yaml (never a copy — a copy would drift away from
the thing it claims to test), wraps it in a throwaway pipeline, feeds fixture
events through the pinned Vector image, and returns the emitted events for
assertion.

It is deliberately dependency-free (stdlib + the yaml already used by
tests/) and SKIPS rather than fails when Docker or the image is unavailable,
so it can sit inside a normal pytest run.

Usage:
    python3 scripts/vrl-harness.py            # self-check: runs the built-in cases
    from vrl_harness import run_transform     # from a test
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Pinned to the image the stack actually runs (docker-compose.yml). A harness
# that tests a different Vector than production is testing nothing.
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"

CONFIGS = {
    "aggregator": os.path.join(ROOT, "deployment", "docker", "vector", "vector.yaml"),
    "router": os.path.join(ROOT, "deployment", "docker", "vector-router", "vector.yaml"),
}


class HarnessUnavailable(RuntimeError):
    """Docker or the pinned Vector image is not usable here."""


def available() -> bool:
    """True when the harness can actually run (docker present + image local).

    The image is never pulled: a test must not depend on network access, and a
    silent pull would make the first run take minutes.
    """
    if not shutil.which("docker"):
        return False
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", VECTOR_IMAGE],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


def transform_source(tier: str, name: str) -> str:
    """The verbatim `source:` VRL of one transform in the real config."""
    with open(CONFIGS[tier]) as fh:
        cfg = yaml.safe_load(fh)
    tr = cfg["transforms"].get(name)
    if tr is None:
        raise KeyError(f"{tier}: no transform named {name!r}")
    src = tr.get("source")
    if src is None:
        raise KeyError(f"{tier}: transform {name!r} has no `source:` (type={tr.get('type')})")
    return src


def run_vrl(source: str, events: list[dict], *, drop: bool = False,
            timeout: int = 60) -> list[dict]:
    """Run `source` over `events`, returning the emitted events.

    drop=True mirrors a transform configured with drop_on_error/drop_on_abort
    + reroute_dropped: the returned events are the DROPPED ones, each carrying
    Vector's own `.metadata.dropped` annotation. That is the only way to test a
    dead-letter path for real — the reason field is written by Vector, not by
    us, so asserting on a hand-built fixture would prove nothing.
    """
    if not available():
        raise HarnessUnavailable(f"docker or {VECTOR_IMAGE} unavailable")

    stage = tempfile.mkdtemp(prefix="vrl-harness-")
    try:
        under_test = {
            "type": "remap",
            "inputs": ["in"],
            "source": source,
        }
        if drop:
            under_test.update(drop_on_abort=True, drop_on_error=True, reroute_dropped=True)

        cfg = {
            # `stdin` (not `file`): it shuts the topology down at EOF, so the
            # run is bounded by the input rather than by a timeout — a harness
            # that always hits its timeout is a harness nobody will run.
            "sources": {
                "in": {
                    "type": "stdin",
                    "decoding": {"codec": "json"},
                    "framing": {"method": "newline_delimited"},
                }
            },
            "transforms": {"under_test": under_test},
            "sinks": {
                "out": {
                    "type": "file",
                    "inputs": ["under_test.dropped" if drop else "under_test"],
                    "path": "/harness/output.json",
                    "encoding": {"codec": "json"},
                }
            },
        }
        with open(os.path.join(stage, "vector.yaml"), "w") as fh:
            yaml.safe_dump(cfg, fh)

        stdin = "".join(json.dumps(ev) + "\n" for ev in events)
        subprocess.run(
            ["docker", "run", "--rm", "-i", "--network", "none",
             "-v", f"{stage}:/harness",
             "-e", "VECTOR_LOG=error",
             VECTOR_IMAGE, "--config", "/harness/vector.yaml"],
            input=stdin.encode(), capture_output=True, timeout=timeout, check=False,
        )

        out_path = os.path.join(stage, "output.json")
        if not os.path.exists(out_path):
            return []
        with open(out_path) as fh:
            return [json.loads(line) for line in fh if line.strip()]
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def run_transform(tier: str, name: str, events: list[dict], **kw) -> list[dict]:
    """Convenience: look the transform up in the real config and run it."""
    return run_vrl(transform_source(tier, name), events, **kw)


def _selfcheck() -> int:
    if not available():
        print(f"SKIP: docker or {VECTOR_IMAGE} unavailable")
        return 0
    failures = 0

    def check(label: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        print(("  ok   " if cond else "  FAIL ") + label + (f"  {detail}" if detail and not cond else ""))
        if not cond:
            failures += 1

    print("router.applogs_tagged — F-01/F-10 timestamp contract")
    # NOTE: every real source on this tier (kafka) stamps `.timestamp`, and so
    # does the harness's stdin source, so the F-10 derivation always has
    # something to work from. The fixtures below therefore pin the PRECEDENCE:
    # a producer-sent `ts` always wins; `timestamp` is only ever a fallback.
    out = run_transform("router", "applogs_tagged", [
        {"ts": 1784658034.77, "tenant_id": ""},                    # float epoch seconds
        {"ts": "2026-07-21T10:00:00Z", "tenant_id": "Acme Corp"},  # rfc3339
        {"ts": "not-a-time", "tenant_id": ""},                     # unparseable
        {"timestamp": "2026-07-21T10:00:00Z", "tenant_id": ""},    # ts absent (F-10)
    ])
    check("float epoch-seconds -> epoch-ms int", out[0].get("ts") == 1784658034770, str(out[0]))
    check("producer ts wins over source timestamp", out[1].get("ts") == 1784628000000
          and "ts_source" not in out[1], str(out[1]))
    check("bad ts preserved as evidence, event not dropped",
          out[2].get("ts_invalid") == "not-a-time", str(out[2]))
    check("bad ts falls back to timestamp, labelled derived",
          out[2].get("ts_source") == "timestamp", str(out[2]))
    check("F-10 ts derived from timestamp", out[3].get("ts") == 1784628000000
          and out[3].get("ts_source") == "timestamp", str(out[3]))
    check("F-11 unmatched tenant is stamped", out[0].get("tenant_attribution") == "unmatched", str(out[0]))
    check("F-11 matched tenant is stamped", out[1].get("tenant_attribution") == "enriched", str(out[1]))
    check("tenant segment is index-safe", out[1].get("tenant_seg") == "acme-corp", str(out[1]))

    print("aggregator.applogs_normalized — F-05 declared-field type poisoning")
    out = run_transform("aggregator", "applogs_normalized", [
        {"message": json.dumps({"level": ["a"], "msg": {"nested": 1}, "widget": {"k": "v"}}),
         "container_name": "api", "label": {"com.docker.compose.service": "api"}},
    ])
    ev = out[0] if out else {}
    check("transform emitted an event", bool(out), str(out))
    check("object on a declared text field is stringified", isinstance(ev.get("msg"), str), str(ev))
    check("array on a declared keyword field is stringified", isinstance(ev.get("level"), str), str(ev))
    check("undeclared producer keys survive in _source", ev.get("widget") is not None, str(ev))
    check("docker label map dropped", "label" not in ev, str(ev))

    print("router.deadletter_encoded — F-14 the reason is actually captured")
    dropped = run_transform("router", "cloudcosts_normalized",
                            [{"kind": "not_a_cost"}], drop=True)
    check("abort reroutes to .dropped", len(dropped) == 1, str(dropped))
    if dropped:
        enc = run_transform("router", "deadletter_encoded", dropped)
        check("reason recorded (was '' before F-14)", enc[0].get("reason") == "abort", str(enc[0]))
        check("detail recorded", "abort" in (enc[0].get("detail") or "").lower(), str(enc[0]))
        # The harness names the transform under test `under_test`, so this
        # asserts the MECHANISM (lane comes from Vector's own component_id)
        # rather than a hardcoded lane name — which is the point of F-14's fix:
        # the old encoder had "cloudcosts" baked in as a literal.
        check("lane derived from component_id, not a literal",
              enc[0].get("lane") == "under_test", str(enc[0]))
        check("raw payload retained", "not_a_cost" in (enc[0].get("raw") or ""), str(enc[0]))

    print(f"\n{'FAILED' if failures else 'PASSED'} ({failures} failure(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selfcheck())
