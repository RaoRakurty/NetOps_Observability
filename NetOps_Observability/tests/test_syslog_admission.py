# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A4 Phase 1 — the syslog admission split (aggregator-side screen).

WHAT IS BEING PINNED. `src/correlation/producers.syslog_promotable` decides
whether a raw syslog line can ever become correlation evidence. On storm-s11 it
admitted 54,767 of 900,001 lines — the engine paid a full decode + dispatch to
prove the other 845,234 uninteresting. A4 moves that screen one hop upstream,
into the vector-aggregator, and publishes the admitted subset onto a SECOND
topic (`netops.syslog.control`) that nothing consumes yet.

The whole build rests on one claim: **the VRL in the aggregator and the Python
in the engine admit exactly the same lines.** These tests are what makes that
claim checkable rather than asserted:

  * the VRL is GENERATED from the Python and re-generation is byte-stable
    (`--check` drift gate), so the two cannot diverge by editing;
  * `rules_hash` moves when the screen's DECISION could move, so a stale
    artifact is identifiable on the wire and not merely in git;
  * `vector test` runs the real generated program against a corpus whose
    expected verdicts were computed by calling `syslog_promotable` itself —
    the golden equality, proven case by case in the actual runtime;
  * the topology is a SUPERSET/subset pair (nothing is re-routed away from
    netops.syslog), the topic is pre-created co-partitioned, and the router is
    not granted it;
  * the scale harness's default leg is byte-identical — the mirror is opt-in.

Run:  python3 -m pytest tests/test_syslog_admission.py -v
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
VECTOR_DIR = ROOT / "deployment" / "docker" / "vector"
VRL_PATH = VECTOR_DIR / "generated" / "syslog-admission.vrl"
TESTS_YAML = VECTOR_DIR / "tests" / "syslog-admission.yaml"
CONFIG_PATH = VECTOR_DIR / "vector.yaml"
GENERATOR = ROOT / "scripts" / "gen-syslog-admission.py"

CONTROL_TOPIC = "netops.syslog.control"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"   # in sync with docker-compose.yml


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gen = _load(GENERATOR, "gen_syslog_admission")
producers = gen.load_producers()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── 1. the generator is the only author (drift) ──────────────────────────────

def test_checked_in_artifacts_are_not_stale():
    """`--check` re-renders the .vrl, the vector test suite AND the spliced
    block in vector.yaml, and fails on any difference. This is the gate that
    makes "the VRL is the Python" true after a rule change rather than at the
    moment someone last remembered to re-run the generator."""
    proc = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, (
        "generated syslog-admission artifacts are STALE — re-run "
        f"`python3 scripts/gen-syslog-admission.py`\n{proc.stdout}{proc.stderr}")


def test_check_mode_detects_a_hand_edit(tmp_path):
    """The drift gate has to actually fail on drift — a --check that always
    passes is worse than no --check (it certifies the drift)."""
    original = _read(VRL_PATH)
    backup = tmp_path / "syslog-admission.vrl"
    backup.write_text(original, encoding="utf-8")
    try:
        VRL_PATH.write_text(original.replace('"by": "marker"',
                                             '"by": "hand-edited"'),
                            encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 1, "a hand edit must fail --check"
        assert "syslog-admission.vrl" in proc.stderr
    finally:
        VRL_PATH.write_text(original, encoding="utf-8")


def test_regeneration_is_byte_stable():
    """Two renders of one screen must be identical — a generator with any
    unordered iteration in it would make every CI run a false drift alarm."""
    first = gen.build()
    second = gen.build()
    assert first == second


# ── 2. rules_hash tracks the DECISION, not the text ──────────────────────────

def _live_screen():
    return gen.read_screen(producers)


def test_rules_hash_is_stamped_into_every_artifact():
    floor, literals = _live_screen()
    digest = gen.rules_hash(floor, literals)
    assert digest in _read(VRL_PATH)
    assert digest in _read(TESTS_YAML)
    assert digest[:12] in _read(CONFIG_PATH), (
        "the 12-hex prefix is what rides on every admitted event (.cx_admission.v) "
        "— it must be in the config the aggregator actually loads")


def test_rules_hash_changes_when_a_literal_changes(monkeypatch):
    """A screen that gained or lost a marker admits a different set of lines.
    If the hash did not move, an event stamped with the old `v` would be
    indistinguishable from one screened by the new rules."""
    floor, literals = _live_screen()
    assert literals is not None
    base = gen.rules_hash(floor, literals)

    added = gen.rules_hash(floor, literals + ("a-brand-new-marker",))
    assert added != base, "adding a literal must move rules_hash"

    dropped = gen.rules_hash(floor, literals[1:])
    assert dropped != base, "dropping a literal must move rules_hash"

    mutated = ("adjchang3",) + literals[1:]
    assert gen.rules_hash(floor, mutated) != base, (
        "changing a literal must move rules_hash")

    # ...and the same screen in a different presentation order is the SAME
    # screen: the tuple's longest-first order is a lookup optimization.
    assert gen.rules_hash(floor, tuple(reversed(literals))) == base


def test_rules_hash_changes_when_the_severity_floor_changes():
    floor, literals = _live_screen()
    assert gen.rules_hash(floor + 1, literals) != gen.rules_hash(floor, literals)


def test_rules_hash_marks_the_unscreenable_screen_distinctly():
    floor, literals = _live_screen()
    assert gen.rules_hash(floor, None) != gen.rules_hash(floor, literals)


def test_a_changed_literal_reaches_the_generated_vrl(monkeypatch):
    """End to end: patch the SCREEN, re-render, and see both the new literal
    and a new hash come out. This is the mechanism the drift gate protects."""
    floor, literals = _live_screen()
    assert literals is not None
    mutant = literals + ("cx-test-only-marker",)
    monkeypatch.setattr(producers, "_SYSLOG_SCREEN_LITERALS", mutant)
    monkeypatch.setattr(producers, "_build_syslog_screen", lambda: mutant)

    digest = gen.rules_hash(floor, mutant)
    vrl = gen.render_vrl(floor, mutant, gen.read_severity_map(producers), digest)
    assert "cx-test-only-marker" in vrl
    assert digest[:12] in vrl
    assert gen.rules_hash(floor, literals)[:12] not in vrl


def test_the_tag_severity_regex_is_emitted_unescaped():
    """REGRESSION (caught while building this): the emitted VRL regex must be
    `(?P<d>\\d)`, not `(?P<d>\\\\d)`. A doubled backslash matches a LITERAL
    backslash, which silently switches off the %FAC-N-MNEMONIC severity path —
    the screen would then admit FEWER lines than the Python does, the one
    direction `syslog_promotable`'s contract forbids. The pattern is derived
    from the pinned copy of `producers._TAG_SEV_RE` so there is no second
    hand-kept literal to slip."""
    vrl = _read(VRL_PATH)
    assert r"parse_regex(cx_tag, r'%[A-Z0-9_]+-(?P<d>\d)-[A-Z0-9_]+')" in vrl
    assert r"\\d" not in vrl, "the digit class must not be double-escaped"
    assert gen.VRL_TAG_SEV_PATTERN.replace("?P<d>", "") == gen.TAG_SEV_PATTERN
    assert producers._TAG_SEV_RE.pattern == gen.TAG_SEV_PATTERN, (
        "the generator's pinned copy has drifted from the engine's regex")


def test_appname_derived_severity_is_actually_exercised():
    """The tag-digit path needs a case with NO severity field at all, or the
    regression above would pass unnoticed."""
    suite = yaml.safe_load(_read(TESTS_YAML))
    cases = [c for c in suite["tests"]
             if "severity" not in c["inputs"][0]["log_fields"]
             and str(c["inputs"][0]["log_fields"].get("appname", "")).startswith("%")]
    assert cases, "no severity-less %FAC-N-MNEMONIC case in the generated suite"


# ── 3. fail-open parity (UNSCREENABLE) ───────────────────────────────────────

def test_an_unscreenable_screen_generates_a_fail_open_program(monkeypatch):
    """`_build_syslog_screen()` returns None when a classifier guard cannot be
    screened soundly, and `syslog_promotable` then admits EVERYTHING. The
    generated VRL must do the same: losing the optimization is acceptable,
    losing a signal is not."""
    monkeypatch.setattr(producers, "_SYSLOG_SCREEN_LITERALS", None)
    monkeypatch.setattr(producers, "_build_syslog_screen", lambda: None)

    floor, literals = gen.read_screen(producers)
    assert literals is None
    vrl = gen.render_vrl(floor, None, gen.read_severity_map(producers),
                         gen.rules_hash(floor, None))
    assert "UNSCREENABLE" in vrl, "the header must say the screen is inert"
    assert '"by": "unscreenable"' in vrl
    assert "match(" not in vrl, (
        "a fail-open program must not carry a literal screen at all")
    # Every line ends up stamped: severity answers, or the fail-open branch does.
    assert "if !exists(.cx_admission) {" in vrl

    # And the Python it mirrors really does admit everything in that state.
    assert producers.syslog_promotable(
        {"message": "nothing interesting here", "severity": "debug"})


def test_the_generator_refuses_a_screen_it_cannot_compile(monkeypatch):
    """Literals are pasted into a VRL regex. One carrying a metacharacter would
    silently change the predicate, so the generator REFUSES rather than
    escaping on a guess."""
    _floor, literals = _live_screen()
    assert literals is not None
    for bad in ("adj(change", "up|down", "quote'd"):
        mutant = literals + (bad,)
        monkeypatch.setattr(producers, "_SYSLOG_SCREEN_LITERALS", mutant)
        monkeypatch.setattr(producers, "_build_syslog_screen", lambda m=mutant: m)
        with pytest.raises(gen.GenerationError, match="cannot compile"):
            gen.read_screen(producers)


def test_the_generator_refuses_a_patched_or_unstable_screen(monkeypatch):
    """Generating from a module global that disagrees with the builder would
    bake a screen the engine does not actually run."""
    _floor, literals = _live_screen()
    monkeypatch.setattr(producers, "_SYSLOG_SCREEN_LITERALS", literals[1:])
    with pytest.raises(gen.GenerationError, match="screen disagreement"):
        gen.read_screen(producers)


def test_the_generator_refuses_a_floor_that_breaks_the_sentinel(monkeypatch):
    """The VRL uses 99 for "no severity derivable". A floor that reached it
    would admit severity-less lines the Python screen rejects."""
    monkeypatch.setattr(producers, "ALARM_SEVERITY_FLOOR", 99)
    with pytest.raises(gen.GenerationError):
        gen.read_screen(producers)


# ── 4. the golden equality, in the real runtime ──────────────────────────────

def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=60, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def test_vector_unit_tests_prove_the_vrl_matches_the_python_screen():
    """THE load-bearing test. Every case in the generated suite carries the
    verdict `producers.syslog_promotable` gives for that exact event (the
    generator refuses to write a case where the two disagree), so a green
    `vector test` means the shipped VRL and the engine admit the same lines.

    Skipped LOUDLY without docker: the assertion cannot be faked in-process,
    and pretending it passed would be the silent-failure shape this repo keeps
    fixing elsewhere."""
    if not _docker_available():
        pytest.skip(
            "docker is unavailable — the VRL golden-equality check DID NOT RUN. "
            "This is the only test that executes the real generated program; "
            "run it before shipping: docker run --rm --entrypoint vector -v "
            "./deployment/docker/vector:/etc/vector/conf:ro " + VECTOR_IMAGE +
            " test /etc/vector/conf/tests/syslog-admission.yaml")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "vector",
         "-v", f"{VECTOR_DIR}:/etc/vector/conf:ro", VECTOR_IMAGE,
         "test", "/etc/vector/conf/tests/syslog-admission.yaml"],
        capture_output=True, text=True, timeout=600, check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"vector test failed:\n{out}"
    assert "failed" not in out.lower(), out
    passed = out.count("... passed")
    assert passed >= 30, f"expected the full generated suite, saw {passed}:\n{out}"


def test_the_generated_suite_proves_rejection_too():
    """A suite where every case is admitted would pass against a VRL that
    admits unconditionally. Both verdicts must be represented, and the
    generator states the split in the header."""
    floor, literals = _live_screen()
    suite = yaml.safe_load(_read(TESTS_YAML))
    verdicts = [t["outputs"][0]["conditions"][0]["source"] for t in suite["tests"]]
    rejected = [v for v in verdicts if "assert_eq!(.cx_admission, null" in v]
    admitted = [v for v in verdicts if ".cx_admission.by" in v]
    assert len(rejected) >= 3, f"only {len(rejected)} rejection cases"
    assert len(admitted) >= 5, f"only {len(admitted)} admission cases"
    for gate in ("severity", "marker"):
        assert any(f'"{gate}"' in v for v in admitted), (
            f"the {gate} gate is never exercised — the generator refuses to "
            "write such a suite, so this means the artifact is stale")

    # And the expectations really are the Python's verdicts, re-derived here
    # from the suite's own inputs rather than trusted from the header.
    for case in suite["tests"]:
        ev = dict(case["inputs"][0]["log_fields"])
        want = gen.expected_by(ev, floor, literals)
        source = case["outputs"][0]["conditions"][0]["source"]
        assert producers.syslog_promotable(ev) == (want is not None)
        if want is None:
            assert "assert_eq!(.cx_admission, null" in source, case["name"]
        else:
            assert f'.cx_admission.by, "{want}"' in source, case["name"]


def test_the_suite_loads_the_generated_file_itself():
    """The suite must exercise the ARTIFACT, not a copy of it — otherwise a
    green run says nothing about what the aggregator loads."""
    suite = yaml.safe_load(_read(TESTS_YAML))
    transform = suite["transforms"]["syslog_admission_stamp"]
    assert transform["file"].endswith("generated/syslog-admission.vrl")


# ── 5. aggregator topology: a superset/subset pair, not a re-route ───────────

def _vector_cfg() -> dict:
    return yaml.safe_load(_read(CONFIG_PATH))


def test_the_stamp_is_additive_and_the_full_lane_is_unchanged():
    cfg = _vector_cfg()
    stamp = cfg["transforms"]["syslog_admission_stamp"]
    assert stamp["type"] == "remap"
    assert stamp["inputs"] == ["syslog_normalized"]
    for forbidden in ("abort", "drop_on_error", "reroute_dropped"):
        assert forbidden not in stamp["source"] or forbidden == "abort", stamp
    assert "abort" not in stamp["source"], (
        "the admission stamp must never drop a line — kafka_syslog carries "
        "the WHOLE lane and correlation still reads it")
    assert cfg["sinks"]["kafka_syslog"]["inputs"] == ["syslog_admission_stamp"], (
        "the full lane runs through the stamp so `.cx_admission` travels on "
        "both copies (the marker is queryable in OpenSearch across the whole "
        "firehose, which is how the split gets qualified before it is trusted)")


def test_the_route_selects_on_the_admission_stamp_only():
    cfg = _vector_cfg()
    route = cfg["transforms"]["syslog_admission"]
    assert route["type"] == "route"
    assert route["inputs"] == ["syslog_admission_stamp"]
    assert route["route"]["control"] == ".cx_admission.by != null"
    assert route["reroute_unmatched"] is False, (
        "an _unmatched output nothing consumes would be dead topology")


def test_cx_admission_is_on_the_control_sinks_input_path():
    """Every event on the control topic carries the stamp — the field is set
    by the stamp transform, the route admits only events that carry it, and
    the sink reads only that route output."""
    cfg = _vector_cfg()
    stamp = cfg["transforms"]["syslog_admission_stamp"]["source"]
    assert ".cx_admission = {" in stamp
    assert '"v":' in stamp and '"by":' in stamp
    sink = cfg["sinks"]["kafka_syslog_control"]
    assert sink["inputs"] == ["syslog_admission.control"]
    assert sink["topic"] == CONTROL_TOPIC
    # …and the stamp is not stripped on the way out (only the partition key is).
    assert sink["encoding"]["except_fields"] == ["__key"]


def test_the_vrl_in_the_config_is_the_generated_artifact_verbatim():
    """vector.yaml carries a SPLICED copy rather than `file:` — see the
    generator's header for why (preflight mounts only vector.yaml, and a
    missing VRL file would be a boot failure of the whole syslog tier). The
    two copies must therefore be provably identical, line for line."""
    spliced = _vector_cfg()["transforms"]["syslog_admission_stamp"]["source"]
    artifact = _read(VRL_PATH)
    assert spliced.rstrip("\n").split("\n") == artifact.rstrip("\n").split("\n")


def test_the_generated_block_is_fenced_by_markers():
    text = _read(CONFIG_PATH)
    assert text.count(gen.BEGIN_MARK) == 1
    assert text.count(gen.END_MARK) == 1
    assert text.index(gen.BEGIN_MARK) < text.index(gen.END_MARK)


# ── 6. bus: the topic exists, co-partitioned, and only correlation may read ──

def test_the_control_topic_is_pre_created_in_both_compose_files():
    for rel in ("docker-compose.yml", "compose.tls.yml"):
        text = _read(ROOT / "deployment" / "docker" / rel)
        assert CONTROL_TOPIC in text, f"{rel} kafka-init must create {CONTROL_TOPIC}"
        assert "BUS_PARTITIONS" in text, (
            f"{rel} must still mint every topic at the shared partition count")


def test_the_control_sink_matches_the_full_lane_byte_for_byte_where_it_must():
    """Same key, same partitioner, same codec, same TLS — anything else and
    partition k of the two topics stops holding the same tenant, which is the
    whole reason a consumer can be switched over by env alone."""
    sinks = _vector_cfg()["sinks"]
    full, ctrl = sinks["kafka_syslog"], sinks["kafka_syslog_control"]
    for field in ("type", "key_field", "librdkafka_options", "encoding",
                  "compression", "tls", "bootstrap_servers"):
        assert ctrl[field] == full[field], field


def test_only_correlation_is_granted_the_control_topic():
    acls = _read(ROOT / "deployment" / "docker" / "kafka" / "apply-acls.sh")
    corr_block = acls.split("acls: correlation", 1)
    assert len(corr_block) == 2, "correlation ACL block not found"
    assert CONTROL_TOPIC in corr_block[1].split("done", 1)[0], (
        "correlation must be granted Read on the control topic")
    # COMMANDS only — the file also EXPLAINS, in prose, why the router is not
    # granted the topic, and a substring check would read that explanation as
    # the grant it warns against.
    router_block = "\n".join(
        ln for ln in acls.split("acls: router", 1)[1]
                         .split("acls: correlation", 1)[0].splitlines()
        if not ln.lstrip().startswith("#"))
    assert CONTROL_TOPIC not in router_block, (
        "the router indexes the FULL lane; granting it the pre-screened copy "
        "would duplicate every admitted document in OpenSearch")


# ── 7. the scale harness mirror is opt-in and exact ──────────────────────────

ml = _load(ROOT / "scripts" / "scale-miniladder.py", "scale_miniladder_admission")


class _RecordingStack:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.produced: list[tuple[str, list[str], str | None]] = []

    def produce(self, topic, lines, key=None):
        self.produced.append((topic, list(lines), key))
        return (True, "") if self.ok else (False, "broker refused")


def _harness(argv: list[str]) -> object:
    h = ml.Harness.__new__(ml.Harness)
    h.args = ml.parse_args(argv)
    h.stack = _RecordingStack()
    h.producer_key = "tenant-a"
    h.produce_failures = []
    return h


def _plan(n: int = 40) -> list[str]:
    """A mixed plan: classifying lines, noise lines, and severity-only lines."""
    rows = []
    for i in range(n):
        if i % 4 == 0:
            rows.append({"hostname": f"d{i}", "appname": "%LINK-3-UPDOWN",
                         "message": f"Interface Gi0/{i} changed state to down",
                         "severity": "err"})
        elif i % 4 == 1:
            rows.append({"hostname": f"d{i}", "appname": "sshd",
                         "message": f"accepted publickey for netops seq {i}",
                         "severity": "info"})
        elif i % 4 == 2:
            rows.append({"hostname": f"d{i}", "appname": "eos",
                         "message": f"LLDP neighbor changed on Et{i}",
                         "severity": "notice"})
        else:
            rows.append({"hostname": f"d{i}", "appname": "cron",
                         "message": f"run-parts daily seq {i}",
                         "severity": "debug"})
    return [json.dumps(r) for r in rows]


def test_the_mirror_is_off_by_default():
    assert ml.parse_args([]).syslog_control_mirror is False


def test_the_default_leg_never_touches_the_control_topic():
    """Byte-identical default: with no flag the harness produces to
    netops.syslog and to nothing else, and imports no engine code."""
    h = _harness([])
    h._mirror_syslog_control(_plan())
    assert h.stack.produced == [], (
        "the default leg must not produce to any second topic")
    assert h.produce_failures == []
    assert h._mirror_evidence()["enabled"] is False


def test_the_mirrored_subset_is_exactly_the_promotable_subset():
    h = _harness(["--syslog-control-mirror"])
    lines = _plan()
    h._mirror_syslog_control(lines)

    assert len(h.stack.produced) == 1
    topic, mirrored, key = h.stack.produced[0]
    assert topic == CONTROL_TOPIC
    assert key == "tenant-a", "the mirror must reuse the run's tenant key"

    want = [ln for ln in lines if producers.syslog_promotable(json.loads(ln))]
    assert mirrored == want, "the mirror is the engine's screen, or it is noise"
    assert 0 < len(want) < len(lines), (
        "the fixture plan must contain BOTH admitted and rejected lines, or "
        "this test cannot tell a real screen from `return True`")
    assert h._mirror_evidence() == {
        "enabled": True, "topic": CONTROL_TOPIC,
        "considered": len(lines), "mirrored": len(want)}


def test_the_mirror_never_rewrites_a_line():
    h = _harness(["--syslog-control-mirror"])
    lines = _plan()
    h._mirror_syslog_control(lines)
    _topic, mirrored, _key = h.stack.produced[0]
    assert set(mirrored) <= set(lines), "mirrored records must be the originals"


def test_a_mirror_produce_failure_is_loud():
    """16.1: a half-mirrored control topic makes the comparison the flag exists
    to enable dishonest — it must fail the burst, not be swallowed."""
    h = _harness(["--syslog-control-mirror"])
    h.stack = _RecordingStack(ok=False)
    h._mirror_syslog_control(_plan())
    assert h.produce_failures, "a failed mirror produce must be recorded"
    assert "syslog-control mirror" in h.produce_failures[0]


def test_a_non_json_line_fails_loudly_rather_than_being_skipped():
    h = _harness(["--syslog-control-mirror"])
    h._mirror_syslog_control(["not json at all"])
    assert h.produce_failures, "an unparseable line must not be silently dropped"
    assert h.stack.produced == []


def test_the_mirror_uses_the_engines_own_screen():
    """Not a reimplementation: the loader returns the very function the engine
    calls, so the two cannot drift."""
    assert ml.load_syslog_screen() is producers.syslog_promotable


def test_the_harness_still_injects_the_full_lane_into_netops_syslog():
    """The mirror is an ADDITION. The primary produce target must stay
    netops.syslog in both burst loops, or every recorded capacity number
    silently changes meaning."""
    src = _read(ROOT / "scripts" / "scale-miniladder.py")
    assert src.count('self.stack.produce("netops.syslog"') >= 2
    assert 'produce(SYSLOG_CONTROL_TOPIC' in src


# ── 7b. the stamp must be SEARCHABLE, not merely present ─────────────────────

def _templates() -> dict:
    with open(ROOT / "deployment" / "docker" / "opensearch" /
              "index-templates.json", encoding="utf-8") as fh:
        return json.load(fh)["templates"]


def test_the_syslog_template_maps_cx_admission_by_as_keyword():
    """THE MINING CONTRACT. `src/backend/parsercov/admission.go` counts
    unrecognized lines with `must_not exists cx_admission.by`. The syslog
    template is `dynamic: false`, so an UNDECLARED object is kept in _source
    but never mapped — `exists` then matches nothing and the miner would report
    100 % unrecognized against a pipeline that is stamping correctly. Declared
    keyword: exact-match and aggregatable, never analysed."""
    props = _templates()["netops-syslog"]["template"]["mappings"]["properties"]
    assert "cx_admission" in props, (
        "the syslog template must declare cx_admission — under dynamic:false "
        "an undeclared stamp is stored but unsearchable")
    cx = props["cx_admission"]
    assert cx["type"] == "object"
    assert cx["properties"]["by"] == {"type": "keyword"}
    assert cx["properties"]["v"] == {"type": "keyword"}
    assert _templates()["netops-syslog"]["template"]["mappings"]["dynamic"] is False, (
        "the field wall (F-05) stays closed — cx_admission is declared, not "
        "admitted by loosening dynamic mapping")


def test_only_the_syslog_lane_declares_the_stamp():
    """The stamp rides syslog ONLY: syslog_admission_stamp feeds kafka_syslog
    and the control route, and no other transform reads it. Declaring it on a
    lane that never carries it would advertise a field that is always absent."""
    cfg = _vector_cfg()
    readers = {name for name, comp in
               list((cfg.get("transforms") or {}).items()) +
               list((cfg.get("sinks") or {}).items())
               if "syslog_admission_stamp" in (comp.get("inputs") or [])}
    assert readers == {"syslog_admission", "kafka_syslog"}, readers
    declaring = {name for name, tpl in _templates().items()
                 if "cx_admission" in tpl["template"]["mappings"]["properties"]}
    assert declaring == {"netops-syslog"}, declaring


def test_no_documentation_key_leaks_into_a_template_payload():
    """`bootstrap-opensearch.sh` strips `_`-prefixed doc keys only at the TOP
    level of a template, and install.py does not strip them at all. A nested
    `_comment` therefore reaches OpenSearch as an unknown mapping parameter and
    the PUT 400s — a template that fails to apply while the install looks fine.
    Keep prose at the template level, never inside `template`."""
    for name, tpl in _templates().items():
        stack = [("template", tpl["template"])]
        while stack:
            path, node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    assert not key.startswith("_"), (
                        f"{name}: documentation key {path}.{key} would be PUT "
                        "to OpenSearch as an unknown mapping parameter")
                    stack.append((f"{path}.{key}", value))
            elif isinstance(node, list):
                stack.extend((f"{path}[{i}]", v) for i, v in enumerate(node))


# ── 8. the docs say the switch is not thrown yet ─────────────────────────────

def test_the_operator_doc_states_the_topic_is_off_by_default():
    doc = _read(ROOT / "docs" / "INGESTION.md")
    assert CONTROL_TOPIC in doc
    assert "CORR_SYSLOG_TOPIC" in doc, (
        "the doc must name the env var that flips the engine over, so the "
        "switch is discoverable and its precondition is written down")
