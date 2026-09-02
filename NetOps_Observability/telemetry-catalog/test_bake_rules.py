"""Pytest: the rule table and its bake (A3).

`events.yaml` is now the SOURCE of the correlation engine's parser, not a
mirror of it. Two things therefore have to be true from inside this directory,
independently of the engine's own suite:

  * the catalog is WELL FORMED — every row complete, no unknown keys, every
    guard/extraction/emission tree compiles;
  * the checked-in generated module IS this catalog — because the image ships
    the module and not the YAML, a stale bake means production is parsing with
    rules that are not the spec.
"""
from __future__ import annotations

import copy
import os
import subprocess
import sys

import pytest

import bake_rules as B

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def loaded():
    return B.load()


@pytest.fixture(scope="module")
def rows(loaded):
    return loaded[1]


def test_the_catalog_loads_and_validates(loaded):
    data, rows = loaded
    assert data["parser_rev"], "events.yaml must declare a parser_rev"
    assert rows, "the rule table is empty"


def test_the_lanes_are_the_declared_ones(rows):
    assert {r["lane"] for r in rows} <= set(B.LANES)
    runtime = [r for r in rows if r["lane"] in B.RUNTIME_LANES]
    assert len(runtime) == 38, (
        f"{len(runtime)} runtime rules — if that is intended, re-pin this "
        "count and the golden corpus in src/correlation")


def test_every_rule_id_is_unique(rows):
    ids = [r["rule_id"] for r in rows]
    assert len(ids) == len(set(ids))


def test_every_rule_id_is_prefixed_by_its_lane(rows):
    """`rule_id` is a metric label and an operator-facing string; a row whose id
    disagrees with its lane makes the /metrics series unreadable."""
    for r in rows:
        prefix = "catalog" if r["lane"] == "catalog" else r["source"]
        assert r["rule_id"].startswith(prefix + "."), (
            f"{r['rule_id']!r} does not start with {prefix!r}")


def test_every_family_is_implemented_by_at_least_one_rule(loaded):
    """A family with no rule is a canonical-event schema nothing can produce —
    the catalog would claim coverage it does not have."""
    data, rows = loaded
    implemented = {r["family"] for r in rows if r["family"]}
    orphans = sorted(set(data["families"]) - implemented)
    assert not orphans, f"families with no rule: {orphans}"


def test_the_emit_kind_defaults_to_the_row_kind(rows):
    """The twelve port rules share ONE `emit` anchor and differ only in their
    `kind`; the bake must fill it per row, not leak one row's kind into all of
    them (YAML anchors alias the SAME dict object)."""
    port = [r for r in rows if r["lane"] == "port"]
    assert len(port) == 12
    assert len({r["emit"]["kind"] for r in port}) == 12
    for r in rows:
        assert r["emit"]["kind"] == r["kind"]


def test_the_bake_is_deterministic(loaded):
    data, rows = loaded
    assert B.render(data, rows) == B.render(*B.load())


def test_the_checked_in_module_matches_this_catalog(loaded):
    """THE DRIFT GUARD, from the catalog's side."""
    data, rows = loaded
    with open(B.TARGET, encoding="utf-8") as fh:
        current = fh.read()
    assert current == B.render(data, rows), (
        "src/correlation/parser_rules.py is stale — run `python3 bake_rules.py`")


def test_the_check_flag_is_green():
    """The exact command CI runs, run as a test — so `--check` itself cannot rot
    (an exit code nobody exercises is not a gate)."""
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "bake_rules.py"), "--check"],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_check_fails_on_a_stale_target(tmp_path, loaded):
    """MUTANT on the guard: point `--check` at a file that is NOT the bake and
    it must exit non-zero. Otherwise the drift guard is decoration."""
    stale = tmp_path / "parser_rules.py"
    stale.write_text("# not the bake\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "bake_rules.py"), "--check",
         "--out", str(stale)],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "STALE" in proc.stderr


def test_a_missing_target_is_reported_not_crashed(tmp_path):
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "bake_rules.py"), "--check",
         "--out", str(tmp_path / "nope.py")],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "does not exist" in proc.stderr


# ── the validator rejects, rather than baking something half-right ───────────

def _row(rows, rule_id):
    return copy.deepcopy(next(r for r in rows if r["rule_id"] == rule_id))


@pytest.mark.parametrize("mutate,needle", [
    (lambda r: r.update(nonsense=1), "unknown key"),
    (lambda r: r.pop("kind"), "missing required key"),
    (lambda r: r.update(lane="nowhere"), "lane"),
    (lambda r: r.update(source="carrier-pigeon"), "source"),
    (lambda r: r.update(entity_type="planet"), "entity_type"),
    (lambda r: r.update(family="ghost_family"), "not defined in `families:`"),
    (lambda r: r.update(severity="apocalyptic"), "severity"),
    (lambda r: r.update(markers=["lowercase"]), "UPPER-CASE"),
    (lambda r: r.update(vendors="cisco"), "list of strings"),
    (lambda r: r.update(shadow="maybe"), "must be a boolean"),
    (lambda r: r.update(guard={"telepathy": []}), "does not compile"),
    (lambda r: r["emit"].update(sevverity="high"), "unknown emit key"),
    (lambda r: r["emit"].pop("metric"), "emit.metric"),
])
def test_a_malformed_row_does_not_bake(loaded, mutate, needle):
    data, rows = loaded
    row = _row(rows, "syslog.link.state_change")
    mutate(row)
    with pytest.raises(B.BakeError) as exc:
        B.validate_row(row, data["families"], set())
    assert needle in str(exc.value)


def test_an_unknown_top_level_key_is_rejected(tmp_path):
    """A misspelt section (`rule:` for `rules:`) would bake an EMPTY table and
    ship a parser that classifies nothing. It must be loud."""
    import yaml
    bad = tmp_path / "events.yaml"
    bad.write_text(yaml.safe_dump({"version": 1, "parser_rev": "x",
                                   "rules": [], "families": {},
                                   "typo_section": {}}), encoding="utf-8")
    with pytest.raises(B.BakeError, match="unknown top-level key"):
        B.load(str(bad))


def test_a_catalog_without_a_parser_rev_is_rejected(tmp_path):
    import yaml
    bad = tmp_path / "events.yaml"
    bad.write_text(yaml.safe_dump({"version": 1, "rules": [], "families": {}}),
                   encoding="utf-8")
    with pytest.raises(B.BakeError, match="parser_rev"):
        B.load(str(bad))


def test_an_extraction_may_not_shadow_a_lane_var(loaded):
    """`msg` / `tag` / `host` are seeded by the lane before any extraction runs,
    so a row declaring one would ship a grammar that never executes — silently.
    Silence is the failure mode this catalog exists to remove."""
    data, rows = loaded
    row = _row(rows, "syslog.link.state_change")
    row["extract"]["tag"] = {"const": "hijacked"}
    with pytest.raises(B.BakeError, match="shadow a lane var"):
        B.validate_row(row, data["families"], set())


def test_a_pattern_src_must_be_a_live_node_of_its_own_guard(loaded):
    """The ingest screen screens this rule BY `pattern_src`. If it is not
    actually a gate of the rule, the screen advertises coverage for a gate that
    no longer exists — the exact drift the derivation was built to stop."""
    data, rows = loaded
    row = _row(rows, "syslog.evpn.mac_move")
    row["pattern_src"] = r"\bdoes-not-appear\b"
    with pytest.raises(B.BakeError, match="pattern_src"):
        B.validate_row(row, data["families"], set())


def test_every_registered_pattern_src_is_screenable(rows):
    """Soundness of the screen itself: a `pattern_src` the literal extractor
    cannot read makes the whole pre-filter fail OPEN (correct but free of
    value). Catch it here, where it is cheap to fix."""
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "correlation")))
    from regex_screen import pattern_screen
    for r in rows:
        if r.get("pattern_src"):
            assert pattern_screen(r["pattern_src"]), (
                f"{r['rule_id']}: pattern_src is unscreenable, which silently "
                "disables the ingest pre-filter")
