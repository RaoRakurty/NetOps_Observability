# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The parser CORPUS is exported, not just its counters.

`corr_parser_rule_hits_total` says how often a rule fired; nothing said what the
rule IS. The parser-coverage page needs both — lane, emitted kind, the catalog's
fidelity claim for the grammar, and whether the row is a `shadow` rule that
deliberately emits nothing — so the corpus ships as per-rule metadata on the
health payload (`parser.rules_meta`) and as a 1-valued info series a scrape can
JOIN the hit counters to (`corr_parser_rule_info`).

Two properties are gated here, and they are the two that make an info series
safe: it is COMPLETE (every rule in the fixed corpus renders exactly one series,
so a rule cannot be silently missing from the page) and it is BOUNDED +
ESCAPED (labels come from the import-time rule table, and the values are escaped
anyway so no future non-fixed value can break the exposition or inject a series).
"""
from __future__ import annotations

import main
import producers


def info_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines()
            if ln.startswith("corr_parser_rule_info{")]


def label(line: str, name: str) -> str:
    return line.split(f'{name}="', 1)[1].split('"', 1)[0]


# ── the health block ─────────────────────────────────────────────────────────

def test_the_health_payload_describes_every_rule_in_the_corpus():
    meta = main._health_payload()["parser"]["rules_meta"]
    assert [m["rule_id"] for m in meta] == [r.rule_id for r in producers.RULES], (
        "rules_meta must list the whole corpus, in CLASSIFICATION ORDER — the "
        "order is behaviour (first match wins), so the page must show it")
    by_id = {r.rule_id: r for r in producers.RULES}
    for m in meta:
        rule = by_id[m["rule_id"]]
        assert m == {"rule_id": rule.rule_id, "lane": rule.lane,
                     "kind": rule.kind, "fidelity": rule.fidelity,
                     "shadow": bool(rule.shadow)}
        assert isinstance(m["shadow"], bool)


def test_the_fidelity_reported_is_the_catalogs_live_claim(monkeypatch):
    """`Rule.fidelity` resolves through the baked event-family map, so a catalog
    promotion is visible here WITHOUT a parser edit — the property the fidelity
    ladder exists for. Exercised by promoting a family in place."""
    # a row-level `fidelity_status` (A9) deliberately WINS over the family, so
    # the probe must be a rule whose claim comes from the family alone.
    catalogued = next((r for r in producers.RULES
                       if r.fidelity_key and not r.fidelity_status), None)
    assert catalogued is not None
    monkeypatch.setitem(producers.CATALOG_EVENT_FIDELITY,
                        catalogued.fidelity_key, "live_validated")
    meta = {m["rule_id"]: m for m in producers.parser_stats()["rules_meta"]}
    assert meta[catalogued.rule_id]["fidelity"] == "live_validated"


# ── the exposition ───────────────────────────────────────────────────────────

def test_every_rule_renders_exactly_one_info_series():
    text = main._metrics_text()
    assert "# HELP corr_parser_rule_info" in text
    assert "# TYPE corr_parser_rule_info gauge" in text
    lines = info_lines(text)
    assert len(lines) == len(producers.RULES)
    rendered = {label(ln, "rule_id") for ln in lines}
    assert rendered == {r.rule_id for r in producers.RULES}
    assert all(ln.endswith("} 1") for ln in lines)


def test_the_series_carries_the_lane_kind_fidelity_and_shadow_of_each_rule():
    by_id = {r.rule_id: r for r in producers.RULES}
    for ln in info_lines(main._metrics_text()):
        rule = by_id[label(ln, "rule_id")]
        assert label(ln, "lane") == rule.lane
        assert label(ln, "kind") == rule.kind
        assert label(ln, "fidelity") == rule.fidelity
        assert label(ln, "shadow") == ("true" if rule.shadow else "false")


def test_the_label_set_is_bounded_by_the_import_time_corpus():
    """§9 bounded cardinality: one series per rule, and every label value comes
    from the fixed table — no device- or attacker-supplied string can widen it."""
    lanes = {r.lane for r in producers.RULES}
    kinds = {r.kind for r in producers.RULES}
    for ln in info_lines(main._metrics_text()):
        assert label(ln, "lane") in lanes
        assert label(ln, "kind") in kinds
        assert label(ln, "shadow") in ("true", "false")


# ── escaping ─────────────────────────────────────────────────────────────────

def test_label_values_are_escaped():
    assert main._prom_label('a"b') == 'a\\"b'
    assert main._prom_label("a\\b") == "a\\\\b"
    assert main._prom_label("a\nb") == "a\\nb"
    assert main._prom_label("plain") == "plain"


def test_a_hostile_label_value_cannot_break_or_inject_a_series(monkeypatch):
    """Today every value is from the fixed corpus, so this can only be reached
    by a future rule id. Pinned now rather than after: an unescaped quote would
    end the label set early and let the rest of the string be read as more
    labels — one malformed rule row corrupting the whole exposition."""
    real = main.parser_stats

    def hostile() -> dict:
        stats = dict(real())
        stats["rules_meta"] = [{
            "rule_id": 'evil",injected="1', "lane": "syslog\nnot_a_metric 1",
            "kind": "k\\1", "fidelity": "code", "shadow": False}]
        return stats

    monkeypatch.setattr(main, "parser_stats", hostile)
    lines = info_lines(main._metrics_text())
    assert len(lines) == 1
    assert 'rule_id="evil\\",injected=\\"1"' in lines[0]
    assert 'lane="syslog\\nnot_a_metric 1"' in lines[0]
    assert 'kind="k\\\\1"' in lines[0]
    assert lines[0].endswith("} 1")
    # nothing escaped into a second series
    assert not any(ln.startswith("not_a_metric")
                   for ln in main._metrics_text().splitlines())
