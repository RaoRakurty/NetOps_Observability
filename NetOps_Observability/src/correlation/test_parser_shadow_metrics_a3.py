# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A3/A8 — shadow-rule hits are EXPOSED, not just counted.

A shadow rule is evaluated by the parser and deliberately emits nothing. That
makes it invisible by construction: the only evidence it exists, matches, and is
ready to graduate is its counter. A counter nobody can scrape is the same defect
as no counter at all (§10 no silent failures), so the exposition is gated here.

`corr_parser_shadow_hits_total` is DISJOINT from `corr_parser_rule_hits_total`
by construction — a hit is a signal the engine acted on, a shadow hit is a match
it chose not to promote — so the two families together are the honest "what the
estate sends vs what the engine acts on" split.
"""
from __future__ import annotations

import main
import producers


def metrics() -> str:
    return main._metrics_text()


def test_the_family_is_declared_even_when_no_shadow_rule_ships():
    """No shadow row ships today. The HELP/TYPE pair must still be emitted, so
    the family reads as "declared, zero rows" rather than as a missing metric a
    dashboard silently drops."""
    text = metrics()
    assert "# HELP corr_parser_shadow_hits_total" in text
    assert "# TYPE corr_parser_shadow_hits_total counter" in text
    assert producers.parser_stats()["shadow_hits"] == {
        r.rule_id: 0 for r in producers.RULES if r.shadow}


def test_each_shadow_rule_renders_one_labelled_series(monkeypatch):
    monkeypatch.setattr(producers, "SHADOW_HITS",
                        {"ctl.shadow.candidate": 7, "ctl.shadow.other": 0})
    text = metrics()
    assert 'corr_parser_shadow_hits_total{rule_id="ctl.shadow.candidate"} 7' in text
    # a shadow rule that has NOT matched is still a series (pre-seeded at zero):
    # a dead branch must show as flat, never as absent.
    assert 'corr_parser_shadow_hits_total{rule_id="ctl.shadow.other"} 0' in text


def test_shadow_and_emitting_hits_are_disjoint_families(monkeypatch):
    monkeypatch.setattr(producers, "SHADOW_HITS", {"ctl.shadow.candidate": 3})
    text = metrics()
    shadow_ids = {line.split('rule_id="', 1)[1].split('"', 1)[0]
                  for line in text.splitlines()
                  if line.startswith("corr_parser_shadow_hits_total{")}
    hit_ids = {line.split('rule_id="', 1)[1].split('"', 1)[0]
               for line in text.splitlines()
               if line.startswith("corr_parser_rule_hits_total{")}
    assert shadow_ids == {"ctl.shadow.candidate"}
    assert not (shadow_ids & hit_ids), (
        "a rule id in BOTH families means a shadow row also emitted — the whole "
        "point of a shadow row is that it does not")


def test_the_label_set_comes_from_the_fixed_rule_corpus():
    """Bounded cardinality (§9): every rendered label is a rule id from the
    import-time corpus, so no device- or attacker-supplied string can widen the
    series count."""
    known = {r.rule_id for r in producers.RULES}
    for line in metrics().splitlines():
        if line.startswith("corr_parser_shadow_hits_total{"):
            rid = line.split('rule_id="', 1)[1].split('"', 1)[0]
            assert rid in known, rid
