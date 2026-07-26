"""The T5 drill matrix (#120) must not drift from the code it describes.

Hermetic: every kind the matrix names must be a real CLOUD_KINDS lane kind,
every signature a real catalog id, and the matrix must cover all 7 acceptance
drills of docs/design/cloud-provider-parity.md for every provider — otherwise
the harness would wave through a drill whose counters can never move (the
exact failure mode #120 exists to prevent).
"""
from catalog import builtin_catalog
from cloud_drill_matrix import (
    MATRIX,
    PROVIDER_BLIND_KINDS,
    PROVIDERS,
    all_kinds,
    expectations_for,
)
from cloud_producers import CLOUD_KINDS


def test_every_matrix_kind_is_a_real_lane_kind():
    known = set(CLOUD_KINDS)
    for exp in MATRIX:
        unknown = all_kinds(exp) - known
        assert not unknown, (
            f"drill {exp.drill} names kinds no lane can emit: {sorted(unknown)} "
            f"— the matrix would wait forever for them"
        )


def test_provider_blind_kinds_are_real():
    assert PROVIDER_BLIND_KINDS <= set(CLOUD_KINDS)


def test_every_matrix_signature_exists_in_catalog():
    ids = {t.id for t in builtin_catalog().templates}
    for exp in MATRIX:
        unknown = set(exp.signatures) - ids
        assert not unknown, (
            f"drill {exp.drill} references unknown signature(s): {sorted(unknown)}"
        )


def test_matrix_covers_all_seven_drills_for_every_provider():
    for provider in PROVIDERS:
        drills = {e.drill for e in expectations_for(provider)}
        assert drills == {1, 2, 3, 4, 5, 6, 7}, (
            f"{provider}: acceptance suite is 7 drills, matrix covers {sorted(drills)}"
        )


def test_every_drill_is_checkable_or_explicitly_manual():
    for exp in MATRIX:
        assert exp.required or exp.manual, (
            f"drill {exp.drill} has neither required counters nor a manual "
            f"instruction — it could 'pass' without anyone checking anything"
        )
        if exp.manual:
            assert not exp.required, (
                f"drill {exp.drill} is both manual and counter-gated — pick one"
            )


def test_required_groups_are_nonempty():
    for exp in MATRIX:
        for group in exp.required:
            assert group, f"drill {exp.drill} has an empty any-of group (vacuous pass)"
