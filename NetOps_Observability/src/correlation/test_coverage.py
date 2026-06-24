"""#80 §5 self-coverage CI gate — the catalog reports its own rule-base blind
spots, and a NEW dead template (a signature whose required kind nothing emits)
fails the build."""

from catalog import builtin_catalog
from coverage import (
    KNOWN_PENDING,
    blind_spot_kinds,
    consumed_kinds,
    coverage_report,
    dead_template_kinds,
)
from producers import EMITTED_KINDS


def test_no_new_dead_templates():
    # Every kind a signature requires is either EMITTED by a producer or an
    # acknowledged v0-theoretical pending kind. A new signature requiring an
    # unemitted, unlisted kind fails here — author Layer-2 emit first.
    cat = builtin_catalog()
    unexpected = dead_template_kinds(cat) - KNOWN_PENDING
    assert not unexpected, (
        f"signature(s) require kinds no producer emits and not in KNOWN_PENDING: "
        f"{sorted(unexpected)} — add the Layer-2 producer (or KNOWN_PENDING w/ a #73 ref)"
    )


def test_known_pending_is_not_stale():
    # KNOWN_PENDING must not claim a kind that is actually emitted now (keeps the
    # backlog honest as Layer-2 lands) nor one no signature even references.
    cat = builtin_catalog()
    stale_emitted = KNOWN_PENDING & EMITTED_KINDS
    assert not stale_emitted, f"KNOWN_PENDING lists now-emitted kinds (remove): {sorted(stale_emitted)}"
    unreferenced = KNOWN_PENDING - consumed_kinds(cat)
    assert not unreferenced, f"KNOWN_PENDING lists kinds no signature references (remove): {sorted(unreferenced)}"


def test_device_alarm_is_an_intentional_blind_spot():
    # The generic-alarm catch-all is emitted and consumed by NO signature — by
    # design (it only grounds/enriches). It must therefore NOT appear as a blind
    # spot needing a signature.
    cat = builtin_catalog()
    assert "device_alarm" in EMITTED_KINDS
    assert "device_alarm" not in blind_spot_kinds(cat)


def test_coverage_report_shape():
    rep = coverage_report(builtin_catalog())
    assert set(rep) == {
        "emitted_kinds", "consumed_kinds", "dead_template_kinds",
        "pending_dead_templates", "blind_spot_kinds",
    }
    assert "device_alarm" in rep["emitted_kinds"]
