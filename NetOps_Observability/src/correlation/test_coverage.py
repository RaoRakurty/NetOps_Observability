"""#80 §5 self-coverage CI gate, hardened per the #98 postmortem: the synthetic
app-experience gap hid for weeks because the flat KNOWN_PENDING bag treated
"we don't collect this" and "we collect this but never map it" as the same
acknowledged state. The gate now enforces the split:

  * a NEW dead template (signature kind nothing emits, undeclared) fails;
  * a NORMALIZATION gap (phenomenon observed, semantic kind unmapped) fails
    unless it is a structurally complete, ticketed allowlist entry — and the
    failure text says "fix the normalizer", not "add a collector";
  * an ORPHAN producer kind (emitted, consumed by nothing, undeclared) fails;
  * stale declarations (kind now emitted / no longer referenced) fail, so the
    ledgers shrink as reality catches up.
"""

from catalog import builtin_catalog
from coverage import (
    COLLECTION_PENDING,
    INTENTIONAL_BLIND,
    KNOWN_PENDING,
    NORMALIZATION_PENDING,
    _NORM_FIELDS,
    blind_spot_kinds,
    classify_kind,
    consumed_kinds,
    coverage_report,
    dead_template_kinds,
    normalization_gap_message,
    orphan_producer_kinds,
)
from producers import EMITTED_KINDS

CAT = builtin_catalog()


# ── the split itself ──────────────────────────────────────────────────────────
def test_pending_classes_are_disjoint():
    overlap = frozenset(COLLECTION_PENDING) & frozenset(NORMALIZATION_PENDING)
    assert not overlap, (
        f"kind(s) declared BOTH collection- and normalization-pending: {sorted(overlap)} "
        f"— a gap has exactly one class; decide whether the phenomenon is observed."
    )


def test_known_pending_is_only_a_compat_view():
    # The deprecated flat view must be exactly the union — never an independent
    # third ledger someone quietly adds to.
    assert KNOWN_PENDING == frozenset(COLLECTION_PENDING) | frozenset(NORMALIZATION_PENDING)


# ── dead templates must be declared AND correctly classified ─────────────────
def test_no_new_dead_templates():
    # Every kind a signature references is either EMITTED by a producer or a
    # DECLARED gap. A new signature requiring an unemitted, undeclared kind
    # fails here — decide its class: no collector observes it → COLLECTION_PENDING;
    # a collector observes it but nothing maps it → NORMALIZATION_PENDING
    # (and prefer fixing the normalizer over declaring).
    unexpected = dead_template_kinds(CAT) - KNOWN_PENDING
    assert not unexpected, (
        f"signature(s) require kinds no producer emits and no ledger declares: "
        f"{sorted(unexpected)} — add the producer/normalizer, or declare the gap "
        f"in COLLECTION_PENDING or NORMALIZATION_PENDING with a ticket."
    )


def test_normalization_pending_entries_are_gated():
    # A normalization gap is a bug-in-waiting (data exists, RCA path dark), so
    # every entry must be a complete, evidenced, ticketed temporary allow.
    # Anything less fails CI with the vocabulary-mismatch message.
    problems: list[str] = []
    for kind, entry in NORMALIZATION_PENDING.items():
        missing = [f for f in _NORM_FIELDS if not entry.get(f)]
        if missing:
            problems.append(f"{kind}: missing metadata {missing}")
        if entry.get("ticket") in (None, "", "TODO"):
            problems.append(f"{kind}: no real ticket reference — not allowed to linger")
    assert not problems, (
        "NORMALIZATION_PENDING entries are under-documented:\n  "
        + "\n  ".join(problems)
        + "\n\n"
        + "\n".join(normalization_gap_message(k) for k in NORMALIZATION_PENDING)
    )


def test_collection_pending_entries_have_metadata():
    # Collection gaps are allowed (catalog deliberately leads ingestion) but
    # never anonymous: each carries reason + ticket, and producer must be None
    # (if a producer observes it, it's a normalization gap — move it).
    problems: list[str] = []
    for kind, entry in COLLECTION_PENDING.items():
        if not entry.get("reason") or not entry.get("ticket") or not entry.get("date_added"):
            problems.append(f"{kind}: incomplete metadata {entry}")
        if entry.get("producer") is not None:
            problems.append(
                f"{kind}: names producer {entry['producer']!r} — an observed "
                f"phenomenon is a NORMALIZATION gap, not a collection gap; move it."
            )
    assert not problems, "COLLECTION_PENDING problems:\n  " + "\n  ".join(problems)


def test_pending_ledgers_are_not_stale():
    # A declared-pending kind that is actually emitted now must be removed
    # (keeps the ledgers honest as producers land — this exact check forced
    # synthetic_http_fail out after #98). One no signature references: same.
    stale_emitted = KNOWN_PENDING & EMITTED_KINDS
    assert not stale_emitted, (
        f"pending ledgers list now-emitted kinds (remove them): {sorted(stale_emitted)}"
    )
    unreferenced = KNOWN_PENDING - consumed_kinds(CAT)
    assert not unreferenced, (
        f"pending ledgers list kinds no signature references (remove them): {sorted(unreferenced)}"
    )


# ── orphan producers ──────────────────────────────────────────────────────────
def test_no_orphan_producer_kinds():
    # Every emitted kind must be consumed by a signature or declared an
    # intentional blind spot — otherwise collection effort feeds nothing.
    orphans = orphan_producer_kinds(CAT)
    assert not orphans, (
        f"producer kind(s) emitted but consumed by NO reasoning path and not "
        f"declared in INTENTIONAL_BLIND: {sorted(orphans)} — author a signature, "
        f"wire a consumer, or declare the blind spot with a reason."
    )


def test_intentional_blind_entries_are_documented_and_live():
    for kind, entry in INTENTIONAL_BLIND.items():
        assert entry.get("reason") and entry.get("owner") and entry.get("date_added"), (
            f"INTENTIONAL_BLIND[{kind}] must carry reason/owner/date_added"
        )
        # A declared blind spot for a kind nothing emits is a stale entry.
        assert kind in EMITTED_KINDS, (
            f"INTENTIONAL_BLIND lists {kind!r} which no producer emits — remove it"
        )


def test_device_alarm_is_an_intentional_blind_spot():
    # The generic-alarm catch-all is emitted and consumed by NO signature — by
    # design (it only grounds/enriches). It must therefore NOT appear as a blind
    # spot needing a signature.
    assert "device_alarm" in EMITTED_KINDS
    assert "device_alarm" not in blind_spot_kinds(CAT)
    assert classify_kind("device_alarm", CAT) == "intentional_blind"


# ── classification & report ───────────────────────────────────────────────────
def test_classify_kind_covers_every_contract_kind():
    valid = {
        "fully_connected", "collection_pending", "normalization_pending",
        "orphan_producer", "dead_template", "intentional_blind",
    }
    for kind in EMITTED_KINDS | consumed_kinds(CAT):
        c = classify_kind(kind, CAT)
        assert c in valid, f"{kind} classified as {c!r}"


def test_classification_examples_hold():
    # The #98 lane end-to-end: semantic synthetic kinds are emitted AND consumed.
    assert classify_kind("synthetic_http_fail", CAT) == "fully_connected"
    assert classify_kind("synthetic_tls_fail", CAT) == "fully_connected"
    # Vocabulary mismatches surface as normalization, not collection:
    assert classify_kind("tls_handshake_fail", CAT) == "normalization_pending"
    assert classify_kind("probe_latency_departure", CAT) == "normalization_pending"
    # True collection gaps stay collection:
    assert classify_kind("dns_failure_rate", CAT) == "collection_pending"
    assert classify_kind("config_change", CAT) == "collection_pending"
    # …and the #98 P5 app-edge lane made the LB vocabulary real:
    assert classify_kind("lb_5xx", CAT) == "fully_connected"
    assert classify_kind("lb_4xx_high", CAT) == "intentional_blind"


def test_normalization_gap_message_is_explicit():
    msg = normalization_gap_message("tls_handshake_fail")
    assert "NORMALIZATION gap" in msg and "not a collection gap" in msg
    assert "synthetic_tls_fail" in msg  # names where the phenomenon already flows


def test_coverage_report_shape():
    rep = coverage_report(CAT)
    # original keys preserved (healthz/CI-log consumers) …
    for key in ("emitted_kinds", "consumed_kinds", "dead_template_kinds",
                "pending_dead_templates", "blind_spot_kinds"):
        assert key in rep, key
    # … plus the classified views.
    for key in ("kind_classes", "fully_connected", "collection_pending",
                "normalization_pending", "orphan_producer", "dead_template",
                "intentional_blind"):
        assert key in rep, key
    assert "device_alarm" in rep["emitted_kinds"]
    assert rep["orphan_producer"] == []
    assert rep["dead_template"] == []
    # every dead-template kind is accounted for by exactly the two ledgers
    assert set(rep["dead_template_kinds"]) == (
        set(rep["collection_pending"]) | set(rep["normalization_pending"])
    )
