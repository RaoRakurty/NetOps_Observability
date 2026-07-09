"""#99 R5 — cross-language ProbeEvent wire contract (Python side).

One checked-in artifact (src/contracts/probe_event_wire.json) that the Go
collector must MARSHAL to and this consumer must NORMALIZE from. If either
side drifts — a renamed field, a type change — exactly one of the two CIs
breaks against the same file, instead of both sides silently pinning their
own idea of the wire.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from golden_wire import normalize_probe_event
from signals import ModalityClass

CONTRACT = json.loads(
    (Path(__file__).parent.parent / "contracts" / "probe_event_wire.json").read_text()
)
NOW = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)


def test_canonical_wire_event_normalizes_exactly_as_contracted():
    ev, want = CONTRACT["event"], CONTRACT["expected_semantic"]
    signals = normalize_probe_event(ev, "acme", NOW)
    sem = [s for s in signals if s.kind == want["kind"]]
    assert len(sem) == 1, f"expected exactly one {want['kind']} signal, got {[s.kind for s in signals]}"
    sig = sem[0]
    assert sig.attrs["reason"] == want["reason"]
    assert sig.attrs["raw_kind"] == want["raw_kind"]
    assert sig.entity_id == want["app"]
    assert sig.modality_class is ModalityClass(want["modality"])
    # every enrichment field the contract carries must survive into attrs
    for key in ("status_code", "method", "path", "dns_ms", "tcp_connect_ms",
                "tls_ms", "ttfb_ms", "total_ms", "cert_days_to_expiry",
                "cert_subject", "cert_issuer", "fail_class"):
        assert sig.attrs.get(key) == ev[key], key
    assert f"site:{ev['site_id']}" in sig.entity_tokens
