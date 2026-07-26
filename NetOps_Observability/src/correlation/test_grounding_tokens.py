"""#99 R2 — grounding-token guard: tenant-/org-wide values can never enter
entity_tokens (the engine's co-location keys). Model-level, so the cross-app
over-grounding bug class (tracker #99) is unwritable by ANY producer."""
from datetime import datetime, timezone

import pytest

from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

NOW = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)


def make(tokens):
    return Signal(
        tenant_id="acme", ts=NOW, source=Source.PROBE, kind="synthetic_http_fail",
        observer=Observer(observer_id="syn-1", observer_type=ObserverType.VANTAGE_AGENT,
                          collection_path="direct"),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.APP,
        entity_id="app_x", severity=Severity.HIGH, native_id="t|1",
        entity_tokens=tuple(tokens),
    )


@pytest.mark.parametrize("bad", ["tenant:acme", "org:org_1", "global:all", "TENANT:acme"])
def test_tenant_wide_tokens_are_rejected(bad):
    with pytest.raises(DeadLetter, match="grounding tokens"):
        make([bad, "app:app_x"])


def test_entity_scoped_tokens_are_accepted():
    sig = make(["app_x", "app:app_x", "host:portal.acme.example", "site:frisco",
                "device:leaf1", "lb:edge-lb-01", "backend_pool:pool1",
                "target:https://a/b", "10.40.17.1", "db.example:5432"])
    assert sig.entity_tokens
