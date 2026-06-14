"""Canonical Signal — pipeline stage [1] of Correlation Engine v2 (#67).

Every record the engine consumes becomes exactly one Signal in the frozen
corr_signals schema (docs/design/correlation-engine.md §2.1), or is dead-
lettered. Two invariants live here:

  * **Deterministic identity** — signal_id = UUIDv5(NS, source|native_id|ts_ms),
    so reprocessing the same input yields the same id: the foundation of
    replay and idempotent inserts.
  * **Mandatory observer block** — confirmation depends on observer
    independence (§4.5), so a Signal without observer_id / modality_class is
    REJECTED (dead-letter), never guessed.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# UUIDv5 namespace for signal identity. Fixed forever — changing it would break
# replay determinism for all stored objects.
SIGNAL_NS = uuid.UUID("6e1f8c3a-67aa-5b9e-9d40-8a52c0de0001")

ATTRS_MAX_BYTES = 4096  # §2.1: attrs JSON bounded


class Source(str, Enum):
    FLOW = "flow"
    PROBE = "probe"
    METRIC = "metric"
    ALERT = "alert"
    TOPOLOGY = "topology"
    SYSLOG = "syslog"
    TRAP = "trap"
    SOT_DRIFT = "sot_drift"


class ObserverType(str, Enum):
    DEVICE = "device"
    VANTAGE_AGENT = "vantage_agent"
    CLOUD_API = "cloud_api"
    FLOW_EXPORTER = "flow_exporter"
    PLATFORM = "platform"


class ModalityClass(str, Enum):
    ACTIVE_PROBE = "active_probe"
    PASSIVE_FLOW = "passive_flow"
    CONTROL_PLANE = "control_plane"
    DEVICE_TELEMETRY = "device_telemetry"


class EntityType(str, Enum):
    DEVICE = "device"
    INTERFACE = "interface"
    PATH = "path"
    SEGMENT = "segment"
    SITE = "site"
    SERVICE = "service"
    PREFIX = "prefix"


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    HIGH = "high"
    CRIT = "crit"


class DeadLetter(ValueError):
    """Record cannot become a Signal (missing mandatory provenance, malformed
    fields). Counted + parked by the caller — never guessed around, never a
    crash."""


@dataclass(frozen=True)
class Observer:
    """WHO measured it — the evidence-independence gate's input (§4.5).

    collection_path feeds fate-sharing analysis: two signals arriving
    via the same controller are NOT independent observers.
    """

    observer_id: str
    observer_type: ObserverType
    location: str = ""
    trust_domain: str = ""                 # enterprise | cloud_tenant | platform
    collection_path: str = "direct"        # direct|via_controller|via_cloud_api|via_aggregator
    clock_quality: str = "unknown"         # ntp|ptp|free_running|unknown

    def __post_init__(self) -> None:
        if not self.observer_id:
            raise DeadLetter("observer_id is mandatory (independence gate)")


@dataclass(frozen=True)
class Signal:
    tenant_id: str
    ts: datetime                      # event time (source clock), tz-aware UTC
    source: Source
    kind: str                         # e.g. probe_loss, if_errors, metric_anomaly
    observer: Observer
    modality_class: ModalityClass
    entity_type: EntityType
    entity_id: str
    severity: Severity
    native_id: str                    # source-native identity → deterministic signal_id
    entity_tokens: tuple[str, ...] = ()
    site: str = ""
    path_id: str | None = None
    service_id: str | None = None
    metric_name: str = ""
    value: float = 0.0
    baseline: float = 0.0
    deviation: float = 0.0
    attrs: dict = field(default_factory=dict)
    # Set ONLY by from_ch_row: a rehydrated signal keeps its stored identity
    # verbatim, so replay compares the same ids the snapshot was built from.
    stored_signal_id: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not self.kind:
            raise DeadLetter("kind is mandatory")
        if not self.entity_id:
            raise DeadLetter("entity_id is mandatory")
        if self.ts.tzinfo is None:
            raise DeadLetter("ts must be timezone-aware (event-time discipline)")

    @property
    def signal_id(self) -> uuid.UUID:
        """Deterministic: same (source, native_id, event time) ⇒ same id.
        Rehydrated signals return their stored id (identity round-trip)."""
        if self.stored_signal_id:
            return uuid.UUID(self.stored_signal_id)
        ts_ms = int(self.ts.timestamp() * 1000)
        return uuid.uuid5(SIGNAL_NS, f"{self.source.value}|{self.native_id}|{ts_ms}")

    def to_ch_row(self) -> dict:
        """JSONEachRow shape for netops.corr_signals (frozen schema)."""
        attrs_json = json.dumps(self.attrs, separators=(",", ":"), sort_keys=True)
        if len(attrs_json.encode()) > ATTRS_MAX_BYTES:
            # Bounded by design: oversize attrs are a producer bug, not data.
            raise DeadLetter(f"attrs exceed {ATTRS_MAX_BYTES} bytes")
        return {
            "tenant_id": self.tenant_id,
            "signal_id": str(self.signal_id),
            "ts": _ch_dt(self.ts),
            "source": self.source.value,
            "kind": self.kind,
            "observer_id": self.observer.observer_id,
            "observer_type": self.observer.observer_type.value,
            "observer_location": self.observer.location,
            "observer_trust_domain": self.observer.trust_domain,
            "collection_path": self.observer.collection_path,
            "modality_class": self.modality_class.value,
            "source_clock_quality": self.observer.clock_quality,
            "entity_type": self.entity_type.value,
            "entity_id": self.entity_id,
            "entity_tokens": list(self.entity_tokens),
            "site": self.site,
            "path_id": self.path_id,
            "service_id": self.service_id,
            "severity": self.severity.value,
            "metric_name": self.metric_name,
            "value": self.value,
            "baseline": self.baseline,
            "deviation": self.deviation,
            "attrs": attrs_json,
        }


    @classmethod
    def from_ch_row(cls, row: dict) -> "Signal":
        """Inverse of to_ch_row — rehydrates a Signal from a corr_signals /
        corr_signals_archive row (the replay input). Round-trip invariant:
        Signal.from_ch_row(s.to_ch_row()).to_ch_row() == s.to_ch_row(), so a
        replay consumes byte-identical evidence."""
        attrs_raw = row.get("attrs") or "{}"
        attrs = json.loads(attrs_raw) if isinstance(attrs_raw, str) else dict(attrs_raw)
        return cls(
            tenant_id=str(row.get("tenant_id", "")),
            ts=_parse_ch_dt(str(row["ts"])),
            source=Source(str(row["source"])),
            kind=str(row["kind"]),
            observer=Observer(
                observer_id=str(row["observer_id"]),
                observer_type=ObserverType(str(row["observer_type"])),
                location=str(row.get("observer_location", "")),
                trust_domain=str(row.get("observer_trust_domain", "")),
                collection_path=str(row.get("collection_path", "direct")),
                clock_quality=str(row.get("source_clock_quality", "unknown")),
            ),
            modality_class=ModalityClass(str(row["modality_class"])),
            entity_type=EntityType(str(row["entity_type"])),
            entity_id=str(row["entity_id"]),
            severity=Severity(str(row["severity"])),
            native_id="rehydrated",   # identity comes from stored_signal_id
            entity_tokens=tuple(row.get("entity_tokens") or ()),
            site=str(row.get("site", "")),
            path_id=row.get("path_id") or None,
            service_id=row.get("service_id") or None,
            metric_name=str(row.get("metric_name", "")),
            value=float(row.get("value", 0.0)),
            baseline=float(row.get("baseline", 0.0)),
            deviation=float(row.get("deviation", 0.0)),
            attrs=attrs,
            stored_signal_id=str(row["signal_id"]),
        )


def _parse_ch_dt(s: str) -> datetime:
    """Parse a ClickHouse DateTime64(3) string back to tz-aware UTC."""
    s = s.strip().replace("T", " ")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)


def _ch_dt(dt: datetime) -> str:
    """ClickHouse DateTime64(3) literal, millisecond precision, UTC."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
