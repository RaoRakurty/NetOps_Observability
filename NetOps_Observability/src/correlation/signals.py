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

# Grounding-token guard (#99 R2): token prefixes that scope WIDER than one
# entity. See Signal.__post_init__ — constructing a signal with one of these
# in entity_tokens dead-letters loudly (tests and CI included).
_FORBIDDEN_TOKEN_PREFIXES: frozenset[str] = frozenset({"tenant", "org", "global", "all"})


class Source(str, Enum):
    FLOW = "flow"
    PROBE = "probe"
    METRIC = "metric"
    ALERT = "alert"
    TOPOLOGY = "topology"
    SYSLOG = "syslog"
    TRAP = "trap"
    SOT_DRIFT = "sot_drift"
    CLOUD = "cloud"  # #81 P3G: Cloud App Observability plane (cloud APIs + cloud logs)
    APP_IDENTITY = "app_identity"  # #81 P5: fused application identity (enrichment, not a fault)
    CONTROLLER = "controller"  # NMS: vendor-controller intelligence (Meraki/vManage/Catalyst/…)


class ObserverType(str, Enum):
    DEVICE = "device"
    VANTAGE_AGENT = "vantage_agent"
    CLOUD_API = "cloud_api"
    FLOW_EXPORTER = "flow_exporter"
    PLATFORM = "platform"
    CONTROLLER = "controller"  # NMS: a vendor management controller as the witness


class ModalityClass(str, Enum):
    ACTIVE_PROBE = "active_probe"
    PASSIVE_FLOW = "passive_flow"
    CONTROL_PLANE = "control_plane"
    DEVICE_TELEMETRY = "device_telemetry"
    # NMS: a distinct modality so the independence gate treats a controller as a
    # corroborating-but-not-confirming plane (controller-alone caps at suspected).
    MANAGEMENT_PLANE = "management_plane"


class EntityType(str, Enum):
    DEVICE = "device"
    INTERFACE = "interface"
    PATH = "path"
    SEGMENT = "segment"
    SITE = "site"
    SERVICE = "service"
    PREFIX = "prefix"
    APP = "app"                       # #81 P3G: an application (cloud-app observability)
    CLOUD_RESOURCE = "cloud_resource"  # #81 P3G: a cloud resource (ELB/RDS/ECS/…)


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    HIGH = "high"
    CRIT = "crit"


# ── Probe authority & independence model (#67 Step 3) ────────────────────────
# Active-probe evidence is LEGITIMATE (ThousandEyes/Catchpoint/Datadog/Kentik all
# treat synthetic tests as real monitoring). The trust distinction is vantage,
# intent and INDEPENDENCE — NOT "synthetic vs real". See docs/design/
# probe-authority-model.md. Authority is DERIVED from (intent × vantage); the
# 4-way probe_scope is only a UI projection.


class ProbeIntent(str, Enum):
    CUSTOMER_PATH = "customer_path"            # a real user/customer route
    SERVICE_DEPENDENCY = "service_dependency"  # a real upstream/SaaS dependency
    PLATFORM_SELF_CHECK = "platform_self_check"  # the platform watching its own infra
    LAB_TEST = "lab_test"                      # synthetic/lab generator traffic
    UNKNOWN = "unknown"


class VantageType(str, Enum):
    PUBLIC_CLOUD_AGENT = "public_cloud_agent"  # vendor-operated, globally distributed
    ENTERPRISE_AGENT = "enterprise_agent"      # inside the customer org
    ENDPOINT_AGENT = "endpoint_agent"          # user-side
    PRIVATE_LOCATION = "private_location"      # customer's private endpoint runner
    INTERNAL_COLLECTOR = "internal_collector"  # the platform's own collector
    LOCAL_CONTAINER = "local_container"        # a co-located lab/test container
    UNKNOWN = "unknown"


class ProbeAuthority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEBUG_ONLY = "debug_only"


class ProbeScope(str, Enum):
    """UI-friendly projection of (intent, vantage) — NOT the source of truth."""

    CUSTOMER_PATH = "customer_path"
    SERVICE_DEPENDENCY = "service_dependency"
    INTERNAL_SELF_PROBE = "internal_self_probe"
    SYNTHETIC_LAB_PROBE = "synthetic_lab_probe"
    UNKNOWN = "unknown"


# Authorities that MAY anchor a confirmed verdict (always still + another modality).
CONFIRM_AUTHORITIES = frozenset({ProbeAuthority.HIGH, ProbeAuthority.MEDIUM})

_REAL_USER_VANTAGES = frozenset({
    VantageType.ENTERPRISE_AGENT, VantageType.ENDPOINT_AGENT, VantageType.PRIVATE_LOCATION,
})
_REAL_VANTAGES = _REAL_USER_VANTAGES | {VantageType.PUBLIC_CLOUD_AGENT}


def derive_probe_authority(intent: ProbeIntent, vantage: VantageType) -> ProbeAuthority:
    """(intent × vantage) → authority. Fail-closed: anything not positively a
    real, sufficiently-trusted vantage degrades to LOW — never confirm-capable."""
    if intent is ProbeIntent.LAB_TEST or vantage is VantageType.LOCAL_CONTAINER:
        return ProbeAuthority.DEBUG_ONLY
    if intent is ProbeIntent.PLATFORM_SELF_CHECK or vantage is VantageType.INTERNAL_COLLECTOR:
        return ProbeAuthority.LOW
    if intent is ProbeIntent.CUSTOMER_PATH and vantage in _REAL_USER_VANTAGES:
        return ProbeAuthority.HIGH
    if intent is ProbeIntent.CUSTOMER_PATH and vantage is VantageType.PUBLIC_CLOUD_AGENT:
        return ProbeAuthority.MEDIUM
    if intent is ProbeIntent.SERVICE_DEPENDENCY and vantage in _REAL_VANTAGES:
        return ProbeAuthority.MEDIUM
    return ProbeAuthority.LOW


def derive_probe_scope(intent: ProbeIntent, vantage: VantageType) -> ProbeScope:
    """The UI label (projection). Source of truth is intent/vantage/authority."""
    if intent is ProbeIntent.CUSTOMER_PATH:
        return ProbeScope.CUSTOMER_PATH
    if intent is ProbeIntent.SERVICE_DEPENDENCY:
        return ProbeScope.SERVICE_DEPENDENCY
    if intent is ProbeIntent.PLATFORM_SELF_CHECK or vantage is VantageType.INTERNAL_COLLECTOR:
        return ProbeScope.INTERNAL_SELF_PROBE
    if intent is ProbeIntent.LAB_TEST or vantage is VantageType.LOCAL_CONTAINER:
        return ProbeScope.SYNTHETIC_LAB_PROBE
    return ProbeScope.UNKNOWN


@dataclass(frozen=True)
class ProbeFate:
    """The fate-sharing fingerprint of a probe. Two probes that share an agent
    host, a NAT/public egress, or a (seam, target, schedule) are NOT independent —
    they share a failure path and must not corroborate each other (§2)."""

    agent_host: str = ""      # agent_id or host_id / VM / container
    source_egress: str = ""   # NAT / public egress IP
    seam_id: str = ""
    target: str = ""
    schedule_id: str = ""

    def shares_fate_with(self, other: "ProbeFate") -> bool:
        if self.agent_host and self.agent_host == other.agent_host:
            return True
        if self.source_egress and self.source_egress == other.source_egress:
            return True
        if (self.seam_id and self.seam_id == other.seam_id
                and self.target and self.target == other.target
                and self.schedule_id and self.schedule_id == other.schedule_id):
            return True
        return False


def probe_authority_of(sig: "Signal") -> "ProbeAuthority | None":
    """A signal's derived probe authority (None for non-probe). Reads the field
    enriched at ingestion; fail-closed to LOW for an unclassified probe."""
    if sig.modality_class is not ModalityClass.ACTIVE_PROBE:
        return None
    raw = str(sig.attrs.get("probe_authority", "")) if isinstance(sig.attrs, dict) else ""
    try:
        return ProbeAuthority(raw) if raw else ProbeAuthority.LOW
    except ValueError:
        return ProbeAuthority.LOW


# ── Observer kind (evidence-accounting Phase B) ──────────────────────────────
# An ADDITIVE ingest hint stamped on every new signal so the accounting layer can
# say how many logical vantages vs control-plane sources vs collectors an incident
# rests on. Backward-compatible: legacy rows carry no `observer_kind` and are
# classified by the Go registry at READ time; the per-tenant structured policy is
# canonical — this hint is only the default. Hard rules (rca-evidence-accounting-
# plan.md constraint 1): `api`/collectors/workers are NEVER logical_vantage;
# unclassified → `unknown` (never silently a collector or vantage).

OBSERVER_KIND_LOGICAL_VANTAGE = "logical_vantage"
OBSERVER_KIND_CONTROL_PLANE = "control_plane_source"
OBSERVER_KIND_COLLECTOR = "collector"
OBSERVER_KIND_UNKNOWN = "unknown"

# Identities that can NEVER be a logical vantage (mirrors the Go registry defaults).
_NEVER_VANTAGE_IDS = frozenset({
    "api", "backend", "correlation", "collector",
    "vector", "telegraf", "goflow", "goflow2",
    "snmp", "gnmi", "netconf", "syslog", "otel", "otel-collector",
})
_NEVER_VANTAGE_MARKERS = ("-worker", "worker-", "collector", "-exporter", "exporter-",
                          "-poller", "poller-", "sidecar")


def _is_never_vantage(observer_id: str) -> bool:
    oid = (observer_id or "").strip().lower()
    if oid in _NEVER_VANTAGE_IDS:
        return True
    return any(m in oid for m in _NEVER_VANTAGE_MARKERS)


def classify_observer_kind(
    observer_id: str, observer_type: "ObserverType | str",
    modality: "ModalityClass | str", probe_authority: str = "",
) -> str:
    """Default observer-kind hint from provenance. Fail-closed (constraint 1):
    a low/debug/unclassified probe is `unknown`, never assumed a vantage; a
    denylisted identity is never a vantage. The Go per-tenant registry may
    override this hint at read, but never to violate the never-vantage rule."""
    mod = modality.value if isinstance(modality, ModalityClass) else str(modality or "").strip().lower()
    if mod in ("control_plane", "management_plane"):
        return OBSERVER_KIND_CONTROL_PLANE
    if mod in ("device_telemetry", "passive_flow"):
        return OBSERVER_KIND_COLLECTOR
    if mod == "active_probe":
        if _is_never_vantage(observer_id):
            return OBSERVER_KIND_COLLECTOR
        if (probe_authority or "").strip().lower() in ("high", "medium"):
            return OBSERVER_KIND_LOGICAL_VANTAGE
        return OBSERVER_KIND_UNKNOWN
    return OBSERVER_KIND_UNKNOWN


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
        # Grounding-token guard (#99 R2): entity_tokens are the engine's
        # CO-LOCATION keys and the correlation window is single-tenant by
        # construction — a tenant-/org-wide token merges UNRELATED entities into
        # one object (the cross-app confirmed-object bug, tracker #99). Enforced
        # at the model so the bug class is unwritable by any producer. Gated to
        # fresh constructions: rows stored before this rule still rehydrate for
        # replay (from_ch_row sets stored_signal_id).
        if self.stored_signal_id is None:
            for tok in self.entity_tokens:
                prefix = tok.split(":", 1)[0].lower()
                if prefix in _FORBIDDEN_TOKEN_PREFIXES and ":" in tok:
                    raise DeadLetter(
                        f"entity_token {tok!r} is {prefix}-wide — grounding tokens "
                        f"must identify ONE entity (app:/host:/site:/device:/…), "
                        f"never a tenant/org/global scope"
                    )

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
        # Additive observer-kind hint (evidence-accounting Phase B). Stamped into
        # attrs — no schema change — so NEW signals carry their default kind while
        # legacy rows classify at read. Never overrides a value a producer already
        # set. The signal_id is unaffected (it derives from source|native_id|ts).
        attrs = self.attrs if isinstance(self.attrs, dict) else {}
        if "observer_kind" not in attrs:
            attrs = dict(attrs)
            attrs["observer_kind"] = classify_observer_kind(
                self.observer.observer_id, self.observer.observer_type,
                self.modality_class, str(attrs.get("probe_authority", "")),
            )
        attrs_json = json.dumps(attrs, separators=(",", ":"), sort_keys=True)
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


def _parse_ch_dt(s) -> datetime:
    """Parse a ClickHouse DateTime64(3) value back to tz-aware UTC. Accepts the
    zone-less SELECT string ("2026-07-16 21:56:03.562", UTC by contract), the
    RFC 3339 wire form (S3), and the scaled-integer epoch-ms insert form (S4) —
    so from_ch_row round-trips rows read from ClickHouse AND rows built
    in-process by to_ch_row."""
    if isinstance(s, (int, float)):
        ms = int(s)
        return datetime.fromtimestamp(ms // 1000, tz=timezone.utc).replace(
            microsecond=(ms % 1000) * 1000)
    s = str(s).strip()
    if s.lstrip("-").isdigit():
        return _parse_ch_dt(int(s))
    s = s.replace("T", " ").rstrip("Z")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)


def _ch_dt(dt: datetime) -> int:
    """UTC epoch **milliseconds** for a DateTime64(3) insert (log-time standard
    S4/R1). ClickHouse treats an inserted integer as an appropriately *scaled*
    Unix timestamp in UTC, so unlike a zone-less string the value can never be
    re-interpreted in the server/column timezone. Truncates to ms exactly like
    the old strftime()[:-3] string form."""
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 1000 + dt.microsecond // 1000
