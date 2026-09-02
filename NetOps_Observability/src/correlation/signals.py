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
import logging
import os
import re
import uuid
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

log = logging.getLogger("correlation.signals")

# UUIDv5 namespace for signal identity. Fixed forever — changing it would break
# replay determinism for all stored objects.
SIGNAL_NS = uuid.UUID("6e1f8c3a-67aa-5b9e-9d40-8a52c0de0001")

ATTRS_MAX_BYTES = 4096  # §2.1: attrs JSON bounded

# ── Untrusted-string caps (audit PIPE-MED-11 / FUNC-MED-8) ────────────────────
#
# The intake validated the SHAPE of a producer record ("entity_id is mandatory")
# but never its SIZE. Every string below lands in a ClickHouse String column, an
# OpenSearch document or — via the metric lane — a VictoriaMetrics LABEL, and all
# three degrade badly under unbounded input: a distinct label value is a distinct
# time series (a cardinality bomb reachable from a device or an HTTP header), and
# an unbounded String column is unbounded row/part width.
#
# The cap is applied by FIELD CLASS at the MODEL boundary — Signal/Observer
# __post_init__ — not per producer, so a new producer inherits the bound instead
# of having to remember it. Truncation is deterministic and idempotent: capping an
# already-capped value is a no-op, so a replayed signal never drifts.
MAX_ID_CHARS = 256      # identity class: entity_id, native_id, kind, grounding tokens
MAX_LABEL_CHARS = 128   # label class: site, metric_name, observer fields, path/service id
MAX_TEXT_CHARS = 512    # free-text class: message / reason / uri — context, not identity
MAX_TOKENS = 32         # entity_tokens CARDINALITY: co-location keys, never a bulk list

# Observability counter (§10): truncation is never silent. Every bound applied is
# counted here and logged once at WARNING, so "the field was cut" is a fact the
# operator can see rather than a difference they have to notice in the data.
TRUNCATIONS = 0


def _count_truncation(where: str, field_name: str, was: int, now: int) -> None:
    global TRUNCATIONS
    TRUNCATIONS += 1
    log.warning("bounded oversize %s.%s: %d → %d chars (untrusted-string cap)",
                where, field_name, was, now)


def cap_str(value: object, limit: int = MAX_LABEL_CHARS, *,
            where: str = "signal", field_name: str = "?") -> str:
    """Bound one untrusted string to `limit` characters, counting + logging when
    it actually had to cut. Non-strings are coerced (a producer may hand us an int
    or None); the empty string is returned unchanged."""
    s = value if isinstance(value, str) else ("" if value is None else str(value))
    if len(s) <= limit:
        return s
    _count_truncation(where, field_name, len(s), limit)
    return s[:limit]


def cap_id(value: object, *, where: str = "signal", field_name: str = "?") -> str:
    """Identity class — entity ids, native ids, grounding tokens."""
    return cap_str(value, MAX_ID_CHARS, where=where, field_name=field_name)


def cap_label(value: object, *, where: str = "signal", field_name: str = "?") -> str:
    """Label class — anything that can become a metric label or a keyword field."""
    return cap_str(value, MAX_LABEL_CHARS, where=where, field_name=field_name)


def cap_text(value: object, *, where: str = "signal", field_name: str = "?") -> str:
    """Free-text class — human context stored for reading, never joined on."""
    return cap_str(value, MAX_TEXT_CHARS, where=where, field_name=field_name)


# MAC / BSSID shape. Wireless intake accepted ANY non-empty string as a client MAC
# or BSSID — an attacker-controlled identity column and a per-value cardinality
# bomb. Normalization is DEFAULT-CLOSED: anything that is not 12 hex nibbles is
# NOT a MAC, so it is rejected (empty string) rather than stored as pseudo-identity.
_MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: object) -> str:
    """Canonical lowercase `aa:bb:cc:dd:ee:ff`, or "" when the input is not a MAC.

    Accepts the three separator conventions devices and controllers actually emit
    (`:` colon, `-` dash, `.` Cisco dotted-quad) plus bare hex. Default-closed:
    a malformed value returns "" — the caller must decide what an unidentifiable
    client means, and can no longer silently persist 4 KB of attacker text into a
    `client_mac` column."""
    s = (value if isinstance(value, str) else "").strip().lower()
    if len(s) > 64:   # bound BEFORE the regex: no unbounded scan on hostile input
        return ""
    s = s.replace(":", "").replace("-", "").replace(".", "").replace(" ", "")
    return ":".join(s[i:i + 2] for i in range(0, 12, 2)) if _MAC_HEX_RE.match(s) else ""

# Grounding-token guard (#99 R2): token prefixes that scope WIDER than one
# entity. See Signal.__post_init__ — constructing a signal with one of these
# in entity_tokens dead-letters loudly (tests and CI included).
# ssid/wlan (#128 Q2, owner-approved 2026-07-26): an SSID is broadcast by every
# AP in the estate — as a grounding token it would weld every unrelated
# wireless incident into one object, the exact #99 bug class this guard exists
# for. SSID/WLAN are filters and display groupings, never co-location evidence.
_FORBIDDEN_TOKEN_PREFIXES: frozenset[str] = frozenset(
    {"tenant", "org", "global", "all", "ssid", "wlan"})


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
    VERIFICATION = "verification"  # RCA spec item 8: active-verification check battery results
    AUDIT = "audit"  # item 121: operator/API actions mirrored onto the spine (audit→feed bridge)
    # T2b generic EVIDENCE-CLASS bus lane. One value per registered evidence
    # class (see EVIDENCE_CLASSES below) — the wire lane a verdict arrived on,
    # exactly as CLOUD names the cloud lane and CONTROLLER the NMS lane. It is
    # DATA, not a code path: the engine has no branch on it, and deleting the
    # producing module leaves an unused enum value, nothing to unwind.
    SECURITY = "security"


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
    # Active Verification (RCA spec item 8): the platform interrogates an
    # implicated device with a bounded READ-ONLY check battery and the device's
    # own answer enters as evidence. A DISTINCT modality so the independence
    # gate can count a device answer as a second source against a probe/flow —
    # while observer identity (the answering device itself) still blocks a
    # device from corroborating its own passive telemetry.
    ACTIVE_VERIFICATION = "active_verification"
    # A VERDICT plane: a rule/benchmark/advisory evaluated against captured
    # state or a feed, not a measurement taken on the wire. It is its OWN
    # modality so the independence gate treats it as a corroborating-but-not-
    # confirming plane exactly like MANAGEMENT_PLANE: a verdict alone can never
    # reach confirmed, and confirmation always needs a second, independently
    # measured plane (control_plane / device_telemetry / passive_flow /
    # active_probe). Distinct from MANAGEMENT_PLANE because a scanner and a
    # vendor controller are not one witness — they can corroborate each other.
    SECURITY = "security"


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
    # #128 wireless (docs/Wireslessdesign.md §7.1) — CH enums extended in
    # lockstep (corr_schema.go + init.sql, TestCorrSignalEnumsConsistent).
    WIRELESS_CONTROLLER = "wireless_controller"  # the LOGICAL WLC/gateway cluster
    ACCESS_POINT = "access_point"
    RADIO = "radio"
    BSSID = "bssid"
    WLAN = "wlan"
    WIRELESS_CLIENT = "wireless_client"
    WIRELESS_SESSION = "wireless_session"


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

    def shares_fate_with(self, other: ProbeFate) -> bool:
        if self.agent_host and self.agent_host == other.agent_host:
            return True
        if self.source_egress and self.source_egress == other.source_egress:
            return True
        return bool(self.seam_id and self.seam_id == other.seam_id and self.target and self.target == other.target and self.schedule_id and self.schedule_id == other.schedule_id)


def probe_authority_of(sig: Signal) -> ProbeAuthority | None:
    """A signal's derived probe authority (None for non-probe). Reads the field
    enriched at ingestion; fail-closed to LOW for an unclassified probe."""
    if sig.modality_class is not ModalityClass.ACTIVE_PROBE:
        return None
    raw = str(sig.attrs.get("probe_authority", "")) if isinstance(sig.attrs, dict) else ""
    try:
        return ProbeAuthority(raw) if raw else ProbeAuthority.LOW
    except ValueError:
        return ProbeAuthority.LOW


# ── Parser-rule fidelity (W1b/A3) + the A7 weighting vocabulary ──────────────
#
# Every classified signal carries `attrs.fidelity`: how well-evidenced the
# GRAMMAR that produced it is. The values are the telemetry-catalog ladder plus
# the hand-written default:
#
#   doc_claimed     the rule exists because a vendor DOC says the line looks
#                   like this — nobody has seen the device emit it
#   code            the grammar lives in the rule table with a test/fixture
#                   behind it (hand-written branches, and catalog rows migrated
#                   from them). The catalog vouches for nothing extra
#   lab_validated   matched against a real device's output in a lab
#   live_validated  matched against production traffic
#
# THE WEIGHTING RULE that reads them (flag CORR_FIDELITY_WEIGHTING, default OFF)
# is stated once, in full, in the confirmability.py module header. This module
# owns only its VOCABULARY and the pure predicates over a signal set, so the
# audit's math and the runtime's cap can never drift apart.
#
# TWO CASES THAT ARE NOT THE SAME (and the reason `fidelity_of` returns ""):
#   * ABSENT — a metric episode, a probe, a flow, a cloud API record: no parser
#     ran, so the signal makes NO fidelity claim. It is NOT doc_claimed, and it
#     is treated exactly as it is today (this is what keeps the flag-OFF path
#     and every non-syslog lane byte-identical).
#   * PRESENT BUT UNREADABLE — a lane stamped a value outside the ladder. That
#     IS a claim, and one we cannot read, so it fails closed to unvalidated: it
#     may support a suspicion, never anchor a confirmation.
FIDELITY_DOC_CLAIMED = "doc_claimed"
FIDELITY_CODE = "code"
FIDELITY_LAB_VALIDATED = "lab_validated"
FIDELITY_LIVE_VALIDATED = "live_validated"

#: Weakest → strongest. `code` sits ABOVE `doc_claimed` deliberately: a
#: hand-written, tested branch is evidence of the grammar; a doc claim is not.
FIDELITY_LADDER: tuple[str, ...] = (
    FIDELITY_DOC_CLAIMED, FIDELITY_CODE,
    FIDELITY_LAB_VALIDATED, FIDELITY_LIVE_VALIDATED,
)

#: The tiers that may take part in a CONFIRMING pair. The catalog can demote a
#: row to `doc_claimed` to shadow it out of confirmation without touching code.
VALIDATED_FIDELITIES: frozenset[str] = frozenset({
    FIDELITY_CODE, FIDELITY_LAB_VALIDATED, FIDELITY_LIVE_VALIDATED,
})

_FIDELITY_RANK: dict[str, int] = {f: i for i, f in enumerate(FIDELITY_LADDER)}


def fidelity_of(sig: Signal) -> str:
    """A signal's declared parser fidelity; "" when it declares none."""
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    return str(attrs.get("fidelity", "") or "").strip()


def is_validated_fidelity(fidelity: str) -> bool:
    """May evidence with this fidelity anchor a confirming pair?

    "" (no claim) — yes, unchanged from today. A ladder tier — only the
    validated three. Anything else — no (fail closed on an unreadable claim).
    """
    return not fidelity or fidelity in VALIDATED_FIDELITIES


def validated_signals(signals: Iterable[Signal]) -> tuple[Signal, ...]:
    """The subset that may anchor a confirmation. Order preserved."""
    return tuple(s for s in signals if is_validated_fidelity(fidelity_of(s)))


def unvalidated_rule_ids(signals: Iterable[Signal]) -> tuple[str, ...]:
    """Sorted, de-duplicated ids of the RULES behind the unvalidated evidence —
    what a verdict names when fidelity held its confirmation back.

    A signal with an unvalidated fidelity and no `rule_id` is reported as
    ``<unknown rule>:<fidelity>`` rather than dropped: §10 — nothing about a
    capped verdict may be silent.
    """
    out: set[str] = set()
    for sig in signals:
        fidelity = fidelity_of(sig)
        if is_validated_fidelity(fidelity):
            continue
        attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
        rule_id = str(attrs.get("rule_id", "") or "").strip()
        out.add(rule_id or f"<unknown rule>:{fidelity}")
    return tuple(sorted(out))


def fidelity_min(signals: Iterable[Signal]) -> str:
    """The WEAKEST fidelity claimed in this evidence set; "" when none claims
    one. An unreadable value ranks below the whole ladder (it is the weakest
    thing an evidence set can carry), and ties break on the string so the value
    is deterministic for a given set."""
    claimed = [f for f in (fidelity_of(s) for s in signals) if f]
    if not claimed:
        return ""
    return min(claimed, key=lambda f: (_FIDELITY_RANK.get(f, -1), f))


# The flag. Read ONCE at import like every other CORR_* knob; `set_fidelity_
# weighting` is the test hook (a monkeypatched module attribute would not be
# seen by `fidelity_weighting_enabled`'s callers, which is the trap this avoids).
_FIDELITY_WEIGHTING: bool = os.environ.get(
    "CORR_FIDELITY_WEIGHTING", "0").strip().lower() in ("1", "true", "yes", "on")


def fidelity_weighting_enabled() -> bool:
    """Is A7 fidelity weighting ON? Default OFF — with it off, not one byte of
    any object moves (INVARIANTS §10/§10a)."""
    return _FIDELITY_WEIGHTING


def set_fidelity_weighting(enabled: bool) -> None:
    """Test hook: toggle the flag in-process. Production reads the env var."""
    global _FIDELITY_WEIGHTING
    _FIDELITY_WEIGHTING = bool(enabled)


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
    observer_id: str, observer_type: ObserverType | str,
    modality: ModalityClass | str, probe_authority: str = "",
) -> str:
    """Default observer-kind hint from provenance. Fail-closed (constraint 1):
    a low/debug/unclassified probe is `unknown`, never assumed a vantage; a
    denylisted identity is never a vantage. The Go per-tenant registry may
    override this hint at read, but never to violate the never-vantage rule."""
    mod = modality.value if isinstance(modality, ModalityClass) else str(modality or "").strip().lower()
    if mod in ("control_plane", "management_plane"):
        return OBSERVER_KIND_CONTROL_PLANE
    if mod in ("device_telemetry", "passive_flow", "active_verification", "security"):
        # active_verification: the witness is the answering device (or the
        # platform executor for reach probes) — never a logical vantage.
        # security (and any future evidence-class lane): the witness is the
        # platform rule/feed evaluator, never a logical vantage either.
        return OBSERVER_KIND_COLLECTOR
    if mod == "active_probe":
        if _is_never_vantage(observer_id):
            return OBSERVER_KIND_COLLECTOR
        if (probe_authority or "").strip().lower() in ("high", "medium"):
            return OBSERVER_KIND_LOGICAL_VANTAGE
        return OBSERVER_KIND_UNKNOWN
    return OBSERVER_KIND_UNKNOWN


def _shrink_attrs(attrs: dict, kind: str) -> tuple[dict, str]:
    """Bound an oversize attrs blob by TRUNCATING its longest string values —
    never by destroying the signal (audit FUNC-MED-8).

    This used to `raise DeadLetter("attrs exceed N bytes")`, which meant one
    oversize free-text field (a 5 KB syslog line, a controller's `correlation_hints`
    blob, an attacker-supplied Host header) converted a REAL event into two
    failures at once: the evidence was lost to the engine, and the whole record —
    unredacted — was written to the dead-letter queue. A cap on a context field
    must cost that field, not the event.

    So: repeatedly halve the longest offending string until the JSON fits, and
    record WHICH keys were cut in `attrs_truncated` — the truncation travels with
    the row (§10, no silent truncation). DeadLetter survives only for the case the
    original comment actually described: a blob that is still oversize once every
    string is minimal, i.e. a genuine producer bug (thousands of keys), not data.
    """
    out = dict(attrs)
    truncated: list[str] = []
    for _ in range(256):
        js = json.dumps(out, separators=(",", ":"), sort_keys=True)
        if len(js.encode()) <= ATTRS_MAX_BYTES:
            if truncated:
                log.warning("attrs truncated for kind=%s: %s (was %d bytes, cap %d)",
                            kind, ",".join(sorted(truncated)),
                            len(json.dumps(attrs, separators=(",", ":"), sort_keys=True).encode()),
                            ATTRS_MAX_BYTES)
            return out, js
        # Pick the biggest CONTRIBUTOR by encoded size, whatever its type — the
        # heaviest field is often a nested blob (a controller's correlation_hints),
        # and a string-only shrinker would spin on it and start eating the small
        # provenance keys instead.
        biggest_key, biggest_len = "", 0
        for k, v in out.items():
            if k == "attrs_truncated":
                continue
            n = len(json.dumps(v, separators=(",", ":"), sort_keys=True, default=str).encode())
            if n > biggest_len:
                biggest_key, biggest_len = k, n
        if biggest_len <= 24:
            break  # nothing left to give: the bulk is key COUNT, not any one value
        v = out[biggest_key]
        if isinstance(v, str):
            out[biggest_key] = v[:max(16, len(v) // 2)]
        else:
            # A nested structure cannot be halved meaningfully; render it to a
            # bounded string so the operator still sees WHAT was there.
            out[biggest_key] = json.dumps(
                v, separators=(",", ":"), sort_keys=True, default=str)[:MAX_TEXT_CHARS]
        if biggest_key not in truncated:
            truncated.append(biggest_key)
            _count_truncation("attrs", biggest_key, biggest_len, len(str(out[biggest_key])))
        out["attrs_truncated"] = sorted(truncated)
    raise DeadLetter(
        f"attrs exceed {ATTRS_MAX_BYTES} bytes even with every string field "
        f"truncated — this is a producer bug (too many keys), not oversize data")


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
        # Bound the observer block: observer_id is a GROUP-BY key on every
        # independence query and location/trust_domain reach the metric lane as
        # labels. A controller that reports a 4 KB observer name would otherwise
        # create one series per report (audit PIPE-MED-11).
        for f in ("observer_id", "location", "trust_domain",
                  "collection_path", "clock_quality"):
            v = getattr(self, f)
            capped = cap_label(v, where="observer", field_name=f)
            if capped != v:
                object.__setattr__(self, f, capped)


# TRACKER 156. Observers are per-DEVICE facts that repeat on every event from
# that device: one syslog line built a fresh Observer, and at the GA burst rate
# that is thousands of identical immutable objects per second, each also
# retained for as long as its Signal sits in the evidence window. Observer is a
# frozen dataclass of hashable scalars, so instances are interchangeable by
# value and one per (device, type, path, ...) is enough.
#
# Bounded on purpose (§9): a hostile or misconfigured source that varies
# observer_id per message must not turn this into an unbounded map. On overflow
# the oldest entry is evicted and construction simply falls back to a fresh
# object — the cache is an allocation optimisation, never a correctness input.
OBSERVER_CACHE_MAX = int(os.environ.get("CORR_OBSERVER_CACHE_MAX", "20000"))
_OBSERVER_CACHE: OrderedDict[tuple, Observer] = OrderedDict()
OBSERVER_CACHE_EVICTED = 0


# ── tracker 165 phase 6/7: shared identity strings on the retained path ──────
#
# A retained Signal costs ~1,012 B live, and ~18% of that is two fields whose
# VALUES repeat massively across a window: `entity_id` ("leaf17:Gi0/3") and
# `entity_tokens` (("leaf17", "Gi0/3")). At 1000 devices the window holds tens
# of thousands of signals drawn from a few tens of thousands of distinct
# entities, so most of those strings are duplicates of one another.
#
# Sharing them is SAFE because both are immutable by type: a str cannot be
# mutated, and entity_tokens is a tuple of str. Nothing can write through a
# shared reference, so two Signals holding the same object can never affect
# each other. `to_ch_row()` output is byte-identical — equal strings serialise
# identically regardless of identity.
#
# `attrs` is DELIBERATELY NOT SHARED, and that is an evidence-based refusal
# rather than caution: it is a plain dict and it IS mutated after Signal
# construction (main.py stamps probe_intent / vantage_type / probe_authority /
# probe_scope / execution_id / seam_id into `sig.attrs` on the probe path).
# Sharing a mutable dict between Signals would let one signal's enrichment
# silently rewrite another's evidence. The measured extra saving was real
# (~549 B/signal instead of ~819) but it is not available without first making
# attrs immutable, which is a separate change with its own risk.
#
# The caches are BOUNDED on the same pattern as _OBSERVER_CACHE above: an LRU
# ceiling with counted eviction. Eviction is safe by construction — a miss just
# means a fresh equal object, never a different value — so this can never
# become "every unique network value, forever".
ENTITY_CACHE_MAX = int(os.environ.get("CORR_ENTITY_CACHE_MAX", "50000"))
_ENTITY_ID_CACHE: OrderedDict[str, str] = OrderedDict()
_ENTITY_TOKENS_CACHE: OrderedDict[tuple, tuple] = OrderedDict()
ENTITY_CACHE_EVICTED = 0


def shared_entity_id(entity_id: str) -> str:
    """The canonical instance of this entity_id string."""
    global ENTITY_CACHE_EVICTED
    got = _ENTITY_ID_CACHE.get(entity_id)
    if got is not None:
        _ENTITY_ID_CACHE.move_to_end(entity_id)
        return got
    _ENTITY_ID_CACHE[entity_id] = entity_id
    if len(_ENTITY_ID_CACHE) > ENTITY_CACHE_MAX:
        _ENTITY_ID_CACHE.popitem(last=False)
        ENTITY_CACHE_EVICTED += 1
    return entity_id


def shared_entity_tokens(tokens: tuple) -> tuple:
    """The canonical instance of this entity_tokens tuple, with its member
    strings shared too — the tuple is usually small but its strings repeat as
    hard as entity_id does."""
    global ENTITY_CACHE_EVICTED
    got = _ENTITY_TOKENS_CACHE.get(tokens)
    if got is not None:
        _ENTITY_TOKENS_CACHE.move_to_end(tokens)
        return got
    canon = tuple(shared_entity_id(t) if isinstance(t, str) else t for t in tokens)
    _ENTITY_TOKENS_CACHE[tokens] = canon
    if len(_ENTITY_TOKENS_CACHE) > ENTITY_CACHE_MAX:
        _ENTITY_TOKENS_CACHE.popitem(last=False)
        ENTITY_CACHE_EVICTED += 1
    return canon


def entity_cache_stats() -> dict:
    """Population and eviction, so the cache cannot grow unobserved (§10)."""
    return {
        "entity_ids": len(_ENTITY_ID_CACHE),
        "entity_token_tuples": len(_ENTITY_TOKENS_CACHE),
        "max": ENTITY_CACHE_MAX,
        "evicted": ENTITY_CACHE_EVICTED,
    }


def observer_of(observer_id: str, observer_type: ObserverType, *,
                location: str = "", trust_domain: str = "",
                collection_path: str = "direct",
                clock_quality: str = "unknown") -> Observer:
    """An Observer, reusing an identical one when we have already built it.

    Value-identical to `Observer(...)`: same fields, same capping (the cached
    instance was itself produced by the constructor, so __post_init__ ran). The
    key is the RAW arguments, so two callers that differ only in something
    __post_init__ would cap to the same value get separate entries — correct,
    just marginally less effective.
    """
    global OBSERVER_CACHE_EVICTED
    key = (observer_id, observer_type, location, trust_domain,
           collection_path, clock_quality)
    got = _OBSERVER_CACHE.get(key)
    if got is not None:
        _OBSERVER_CACHE.move_to_end(key)
        return got
    obs = Observer(observer_id=observer_id, observer_type=observer_type,
                   location=location, trust_domain=trust_domain,
                   collection_path=collection_path, clock_quality=clock_quality)
    _OBSERVER_CACHE[key] = obs
    if len(_OBSERVER_CACHE) > OBSERVER_CACHE_MAX:
        _OBSERVER_CACHE.popitem(last=False)
        OBSERVER_CACHE_EVICTED += 1
    return obs


# ── P2 step 0c: the per-instance signal_id cache (see Signal.signal_id) ──────
# Default ON. `CORR_SIGNAL_ID_CACHE=0` restores the pre-P2 recompute-every-call
# behaviour so the RSS/CPU trade can be A/B'd on ONE image. Read once at import,
# like every other CORR_* knob.
CORR_SIGNAL_ID_CACHE = os.environ.get(
    "CORR_SIGNAL_ID_CACHE", "1").lower() in ("1", "true", "yes")


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
        self._bound_untrusted_strings()
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

    def _bound_untrusted_strings(self) -> None:
        """Apply the field-class caps (audit PIPE-MED-11) at the model boundary.

        Producers read device-, controller- and HTTP-supplied strings; the model is
        the ONE place every one of them passes through, so the bound lives here and
        a new producer cannot forget it. Deterministic + idempotent, so rehydrating
        a stored row and re-capping it yields the same bytes.

        signal_id derives from source|native_id|ts, so capping native_id changes the
        id ONLY for a signal whose native_id was already past 256 characters — and
        it changes it deterministically, which is what replay requires."""
        for f, limit in (("kind", MAX_ID_CHARS),
                         ("entity_id", MAX_ID_CHARS),
                         ("native_id", MAX_ID_CHARS),
                         ("site", MAX_LABEL_CHARS),
                         ("metric_name", MAX_LABEL_CHARS),
                         ("path_id", MAX_LABEL_CHARS),
                         ("service_id", MAX_LABEL_CHARS)):
            v = getattr(self, f)
            if not isinstance(v, str):   # path_id/service_id are Optional[str]
                continue
            capped = cap_str(v, limit, where="signal", field_name=f)
            if capped != v:
                object.__setattr__(self, f, capped)

        # entity_tokens are the engine's CO-LOCATION keys — the join surface. Two
        # bounds, both cardinality: how MANY a signal may carry, and how long each
        # may be. A producer that dumps an unbounded token list would make one
        # signal join to everything, which is the #99 bug class by another route.
        toks = tuple(cap_id(t, where="signal", field_name="entity_token")
                     for t in self.entity_tokens)
        if len(toks) > MAX_TOKENS:
            _count_truncation("signal", "entity_tokens", len(toks), MAX_TOKENS)
            toks = toks[:MAX_TOKENS]
        if toks != tuple(self.entity_tokens):
            object.__setattr__(self, "entity_tokens", toks)

    @property
    def signal_id(self) -> uuid.UUID:
        """Deterministic: same (source, native_id, event time) ⇒ same id.
        Rehydrated signals return their stored id (identity round-trip).

        MEMOISED per instance (P2 step 0c, 2026-08-28), reversing the earlier
        tracker-156 "never memoise here" ruling on a fresh measurement — the
        ruling is kept in force for `to_ch_row` below, which is a different and
        far larger object.

        WHY IT IS WORTH CACHING. `signal_id` is a uuid5 (a SHA-1 over the
        formatted key), and it is re-derived on every ordering comparison: the
        cProfile of one first-sight `run_window` at 2.5K shape
        (docs/scale/P2_COHORT_PROFILE_2026-08-28.md §8) shows **66,769 calls,
        1.707 s cumulative of a 9.36 s run_window (~18 %)**, all of them
        `sorted(..., key=lambda s: (s.ts, str(s.signal_id)))` and
        `min(comp_sigs, ...)` over the SAME signal objects.

        WHY THE RSS OBJECTION NO LONGER HOLDS. The old note claimed +944 bytes
        per signal (a key-sharing instance dict being converted to a standalone
        one). Re-measured on this Signal (20 dataclass fields, CPython 3.10)
        with both tracemalloc and RSS over 200,000 signals: the cache costs
        **~128 bytes per signal** — the UUID object itself plus one dict slot;
        the instance dict does NOT resize, because 20 fields + 1 cache key still
        fits its table. Across the 50k-signal window cap that is ~6.4 MB, not
        47 MB. The old figure does not reproduce and is superseded by this
        measurement. `CORR_SIGNAL_ID_CACHE=0` reverts to the pre-P2 behaviour on
        ONE image if the trade ever needs revisiting; keep the field count in
        mind when adding to this dataclass — crossing the dict's table boundary
        would put the resize back.

        RECOMPUTE-ON-COPY, exactly like the P1 digest cache: the cache is stored
        via object.__setattr__ and is deliberately NOT a dataclass field, so it
        never enters __eq__/__hash__ and `dataclasses.replace` produces a fresh,
        uncached instance that re-derives from ITS OWN fields. That is the
        conservative reading and it is what makes a re-keyed or rehydrated copy
        safe. Thread-safe by idempotence — a race recomputes the same uuid.
        """
        cached = self.__dict__.get("_signal_id_c")
        if cached is not None:
            return cached
        if self.stored_signal_id:
            value = uuid.UUID(self.stored_signal_id)
        else:
            ts_ms = int(self.ts.timestamp() * 1000)
            value = uuid.uuid5(SIGNAL_NS,
                               f"{self.source.value}|{self.native_id}|{ts_ms}")
        if CORR_SIGNAL_ID_CACHE:
            object.__setattr__(self, "_signal_id_c", value)
        return value

    @property
    def signal_id_str(self) -> str:
        """`str(signal_id)`. Convenience only — see signal_id on why neither is
        memoised on the instance."""
        return str(self.signal_id)

    def to_ch_row(self) -> dict:
        """JSONEachRow shape for netops.corr_signals (frozen schema).

        DELIBERATELY NOT MEMOISED (tracker 156), unlike signal_id. Two variants
        were measured against a 20,000-signal window and both REJECTED, because
        anything cached here is retained for as long as the Signal sits in
        WINDOW_BUFFER — i.e. it trades the resource that is scarce for the one
        that is not:

            variant                RSS      live objs   cycle CPU
            no memo (this)         185 MB   ...         (see below)
            attrs-json memo        185 MB    59 MB      2x faster
            whole-row memo         228 MB    85 MB      no further gain

        The row is rebuilt per call and callers may mutate what they get back
        (the archive stamps archived_for / archived_version onto it). The
        per-CYCLE row cache in main.py gets the same CPU saving with transient
        memory that is freed when the cycle ends."""
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
            attrs, attrs_json = _shrink_attrs(attrs, self.kind)
        row = {
            "tenant_id": self.tenant_id,
            "signal_id": self.signal_id_str,
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
        return row


    @classmethod
    def from_ch_row(cls, row: dict) -> Signal:
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


# ══ GENERIC EVIDENCE-CLASS BUS INTAKE (T2b) ══════════════════════════════════
#
# WHAT THIS IS. A second, declarative way for an evidence lane to reach the
# spine. The existing lanes (syslog, flows, cloud, controller, verification …)
# each own a hand-written producer module because each parses a DIFFERENT raw
# wire shape. An evidence-class lane does not: it publishes an ALREADY-CANONICAL
# envelope — entity + seam + timestamp + evidence refs — whose fields map onto
# Signal fields BY NAME. So there is no per-lane parser to write, and therefore
# no per-lane code for the engine to depend on.
#
# WHY IT MATTERS (the removable-module constraint, HLD 2026-08-25). The engine
# must ground a new evidence class WITHOUT importing, naming or branching on
# that class. Everything class-specific here is one frozen row in
# `EVIDENCE_CLASSES` — data. `evidence_signal_from_event` reads the row and
# never asks which class it got. Removing a class is deleting its producers
# (and, optionally, its row); nothing in the engine has to change.
#
# WHY THE FIELDS ARE DECLARED, NOT HARD-CODED. `rule_id_fields` /
# `observer_fields` are ordered lookup lists rather than an if-chain, so a lane
# whose attrs spell the rule id differently is a data edit, not a code edit.
#
# BOUNDEDNESS (§9 / INVARIANTS §10a). Nothing here retains state: the registry
# is built once at import and is O(classes × kinds); the adapter is pure and
# allocates one Signal. Every untrusted string it copies is capped by the
# Signal/Observer model, `entity_tokens` by MAX_TOKENS and the whole attrs blob
# by ATTRS_MAX_BYTES — the same bounds every other lane passes through.

# Wire severity token → canonical Severity. Deliberately its OWN table rather
# than a reach into a lane module (signals.py is the bottom of the import
# graph): the vocabulary is the union of the common vendor/cloud/OCSF spellings.
EVIDENCE_SEVERITY_ALIASES: dict[str, Severity] = {
    "info": Severity.INFO, "informational": Severity.INFO, "notice": Severity.INFO,
    "debug": Severity.INFO, "ok": Severity.INFO, "low": Severity.INFO,
    "none": Severity.INFO, "pass": Severity.INFO,
    "warn": Severity.WARN, "warning": Severity.WARN, "minor": Severity.WARN,
    "medium": Severity.WARN, "moderate": Severity.WARN,
    "high": Severity.HIGH, "error": Severity.HIGH, "err": Severity.HIGH,
    "major": Severity.HIGH, "important": Severity.HIGH,
    "crit": Severity.CRIT, "critical": Severity.CRIT, "fatal": Severity.CRIT,
    "emergency": Severity.CRIT,
}

# Max evidence_refs copied onto a Signal. Refs are POINTERS (locator + ruleset
# version + digest), so a handful is the honest working set; a producer that
# shipped hundreds would otherwise push the attrs blob into _shrink_attrs and
# cost every downstream reader. Bounded here, at the boundary (§9).
EVIDENCE_REFS_MAX = 8

# The wire contract this adapter implements (secbus.SchemaVersion). A record
# stamped with anything else is REFUSED, never best-effort parsed: provenance is
# never invented (§10 no silent failures). "" is accepted as the pre-versioning
# form so an older producer is not silently darkened.
EVIDENCE_SCHEMA_VERSIONS: frozenset[str] = frozenset({"", "1"})


@dataclass(frozen=True)
class EvidenceClassSpec:
    """One registered EVIDENCE CLASS — the whole of what the engine knows about
    a bus lane whose records are already canonical. Pure data."""

    name: str                              # attrs["evidence_class"]; the metric label
    topic: str                             # the bus topic the class publishes on
    kinds: frozenset[str]                  # the class's Signal.kind vocabulary
    source: Source
    modality: ModalityClass
    observer_type: ObserverType
    default_entity_type: EntityType
    trust_domain: str = "platform"
    collection_path: str = "via_aggregator"
    # Ordered attrs keys the lane may carry its producing rule's id under; the
    # first present, non-empty one wins (provenance, W1b `rule_id`).
    rule_id_fields: tuple[str, ...] = ()
    # Ordered keys naming the producing sub-lane; used to build the observer id
    # so two sub-lanes are two witnesses and neither is ever the device itself.
    observer_fields: tuple[str, ...] = ()


EVIDENCE_CLASSES: dict[str, EvidenceClassSpec] = {
    # The fourth evidence class (SECURITY_OBSERVABILITY_HLD §1). Its kinds are
    # the lane discriminators secbus emits (src/backend/internal/secbus/event.go
    # Kind*), NOT per-rule kinds: the control/rule identity rides in attrs, so
    # the engine's kind space stays a small, stable vocabulary.
    "security": EvidenceClassSpec(
        name="security",
        topic="netops.security",
        kinds=frozenset({"security_posture", "security_exposure", "security_signal"}),
        source=Source.SECURITY,
        modality=ModalityClass.SECURITY,
        # The witness is the platform's rule/feed evaluator — never the device
        # under evaluation, so a verdict can never corroborate itself.
        observer_type=ObserverType.PLATFORM,
        default_entity_type=EntityType.DEVICE,
        rule_id_fields=("rule_id", "raw_rule_id", "control_id"),
        observer_fields=("provider_source", "source"),
    ),
}

# kind → its class. Built once; the adapter's ONLY dispatch (one dict lookup,
# no branch on the class).
EVIDENCE_CLASS_BY_KIND: dict[str, EvidenceClassSpec] = {
    kind: spec for spec in EVIDENCE_CLASSES.values() for kind in spec.kinds
}
# The kind vocabulary the evidence bus contributes to the engine's emitted set
# (coverage.EMITTED_KINDS unions it with the producer-pipeline kinds).
EVIDENCE_BUS_KINDS: frozenset[str] = frozenset(EVIDENCE_CLASS_BY_KIND)
# The topics the classes publish on — the default of main.CORR_EVIDENCE_TOPICS.
EVIDENCE_TOPICS: tuple[str, ...] = tuple(
    sorted({spec.topic for spec in EVIDENCE_CLASSES.values()}))


def evidence_class_of(kind: str) -> str:
    """The evidence class a signal kind belongs to, or "" for the network
    lanes. Pure, O(1) — the projection a consumer filters stories with."""
    spec = EVIDENCE_CLASS_BY_KIND.get(kind)
    return spec.name if spec is not None else ""


def evidence_classes_of(kinds) -> tuple[str, ...]:
    """The sorted, deduped evidence classes present in an iterable of signal
    kinds. "" (the network lanes) is never emitted as a class."""
    return tuple(sorted({c for c in (evidence_class_of(k) for k in kinds) if c}))


def parse_evidence_severity(raw: object) -> Severity:
    """Wire severity token → canonical Severity; an unknown token is WARN."""
    return EVIDENCE_SEVERITY_ALIASES.get(str(raw or "").strip().lower(), Severity.WARN)


def _parse_evidence_ts(raw: object) -> datetime | None:
    """RFC3339(Nano) → tz-aware UTC datetime, or None when unparseable.

    Go's RFC3339Nano emits up to 9 fractional digits; `fromisoformat` accepts at
    most 6, so the fraction is truncated (never rounded — truncation is
    deterministic and monotone, which replay requires)."""
    s = str(raw or "").strip()
    if not s:
        return None
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    if "." in s:
        head, _, rest = s.partition(".")
        digits = ""
        for ch in rest:
            if not ch.isdigit():
                break
            digits += ch
        s = f"{head}.{digits[:6]}{rest[len(digits):]}" if digits else head + rest[len(digits):]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _first_attr(attrs: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = str(attrs.get(k) or "").strip()
        if v:
            return v
    return ""


def evidence_signal_from_event(ev: dict, tenant: str) -> Signal:
    """One canonical evidence-bus envelope → one canonical Signal.

    GENERIC BY CONSTRUCTION: every class-specific fact is read from the
    `EvidenceClassSpec` the envelope's `kind` selects. There is no branch on the
    class, and no name of any class appears in this function.

    Raises DeadLetter on a malformed envelope (unknown schema version, unknown
    kind, no entity, bad entity type, unparseable event time) so the consumer
    parks + counts the record rather than guessing (§10 no silent failures).
    Tenancy is the CALLER's job — it is verified against the device registry
    before this is reached, exactly as the syslog lane does (§3a).

    There is deliberately no ingest-clock fallback (unlike the cloud lane): an
    envelope with no parseable event time is REFUSED. The producer stamps the
    verdict instant and refuses to emit without one (secbus.FromFinding), so a
    missing ts here is a corrupt record, not a tolerable omission — and
    substituting arrival time would silently re-date evidence (log-time
    standard S3: event time is never invented).
    """
    if not isinstance(ev, dict):
        raise DeadLetter("evidence event is not an object")
    schema = str(ev.get("schema_version") or "").strip()
    if schema not in EVIDENCE_SCHEMA_VERSIONS:
        raise DeadLetter(f"unsupported evidence schema_version: {schema!r}")
    kind = str(ev.get("kind") or "").strip()
    spec = EVIDENCE_CLASS_BY_KIND.get(kind)
    if spec is None:
        raise DeadLetter(f"unknown evidence kind: {kind!r}")
    entity_id = str(ev.get("entity_id") or "").strip()
    if not entity_id:
        raise DeadLetter(f"evidence event {kind!r} carries no entity_id")
    native_id = str(ev.get("native_id") or "").strip()
    if not native_id:
        raise DeadLetter(f"evidence event {kind!r} carries no native_id (identity)")
    ts = _parse_evidence_ts(ev.get("ts"))
    if ts is None:
        raise DeadLetter(f"evidence event {kind!r} carries no parseable ts: {ev.get('ts')!r}")

    raw_et = str(ev.get("entity_type") or "").strip()
    if raw_et:
        try:
            entity_type = EntityType(raw_et)
        except ValueError as exc:
            raise DeadLetter(f"unknown entity_type {raw_et!r}") from exc
    else:
        entity_type = spec.default_entity_type

    raw_tokens = ev.get("entity_tokens")
    tokens = (tuple(str(t).strip() for t in raw_tokens if str(t or "").strip())
              if isinstance(raw_tokens, (list, tuple)) else ())
    if not tokens:
        tokens = (entity_id,)

    raw_attrs = ev.get("attrs")
    wire_attrs = dict(raw_attrs) if isinstance(raw_attrs, dict) else {}

    # The engine's evidence CLASS is the registry's, not the payload's. A lane
    # that already carries a finer `evidence_class` of its own keeps it, under
    # `evidence_subclass` — renamed, never dropped (§10 nothing silently lost).
    incoming_class = str(wire_attrs.pop("evidence_class", "") or "").strip()
    attrs: dict = dict(wire_attrs)
    if incoming_class:
        attrs["evidence_subclass"] = incoming_class
    attrs["evidence_class"] = spec.name
    # Seam attribution rides in attrs — opaque to the engine's hot path, read by
    # the seam-owned story surfaces.
    for wire_key in ("seam_id", "seam_type"):
        v = str(ev.get(wire_key) or "").strip()
        if v:
            attrs[wire_key] = v
    if bool(ev.get("internet_facing")):
        attrs["internet_facing"] = True
    refs = ev.get("evidence_refs")
    if isinstance(refs, (list, tuple)) and refs:
        attrs["evidence_refs"] = [r for r in list(refs)[:EVIDENCE_REFS_MAX]
                                  if isinstance(r, dict)]
    # W1b provenance, on the same three fields every classified signal carries.
    # `parser_rev` is "bus" because NO parser ran: the producer published an
    # already-canonical record, and claiming a rule-corpus revision it never
    # passed through would be a false provenance claim.
    rule_id = _first_attr(wire_attrs, spec.rule_id_fields)
    if rule_id:
        attrs["rule_id"] = rule_id
    attrs["parser_rev"] = "bus"
    fidelity = str(wire_attrs.get("fidelity") or "").strip()
    if fidelity:
        attrs["fidelity"] = fidelity

    sub = _first_attr(wire_attrs, spec.observer_fields)
    observer = observer_of(
        f"{spec.name}:{sub}" if sub else f"{spec.name}:lane",
        spec.observer_type,
        trust_domain=spec.trust_domain,
        collection_path=spec.collection_path,
    )
    return Signal(
        tenant_id=tenant,
        ts=ts,
        source=spec.source,
        kind=kind,
        observer=observer,
        modality_class=spec.modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=parse_evidence_severity(ev.get("severity")),
        native_id=native_id,
        entity_tokens=tokens,
        attrs=attrs,
    )
