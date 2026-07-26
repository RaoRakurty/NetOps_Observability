"""Applicability-aware client-onboarding episodes (#128 Phase 4, design
docs/Wireslessdesign.md §16) + the wireless client-identity ladder (§9.3).

The whole point is APPLICABILITY: not every phase applies to every client, and
reporting a skipped step as a failure is the classic wireless-monitoring lie.
Phase applicability derives from the WLAN's configuration — never assumed:

    discovery        always
    authentication   method from the WLAN (802.1X | PSK | SAE | OWE | open |
                     MAC-auth | portal); a PSK WLAN has NO RADIUS step
    association      always
    key_exchange     absent on open/OWE-transition networks
    addressing       from the WLAN's address policy (v4 | v6 | dual | static)
    name_resolution  applicable only once addressing succeeded (skipped ≠ failed)
    first_data       always

THE SIGNAL RULE (§20, volume-bounding): terminal FAILURES become correlation
signals at the layer of the terminal phase; SUCCESSES stay ClickHouse data for
troubleshooting and never enter the engine window. A dual-stack client that
got one family but not the other is DEGRADED, not failed and not success —
reported as a warn-severity signal (a v4-only monitor would call it healthy
while the user cannot reach a v4-only service).

Pure module: no IO, no wall clock (callers pass timestamps) — the same
observations always assemble the same episode (replay + fixture contract).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

PHASES = ("discovery", "authentication", "association", "key_exchange",
          "addressing", "name_resolution", "first_data")

# terminal phase → the signal kind (whose causal layer, layers.py, is the
# phase's layer: auth→LINK, addressing→NETWORK, name_resolution→SERVICE).
FAILURE_KIND_BY_PHASE = {
    "discovery": "wireless_onboarding_assoc_failure",
    "authentication": "wireless_onboarding_auth_failure",
    "association": "wireless_onboarding_assoc_failure",
    "key_exchange": "wireless_onboarding_key_failure",
    "addressing": "wireless_onboarding_dhcp_failure",
    "name_resolution": "wireless_onboarding_dns_failure",
    "first_data": "wireless_onboarding_assoc_failure",
}


def _hash16(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def is_randomized_mac(mac: str) -> bool:
    """Locally-administered (U/L) bit ⇒ randomized. Malformed ⇒ True — the
    identity ladder under-claims continuity, never over-claims (mirrors
    wireless/identity.go IsRandomizedMAC)."""
    s = mac.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(s) != 12:
        return True
    try:
        return (int(s[0:2], 16) & 0x02) != 0
    except ValueError:
        return True


def client_identity(tenant: str, client_mac: str, *, eap_cn: str = "",
                    username: str = "", dhcp_client_id: str = "",
                    session_seed: str = "") -> tuple[str, str, str]:
    """The §9.3 ladder → (client_id, confidence, method).

    EAP-TLS CN (authoritative) → 802.1X username (strong) → stable MAC
    (strong) → DHCP client-id (candidate) → randomized MAC (unknown,
    SESSION-SCOPED id: cross-session history honestly does not exist)."""
    if eap_cn.strip():
        return "wcl-" + _hash16(tenant, "cn", eap_cn.strip()), "authoritative", "eap_tls_cn"
    if username.strip():
        return "wcl-" + _hash16(tenant, "user", username.strip()), "strong", "dot1x_username"
    if not is_randomized_mac(client_mac):
        return "wcl-" + _hash16(tenant, "mac", client_mac.strip().lower()), "strong", "stable_mac"
    if dhcp_client_id.strip():
        return "wcl-" + _hash16(tenant, "dhcp", dhcp_client_id.strip()), "candidate", "dhcp_client_id"
    # Randomized MAC and nothing better: identity is the SESSION, on purpose.
    return "wcl-" + _hash16(tenant, "session", session_seed or client_mac), "unknown", "randomized_mac"


@dataclass(frozen=True)
class PhaseResult:
    phase: str
    applicable: bool
    outcome: str          # success | failure | timeout | skipped | degraded | unknown
    duration_ms: int = 0
    reason_code: str = ""
    reason_text: str = ""
    evidence_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "phase": self.phase, "applicable": self.applicable,
            "outcome": self.outcome, "duration_ms": self.duration_ms,
            "reason_code": self.reason_code, "reason_text": self.reason_text,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True)
class Episode:
    tenant_id: str
    episode_id: str
    client_mac: str
    bssid: str
    ap_ref: str
    wlan_ref: str
    attempt_start: datetime
    phases: tuple[PhaseResult, ...]
    terminal_phase: str
    terminal_outcome: str  # success | failure | degraded | unknown
    total_duration_ms: int
    session_ref: str = ""  # empty: a failed onboard has no session
    observer_id: str = ""
    collection_path: str = "via_controller"
    data_class: str = "live"
    attrs: dict = field(default_factory=dict)

    def to_ch_row(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "episode_id": self.episode_id,
            "session_ref": self.session_ref,
            "client_mac": self.client_mac,
            "bssid": self.bssid,
            "ap_ref": self.ap_ref,
            "wlan_ref": self.wlan_ref,
            "attempt_start": int(self.attempt_start.timestamp() * 1000),
            "phases": json.dumps([p.to_dict() for p in self.phases],
                                 separators=(",", ":"), sort_keys=True),
            "terminal_phase": self.terminal_phase,
            "terminal_outcome": self.terminal_outcome,
            "total_duration_ms": self.total_duration_ms,
            "observer_id": self.observer_id,
            "collection_path": self.collection_path,
            "data_class": self.data_class,
        }


def applicable_phases(wlan: dict) -> dict[str, bool]:
    """Which phases apply, from the WLAN's configuration — never assumed.
    Unknown config fails OPEN to applicable=True for the always-phases and
    auth/addressing (a phase wrongly marked inapplicable would HIDE failures;
    wrongly applicable at worst reports unknown)."""
    auth = str(wlan.get("auth_method", "unknown")).lower()
    security = str(wlan.get("security_mode", "unknown")).lower()
    addressing = str(wlan.get("address_policy", "dual")).lower()
    return {
        "discovery": True,
        "authentication": True,          # method varies; the PHASE always exists
        "association": True,
        # open and OWE-transition have no 4-way handshake.
        "key_exchange": not (auth == "open" or security == "open" or "owe" in security),
        "addressing": addressing != "static",
        "name_resolution": True,          # gated at assembly on addressing outcome
        "first_data": True,
    }


def assemble_episode(tenant: str, client_mac: str, bssid: str, ap_ref: str,
                     wlan: dict, observations: dict, attempt_start: datetime,
                     observer_id: str, *, wlan_ref: str = "",
                     data_class: str = "live") -> Episode:
    """Fold raw phase observations into an applicability-aware episode.

    `observations` maps phase → {"outcome", "duration_ms", "reason_code",
    "reason_text", "evidence_ref"} for the phases the source reported.
    Dual-stack rule: observations may carry addressing_v4/addressing_v6
    sub-outcomes; one family failing while the other succeeds is DEGRADED.
    """
    applicable = applicable_phases(wlan)
    results: list[PhaseResult] = []
    terminal_phase = ""
    terminal_outcome = "success"
    addressing_ok = True
    total_ms = 0

    for phase in PHASES:
        if not applicable.get(phase, True):
            results.append(PhaseResult(phase, False, "skipped"))
            continue
        if phase == "name_resolution" and not addressing_ok:
            # Skipped BECAUSE addressing failed — skipped is not failed.
            results.append(PhaseResult(phase, True, "skipped",
                                       reason_text="not attempted: no address"))
            continue

        if phase == "addressing" and ("addressing_v4" in observations
                                      or "addressing_v6" in observations):
            v4 = observations.get("addressing_v4", {}).get("outcome", "unknown")
            v6 = observations.get("addressing_v6", {}).get("outcome", "unknown")
            fams = {f for f in (v4, v6) if f != "unknown"}
            if fams == {"success"}:
                outcome = "success"
            elif "success" in fams and ("failure" in fams or "timeout" in fams):
                # Dual-stack partial: the user has SOME connectivity but a
                # v4-only (or v6-only) service is dark — degraded, not success
                # and not failed (report §16).
                outcome = "degraded"
            elif fams and "success" not in fams:
                outcome = "failure"
            else:
                outcome = "unknown"
            obs = observations.get("addressing", {})
            r = PhaseResult(phase, True, outcome,
                            int(obs.get("duration_ms", 0)),
                            str(obs.get("reason_code", "")),
                            f"v4={v4} v6={v6}",
                            str(obs.get("evidence_ref", "")))
        else:
            obs = observations.get(phase)
            if obs is None:
                results.append(PhaseResult(phase, True, "unknown"))
                continue
            r = PhaseResult(phase, True, str(obs.get("outcome", "unknown")),
                            int(obs.get("duration_ms", 0)),
                            str(obs.get("reason_code", "")),
                            str(obs.get("reason_text", "")),
                            str(obs.get("evidence_ref", "")))

        results.append(r)
        total_ms += r.duration_ms
        if phase == "addressing" and r.outcome in ("failure", "timeout"):
            addressing_ok = False
        if r.outcome in ("failure", "timeout") and terminal_outcome == "success":
            terminal_phase, terminal_outcome = phase, "failure"
        elif r.outcome == "degraded" and terminal_outcome == "success":
            terminal_phase, terminal_outcome = phase, "degraded"

    start_ms = int(attempt_start.timestamp() * 1000)
    return Episode(
        tenant_id=tenant,
        episode_id=_hash16(tenant, client_mac.lower(), bssid.lower(), str(start_ms)),
        client_mac=client_mac, bssid=bssid, ap_ref=ap_ref,
        wlan_ref=wlan_ref or str(wlan.get("wlan_id", "")),
        attempt_start=attempt_start,
        phases=tuple(results),
        terminal_phase=terminal_phase,
        terminal_outcome=terminal_outcome,
        total_duration_ms=total_ms,
        observer_id=observer_id,
        data_class=data_class,
    )


def episode_signal(ep: Episode, wlan: dict | None = None) -> Signal | None:
    """THE SIGNAL RULE: a terminal failure (or degraded) becomes ONE signal at
    the terminal phase's kind; success returns None and never enters the
    engine window. The entity is the SESSION (always-reliable identity);
    grounding to the AP rides entity_tokens (the AP's canonical id names ONE
    entity — allowed; SSID/WLAN tokens are forbidden at the model layer)."""
    if ep.terminal_outcome == "success" or not ep.terminal_phase:
        return None
    kind = FAILURE_KIND_BY_PHASE.get(ep.terminal_phase)
    if kind is None:
        return None
    client_id, confidence, method = client_identity(
        ep.tenant_id, ep.client_mac, session_seed=ep.episode_id,
        username=str(ep.attrs.get("username", "")) if ep.attrs else "",
    )
    severity = Severity.HIGH if ep.terminal_outcome == "failure" else Severity.WARN
    tokens = tuple(t for t in (ep.ap_ref,) if t)
    return Signal(
        tenant_id=ep.tenant_id,
        ts=ep.attempt_start if ep.attempt_start.tzinfo
        else ep.attempt_start.replace(tzinfo=timezone.utc),
        source=Source.CONTROLLER,
        kind=kind,
        observer=Observer(observer_id=ep.observer_id or "wireless",
                          observer_type=ObserverType.CONTROLLER,
                          collection_path=ep.collection_path),
        modality_class=ModalityClass.MANAGEMENT_PLANE,
        entity_type=EntityType.WIRELESS_SESSION,
        entity_id=f"{client_id}:{ep.episode_id}",
        severity=severity,
        native_id=f"onboarding|{ep.episode_id}",
        entity_tokens=tokens,
        attrs={
            "terminal_phase": ep.terminal_phase,
            "terminal_outcome": ep.terminal_outcome,
            "identity_confidence": confidence,
            "identity_method": method,
            "bssid": ep.bssid,
            "data_class": ep.data_class,
        },
    )
