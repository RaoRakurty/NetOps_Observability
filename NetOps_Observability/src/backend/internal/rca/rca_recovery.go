// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_recovery.go — the generic RecoveryReconciler and IncidentPhaseBuilder
// (truthfulness redesign 2026-07-15, audit D1).
//
// Recovery is modelled per SCOPE, never as one boolean:
//
//   component scope — a resource's own status (tunnel up, interface up, BGP
//                     established, device healthy). Proves THAT resource
//                     recovered, nothing above it.
//   service scope   — end-to-end evidence (customer-path probes/synthetics,
//                     real-traffic and app/LB health). Proves the service
//                     experience recovered.
//
// A lower-level recovery must never recover a higher scope: an IPsec tunnel
// coming up at 17:44 while end-to-end checks fail until 17:51 is component
// recovery + residual degradation, NOT incident recovery. The incident-level
// recovered_at exists only when the LAST qualifying anomaly precedes the last
// recovery evidence for every participating scope.
//
// All functions here are pure derivations over the already-tenant-scoped
// signal slice — no I/O, no re-decision of the engine's facts.

import (
	"fmt"
	"strings"
	"time"
)

// ---- scope classification ------------------------------------------------------

// rcaEvidenceScope classifies one signal into the recovery scope it can speak
// for. Generic: driven by modality/kind families, never by signature or case.
func rcaEvidenceScope(sig map[string]any) string {
	kind := fmt.Sprintf("%v", sig["kind"])
	lane := fmt.Sprintf("%v", sig["modality_class"])
	if lane == "active_probe" || strings.HasPrefix(kind, "synthetic_") || strings.HasPrefix(kind, "probe_") {
		return "service"
	}
	switch kind {
	case "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high":
		return "service"
	}
	if lane == "passive_flow" {
		return "service" // real-traffic behaviour is a service-level observation
	}
	return "component"
}

// ---- recovery assessment --------------------------------------------------------

// RecoveryScopeState is one scope's recovery assessment.
type RecoveryScopeState struct {
	// State: not_applicable | not_observed | inferred | explicitly_confirmed |
	// failed_validation | not_observable
	State string `json:"state"`
	At    string `json:"at,omitempty"`
	Basis string `json:"basis"`
}

// RecoveryAssessment is the reconciled multi-scope recovery picture.
type RecoveryAssessment struct {
	Component RecoveryScopeState `json:"component"`
	Service   RecoveryScopeState `json:"service"`

	// Confirmed: the whole incident's recovery gate passed — recovery evidence
	// exists at/after the last qualifying anomaly in EVERY participating scope.
	Confirmed bool      `json:"confirmed"`
	At        time.Time `json:"-"` // incident-level recovery time (zero unless Confirmed)

	// ResidualAfterComponent: anomalous evidence continued after the last
	// component recovery — the incident entered residual degradation.
	ResidualAfterComponent bool `json:"residual_after_component"`

	componentAt          time.Time
	serviceAt            time.Time
	lastAnomaly          time.Time
	lastComponentAnomaly time.Time
	lastServiceAnomaly   time.Time
	componentPresent     bool
	servicePresent       bool
	recoveryCount        int
}

// ReconcileRecovery derives the multi-scope recovery assessment.
//   - anomalous: attached anomalous signals (the incident's qualifying symptoms)
//   - recoveries: observed recovery evidence (clears + post-onset up-states),
//     each already filtered to AFTER the first anomaly by the caller.
func ReconcileRecovery(anomalous, recoveries []map[string]any) RecoveryAssessment {
	var ra RecoveryAssessment
	ts := func(sig map[string]any) (time.Time, bool) {
		if ct, ok := parseChTS(fmt.Sprintf("%v", sig["clear_ts"])); ok {
			return ct, true
		}
		return parseChTS(fmt.Sprintf("%v", sig["ts"]))
	}
	for _, sig := range anomalous {
		t, ok := parseChTS(fmt.Sprintf("%v", sig["ts"]))
		if !ok {
			continue
		}
		if t.After(ra.lastAnomaly) {
			ra.lastAnomaly = t
		}
		if rcaEvidenceScope(sig) == "service" {
			ra.servicePresent = true
			if t.After(ra.lastServiceAnomaly) {
				ra.lastServiceAnomaly = t
			}
		} else {
			ra.componentPresent = true
			if t.After(ra.lastComponentAnomaly) {
				ra.lastComponentAnomaly = t
			}
		}
	}
	for _, sig := range recoveries {
		t, ok := ts(sig)
		if !ok {
			continue
		}
		ra.recoveryCount++
		if rcaEvidenceScope(sig) == "service" {
			if t.After(ra.serviceAt) {
				ra.serviceAt = t
			}
		} else {
			if t.After(ra.componentAt) {
				ra.componentAt = t
			}
		}
	}

	// component scope
	switch {
	case !ra.componentPresent:
		ra.Component = RecoveryScopeState{State: "not_applicable",
			Basis: "No component-scope evidence participated in this incident."}
	case ra.componentAt.IsZero():
		ra.Component = RecoveryScopeState{State: "not_observed",
			Basis: "No component recovery evidence was captured."}
	case !ra.lastComponentAnomaly.After(ra.componentAt):
		ra.Component = RecoveryScopeState{State: "explicitly_confirmed", At: FmtUTC(ra.componentAt),
			Basis: fmt.Sprintf("Component status recovery observed at %s.", FmtUTC(ra.componentAt))}
	default:
		ra.Component = RecoveryScopeState{State: "failed_validation", At: FmtUTC(ra.componentAt),
			Basis: fmt.Sprintf("A component recovery was observed at %s, but component-scope anomalies continued through %s.",
				FmtUTC(ra.componentAt), FmtUTC(ra.lastComponentAnomaly))}
	}

	// service scope
	switch {
	case !ra.servicePresent:
		ra.Service = RecoveryScopeState{State: "not_applicable",
			Basis: "No service-scope (end-to-end) evidence participated in this incident."}
	case !ra.serviceAt.IsZero() && !ra.lastServiceAnomaly.After(ra.serviceAt):
		ra.Service = RecoveryScopeState{State: "explicitly_confirmed", At: FmtUTC(ra.serviceAt),
			Basis: fmt.Sprintf("Service-level recovery evidence observed at %s, after the last failing check.", FmtUTC(ra.serviceAt))}
	case !ra.serviceAt.IsZero():
		ra.Service = RecoveryScopeState{State: "failed_validation", At: FmtUTC(ra.serviceAt),
			Basis: fmt.Sprintf("Service-scope checks continued failing through %s after the recovery evidence at %s.",
				FmtUTC(ra.lastServiceAnomaly), FmtUTC(ra.serviceAt))}
	case !ra.componentAt.IsZero() && ra.lastServiceAnomaly.After(ra.componentAt):
		ra.Service = RecoveryScopeState{State: "failed_validation",
			Basis: fmt.Sprintf("Component status recovered at %s, but end-to-end checks continued failing through %s. Service recovery is not confirmed.",
				FmtUTC(ra.componentAt), FmtUTC(ra.lastServiceAnomaly))}
	default:
		ra.Service = RecoveryScopeState{State: "not_observed",
			Basis: "No service-level recovery evidence was captured."}
	}

	// residual degradation: any qualifying anomaly after the component recovery.
	ra.ResidualAfterComponent = !ra.componentAt.IsZero() && ra.lastAnomaly.After(ra.componentAt)

	// incident-level gate: the LAST recovery evidence must not precede the last
	// qualifying anomaly, and the highest participating scope must be confirmed.
	last := ra.componentAt
	if ra.serviceAt.After(last) {
		last = ra.serviceAt
	}
	serviceOK := !ra.servicePresent || ra.Service.State == "explicitly_confirmed"
	componentOK := !ra.componentPresent || ra.Component.State == "explicitly_confirmed" ||
		(ra.servicePresent && ra.Service.State == "explicitly_confirmed" && !ra.lastComponentAnomaly.After(last))
	if !last.IsZero() && !ra.lastAnomaly.After(last) && serviceOK && componentOK {
		ra.Confirmed = true
		ra.At = last
	}
	return ra
}

// ---- incident phases (P1.2) ----------------------------------------------------

type IncidentPhase struct {
	Type    string `json:"type"` // detection | degradation | component_recovery | residual_degradation | service_recovery | monitoring
	StartAt string `json:"start_at,omitempty"`
	EndAt   string `json:"end_at,omitempty"`
	Summary string `json:"summary"`
}

// BuildIncidentPhases derives the generic phase ladder from the reconciled
// recovery assessment. Phases are facts about the evidence timeline — the
// narrative renders them so conflicting timestamps are EXPLAINED, never hidden.
func BuildIncidentPhases(firstObs time.Time, ra RecoveryAssessment, monitoringUntil string) []IncidentPhase {
	if firstObs.IsZero() {
		return nil
	}
	var phases []IncidentPhase
	phases = append(phases, IncidentPhase{
		Type: "detection", StartAt: FmtUTC(firstObs),
		Summary: "First anomalous evidence observed.",
	})
	degEnd := ra.lastAnomaly
	if !ra.componentAt.IsZero() && ra.componentAt.Before(degEnd) {
		degEnd = ra.componentAt
	}
	if degEnd.After(firstObs) {
		phases = append(phases, IncidentPhase{
			Type: "degradation", StartAt: FmtUTC(firstObs), EndAt: FmtUTC(degEnd),
			Summary: "Anomalous evidence persisted across the participating evidence classes.",
		})
	}
	if !ra.componentAt.IsZero() {
		phases = append(phases, IncidentPhase{
			Type: "component_recovery", StartAt: FmtUTC(ra.componentAt),
			Summary: "Component status recovery observed.",
		})
	}
	if ra.ResidualAfterComponent {
		phases = append(phases, IncidentPhase{
			Type: "residual_degradation", StartAt: FmtUTC(ra.componentAt), EndAt: FmtUTC(ra.lastAnomaly),
			Summary: fmt.Sprintf("Component status recovered at %s, but end-to-end evidence continued failing through %s — the incident entered residual degradation rather than full recovery.",
				FmtUTC(ra.componentAt), FmtUTC(ra.lastAnomaly)),
		})
	}
	if ra.Confirmed {
		phases = append(phases, IncidentPhase{
			Type: "service_recovery", StartAt: FmtUTC(ra.At),
			Summary: "Recovery evidence observed after the last qualifying anomaly in every participating scope.",
		})
		if monitoringUntil != "" {
			phases = append(phases, IncidentPhase{
				Type: "monitoring", StartAt: FmtUTC(ra.At), EndAt: monitoringUntil,
				Summary: "Post-recovery stability window.",
			})
		}
	}
	return phases
}
