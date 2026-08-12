// Package secobs is the security-observability domain (SEC-020/021): the single
// vocabulary for security metrics and audit events, the transport-inventory
// reader, and the posture assembly that joins declared policy with observed
// transport state.
//
// SEC-020.1's contract is "name the signals once": every security metric this
// platform emits — or has agreed to emit when its owning epic lands — is a row
// in Vocabulary below. scripts/audit_metric_contract.py reads this table
// (line-oriented; keep one field set per line) and fails CI when an EMITTED row
// stops being emitted or an emitted security metric is missing from the table.
package secobs

import (
	"fmt"
	"regexp"
	"strings"
)

// FamilyStatus says whether a vocabulary row is emitted today or reserved for
// its owning epic. Reserved rows exist so two epics cannot mint two names for
// the same signal — the whole point of a vocabulary.
type FamilyStatus string

const (
	// StatusEmitted — the family appears on a /metrics surface today. The
	// contract auditor enforces this.
	StatusEmitted FamilyStatus = "emitted"
	// StatusReserved — the name is registered; emission arrives with the
	// owning epic. The contract auditor forbids an unregistered netops_sec_*
	// family from appearing, so a reserved name cannot be squatted ad hoc.
	StatusReserved FamilyStatus = "reserved"
)

// Family is one security metric family. Labels lists the complete allowed
// label set: a label carrying a secret, token, credential or PII is forbidden
// (CLAUDE.md §8) and the redaction test pins that labels come from closed
// enumerations, never from operator-supplied values.
type Family struct {
	Name   string
	Type   string // "gauge" | "counter"
	Labels []string
	Help   string
	Epic   string // owning epic, e.g. "SEC-020"
	Status FamilyStatus
}

// Vocabulary is THE security metric registry. Order: emitted first, then
// reserved, alphabetical within each block.
//
// NOTE for scripts/audit_metric_contract.py: one row per line, `Name:` first.
var Vocabulary = []Family{
	// Emitted before SEC-020 (grandfathered names — renaming a shipped family
	// breaks dashboards and alert rules for zero security value; the vocabulary
	// registers them rather than churning them).
	{Name: "netops_tls_cert_expiry_seconds", Type: "gauge", Labels: nil, Help: "Seconds until the API server TLS certificate expires.", Epic: "SEC-003", Status: StatusEmitted},
	{Name: "netops_tls_handshake_errors_total", Type: "counter", Labels: nil, Help: "TLS handshake failures at the API listener.", Epic: "SEC-003", Status: StatusEmitted},
	{Name: "netops_tls_identity_rejected_total", Type: "counter", Labels: nil, Help: "mTLS peers with a trusted chain but a disallowed identity.", Epic: "SEC-003", Status: StatusEmitted},
	{Name: "netops_tls_peer_cert_expiry_seconds", Type: "gauge", Labels: []string{"endpoint"}, Help: "Seconds until the certificate SERVED by a mesh endpoint expires.", Epic: "SEC-019", Status: StatusEmitted},
	{Name: "netops_tls_peer_probe_ok", Type: "gauge", Labels: []string{"endpoint"}, Help: "Whether the last served-certificate probe captured a certificate.", Epic: "SEC-019", Status: StatusEmitted},

	// Emitted by SEC-020.1 (this epic).
	{Name: "netops_sec_declared_edges", Type: "gauge", Labels: []string{"tier"}, Help: "Transport-inventory edges by declared security_profile transport tier.", Epic: "SEC-020", Status: StatusEmitted},
	{Name: "netops_sec_exception_age_seconds", Type: "gauge", Labels: []string{"edge"}, Help: "Age of each declared plaintext exception since it was last reviewed (accepted date in the transport inventory).", Epic: "SEC-020", Status: StatusEmitted},
	{Name: "netops_sec_posture_findings", Type: "gauge", Labels: []string{"severity"}, Help: "Boot security-posture validator finding counts (fatal/warn/info) for the running configuration.", Epic: "SEC-020", Status: StatusEmitted},

	// Emitted by F-11 seal-or-quarantine (internal/quarantine.Metrics, wired
	// into the api /metrics writer; sampler over netops-quarantine-*).
	{Name: "netops_sec_quarantine_depth", Type: "gauge", Labels: nil, Help: "Sealed unattributable events currently held in the quarantine index.", Epic: "F-11", Status: StatusEmitted},
	{Name: "netops_sec_quarantine_oldest_seconds", Type: "gauge", Labels: nil, Help: "Age of the oldest quarantined event; 0 when the quarantine is empty.", Epic: "F-11", Status: StatusEmitted},
	{Name: "netops_sec_quarantine_restored_total", Type: "counter", Labels: []string{"outcome"}, Help: "Quarantined events processed by operator re-attribution, by outcome (restored|failed).", Epic: "F-11", Status: StatusEmitted},

	// Reserved for their owning epics. Emission points are named in the epic
	// specs (docs/security/CORRELIX_SECURITY_IMPLEMENTATION_BACKLOG.md).
	{Name: "netops_sec_acl_denials_total", Type: "counter", Labels: []string{"principal_kind"}, Help: "Kafka authorizer denials observed by the platform (SEC-007 enforce flip).", Epic: "SEC-007", Status: StatusReserved},
	{Name: "netops_sec_exporter_rejected_total", Type: "counter", Labels: []string{"channel", "reason"}, Help: "Flow/telemetry packets dropped by exporter-address policy.", Epic: "SEC-016", Status: StatusReserved},
	{Name: "netops_sec_ingest_rejected_total", Type: "counter", Labels: []string{"lane", "reason"}, Help: "Ingest-lane requests rejected after the shared-token fallback is dropped (lane-token narrowing).", Epic: "SEC-013", Status: StatusReserved},
	{Name: "netops_sec_sealing_fetch_total", Type: "counter", Labels: []string{"result"}, Help: "Sealing edge-key fetch attempts by outcome (SEC-018 hop, feature-gated).", Epic: "SEC-018", Status: StatusReserved},
	{Name: "netops_sec_trap_policy_rejected_total", Type: "counter", Labels: []string{"reason"}, Help: "SNMP traps dropped by per-sender transport policy (closes the decodeTrapV3 fail-open).", Epic: "SEC-005", Status: StatusReserved},
}

var metricNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateVocabulary enforces the vocabulary's own rules. It is called from the
// unit test, not at boot — the table is compile-time constant.
func ValidateVocabulary() error {
	seen := make(map[string]bool, len(Vocabulary))
	for _, f := range Vocabulary {
		if !metricNameRe.MatchString(f.Name) {
			return fmt.Errorf("vocabulary: %q is not a valid metric name", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("vocabulary: duplicate family %q", f.Name)
		}
		seen[f.Name] = true
		if !strings.HasPrefix(f.Name, "netops_sec_") && !strings.HasPrefix(f.Name, "netops_tls_") {
			return fmt.Errorf("vocabulary: %q must use the netops_sec_ prefix (netops_tls_ is grandfathered)", f.Name)
		}
		if strings.HasPrefix(f.Name, "netops_sec_") && f.Type == "counter" && !strings.HasSuffix(f.Name, "_total") {
			return fmt.Errorf("vocabulary: counter %q must end in _total", f.Name)
		}
		if f.Type != "gauge" && f.Type != "counter" {
			return fmt.Errorf("vocabulary: %q has unknown type %q", f.Name, f.Type)
		}
		if f.Status != StatusEmitted && f.Status != StatusReserved {
			return fmt.Errorf("vocabulary: %q has unknown status %q", f.Name, f.Status)
		}
		if f.Epic == "" || f.Help == "" {
			return fmt.Errorf("vocabulary: %q must carry Epic and Help", f.Name)
		}
		for _, l := range f.Labels {
			if !metricNameRe.MatchString(l) {
				return fmt.Errorf("vocabulary: %q label %q is not a valid label name", f.Name, l)
			}
		}
	}
	return nil
}
