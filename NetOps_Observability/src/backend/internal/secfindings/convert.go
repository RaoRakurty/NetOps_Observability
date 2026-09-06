// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secfindings

import (
	"strings"

	"netops/backend/internal/compliance"
)

// FromComplianceFinding converts a legacy internal/compliance.Finding into the
// owned normalized model with ZERO rewrite of the 9 existing checks. The
// conversion is lossless for every field that exists on the source; fields the
// source does not carry are left to be stamped by the producing layer, and are
// enumerated here so nothing is silently invented:
//
//   - ID, ScanID, Time      — assigned by the producer/emitter (T2+), not the check.
//   - TenantID              — stamped from the authenticated principal (§3a), never
//     from a finding body; left empty here on purpose.
//   - EvidenceRef           — the legacy check holds no by-reference artifact; nil.
//   - ControlID             — the owned control-layer id (§5d) is assigned by the
//     mapping layer, not derivable from a legacy check; empty.
//   - Remediation           — the legacy Finding has NO dedicated remediation field
//     (its guidance is embedded in Detail), so it cannot map
//     cleanly; carried through inside Detail, left empty here.
//   - Resource.Hostname/Address/Platform — not present on the legacy Finding.
//
// A compliance.Finding is by construction a VIOLATION (the evaluator only emits
// non-compliant rows), so the normalized verdict is always Fail — this is a
// semantic mapping, not a lost field. The subject is a network device (the
// legacy evaluator's entire domain), so Resource.Kind defaults to network-device.
func FromComplianceFinding(c compliance.Finding) Finding {
	f := Finding{
		Source:        SourceCompliance,
		EvidenceClass: EvidencePosture,
		Standards:     splitStandards(c.Framework),
		ControlTitle:  c.Title,
		Category:      c.Class, // drift | policy
		Severity:      c.Severity,
		Resource: Resource{
			DeviceID:   c.DeviceID,
			DeviceName: c.DeviceName,
			Kind:       KindNetworkDevice,
		},
		Observed:  c.Observed,
		Intended:  c.Intended,
		Detail:    c.Detail,
		RawRuleID: c.Check,
	}
	f.SetStatus(StatusFail)
	return f
}

// splitStandards parses the legacy free-form Framework string into the normalized
// Standards slice. Legacy values pack one or more standards on one line separated
// by a middle dot ("CIS · NIST 800-53 IA-5"); single-standard values
// ("NIST CSF ID.AM-1", "CISA BOD 22-01") yield one element. Empty/whitespace
// segments are dropped so the slice is clean.
func splitStandards(framework string) []string {
	framework = strings.TrimSpace(framework)
	if framework == "" {
		return nil
	}
	parts := strings.Split(framework, "·")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
