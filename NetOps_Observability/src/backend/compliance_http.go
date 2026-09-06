// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// compliance_http.go — the HTTP surface of Compliance Monitoring (#14). The
// evaluation lives in internal/compliance; this file adapts the server's
// collaborators to that package's seams (§2: the entrypoint package keeps
// wiring and HTTP). The credential adapter hands compliance ONLY the profile
// identity and crypto parameters — community strings and keys stay on this
// side of the boundary.

import (
	"errors"
	"net/http"

	"netops/backend/internal/compliance"
	"netops/backend/internal/vuln"
)

// handleCompliance — GET /api/compliance. Tenant-scoped posture assessment.
func (s *server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	merged := visibleDevices(s.discovery.Devices(), claims)
	if len(merged) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"compliance_enabled": false})
		return
	}
	limit, errLimit := intQuery(r, "limit", 500, 1, 2000)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}

	raw := visibleDevices(s.discovery.RawDevices(), claims)
	// Drift pairs against whichever SoT provider is active (internal | netbox | …),
	// not a NetBox-specific flag. The provider names the Device.Source its declared
	// records carry; "" means none exist → drift inactive.
	sotp := s.activeSoT()
	sotSource := sotp.DeviceRecordSource()

	resolveProfile := func(ref string) (compliance.SNMPProfile, bool) {
		c, ok := s.snmpCreds.Resolve(ref)
		if !ok {
			return compliance.SNMPProfile{}, false
		}
		return compliance.SNMPProfile{
			Name: c.Name, Version: c.Version, SecurityLevel: c.SecurityLevel,
			AuthProtocol: c.AuthProtocol, PrivProtocol: c.PrivProtocol,
		}, true
	}
	var vulnMatch func(vendor, product, version string) []vuln.Entry
	if s.vulns.Ensure() {
		vulnMatch = s.vulns.Match
	}
	res := compliance.Evaluate(merged, raw, sotSource, resolveProfile, vulnMatch)

	affected := map[string]bool{}
	drift, policy, high := 0, 0, 0
	for _, f := range res.Findings {
		affected[f.DeviceID] = true
		if f.Class == "drift" {
			drift++
		} else {
			policy++
		}
		if f.Severity == "high" {
			high++
		}
	}
	// Findings pair to raw per-source records; cap affected at the physical count.
	affectedN := len(affected)
	if affectedN > res.Physical {
		affectedN = res.Physical
	}
	checksActive := 0
	for _, c := range res.Checks {
		if c.Active {
			checksActive++
		}
	}
	total := len(res.Findings)
	findings := res.Findings
	if len(findings) > limit {
		findings = findings[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"compliance_enabled": true,
		// configured = drift has declared records to compare against (an external
		// SoT read into the inventory); provider = the active SoT role-holder.
		"sot": map[string]any{"configured": sotSource != "", "provider": sotp.Name()},
		"summary": map[string]any{
			"devices": res.Physical, "affected": affectedN, "compliant": res.Physical - affectedN,
			"findings": total, "drift": drift, "policy": policy, "high": high,
			"checks_active": checksActive, "checks_total": len(res.Checks),
		},
		"checks":   res.Checks,
		"findings": findings,
		"gaps":     res.Gaps,
	})
}
