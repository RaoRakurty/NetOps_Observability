// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// http.go — the lane's two operator surfaces. Both are §3a-scoped through the
// INJECTED authz resolver; this package holds no ambient authority and never
// reads a tenant out of a request body.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/secbus"
	"netops/backend/secapi"
)

// HandleStatus serves GET /api/security/lane/status.
//
// GATE (§3a rule 3): the secapi ADMIN gate (administration:write on this
// platform — the same per-tenant configuration gate rule enablement uses), then
// the tenant filter. The cross-tenant PLATFORM admin sees one row per tenant; a
// tenant admin sees ONLY its own row, because the mere existence of another
// tenant is not its to know.
//
// The principal also carries the OPERATOR-VISIBILITY restriction, applied inside
// StatusFor, the one place this lane's read rule lives. A restricted tenant's
// row is dropped from the platform admin's Global list and a platform admin
// scoped into one reads no row at all: a 200 with nothing in it, never a 403,
// which would confirm the tenant has a lane.
func (l *Lane) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		l.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	p, ok := l.deps.Authz(w, r, secapi.GateAdmin)
	if !ok {
		return
	}
	rows := l.StatusFor(p)
	scope := "tenant"
	if p.Cross {
		scope = "platform"
	}
	l.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"enabled":                 true,
		"interval_seconds":        int(l.interval / time.Second),
		"max_findings_per_tenant": l.maxFindings,
		"topic":                   secbus.TopicSecurityEvidence,
		// The counter block is scoped the same way the rows are. It used to be
		// the RAW platform snapshot — platform-wide scan runs, per-class
		// emission counts, dead-letter and lost totals — handed to any tenant
		// admin: not a row leak, but an aggregate inference channel into every
		// other tenant's activity, which §3a rule 1 answers the same way.
		"metrics": l.metricsFor(p, rows),
		// What those numbers COVER, said in the response rather than assumed by
		// the page: a tenant admin's block is its own, not the platform's.
		"metrics_scope": scope,
		"tenants":       rows,
	})
}

// HandleScan serves POST /api/security/scan — a manual, bounded trigger for the
// CALLER'S OWN tenant (administration:write via the secapi ADMIN gate). A
// cross-tenant caller must scope into a tenant first: there is no "scan
// everything" button, because a scan writes tenant-attributed evidence and the
// attribution must be unambiguous. 429 when one is already queued or running.
func (l *Lane) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	p, ok := l.deps.Authz(w, r, secapi.GateAdmin)
	if !ok {
		return
	}
	tenant := strings.ToLower(strings.TrimSpace(p.Tenant))
	if p.Cross || tenant == "" || (l.deps.GlobalTenant != "" && tenant == l.deps.GlobalTenant) {
		l.deps.WriteError(w, http.StatusBadRequest, ErrScanNoTenant)
		return
	}
	// The OPERATOR-VISIBILITY restriction. A scan is a WRITE on this tenant's
	// estate: it reads the tenant's devices and configurations and produces
	// tenant-attributed evidence. An operator that may not read the tenant's lane
	// must not drive its evidence production either, so a denied trigger is
	// refused outright rather than answered under some empty scope — a write
	// answered that way would create rows no tenant could ever see.
	if p.Deny {
		l.deps.WriteError(w, http.StatusForbidden, ErrScanRestricted)
		return
	}
	if err := l.Enqueue(tenant); err != nil {
		l.deps.WriteError(w, http.StatusTooManyRequests, err)
		return
	}
	if l.deps.Audit != nil {
		l.deps.Audit(r, tenant, "security_scan_enqueued",
			map[string]any{"tenant_seg": l.deps.TenantSeg(tenant)})
	}
	l.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"queued": true, "tenant_seg": l.deps.TenantSeg(tenant),
	})
}

// metricsFor scopes the counter block to the caller (§3a rule 1, default-closed).
//
// A cross-tenant platform admin reads the whole snapshot, which is what it has
// always been. A tenant admin reads only what is attributable to the tenants it
// may see — today its own scan-run count. The platform-wide totals (truncation,
// publish failures, dead-letter, lost, per-class emission) are deliberately
// ABSENT rather than zeroed: a missing counter is honest, and a zero would
// claim that nothing was ever lost anywhere.
func (l *Lane) metricsFor(p secapi.Principal, rows []ScanStatus) map[string]int64 {
	if p.Cross {
		return l.metrics.Snapshot()
	}
	var runs int64
	for _, st := range rows {
		for _, outcome := range []string{OutcomeOK, OutcomePartial, OutcomeError, OutcomeSkipped} {
			runs += l.metrics.RunsFor(st.TenantSeg, outcome)
		}
	}
	return map[string]int64{"scan_runs_total": runs}
}
