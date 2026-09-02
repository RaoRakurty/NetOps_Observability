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
func (l *Lane) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		l.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	p, ok := l.deps.Authz(w, r, secapi.GateAdmin)
	if !ok {
		return
	}
	l.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"enabled":                 true,
		"interval_seconds":        int(l.interval / time.Second),
		"max_findings_per_tenant": l.maxFindings,
		"topic":                   secbus.TopicSecurityEvidence,
		"metrics":                 l.metrics.Snapshot(),
		"tenants":                 l.StatusFor(p.Tenant, p.Cross),
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
