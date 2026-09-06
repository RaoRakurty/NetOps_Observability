// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_context.go — the canonical, server-derived tenant identity (Phase 1 of
// the opaque-identity hardening, docs/design/opaque-identity-model.md).
//
// THE CONTRACT (AWS/Azure/GCP-style isolation): tenant identity is NEVER trusted
// from the client. A URL slug / header / body field is accepted only at the edge
// for routing; it is resolved server-side to the opaque, immutable tenant_id, the
// actor is authorized against that tenant_id, and downstream code carries the
// TenantContext — preferring TenantContext.TenantID, never the raw slug. Resolution
// fails CLOSED: callers must deny when ok=false (no slug fallback, no default/first/
// demo tenant).

import (
	"net/http"
)

// resolved_from provenance — how a TenantContext's identity was established.
const (
	ResolvedFromID      = "id"      // matched an opaque/legacy id
	ResolvedFromSlug    = "slug"    // matched a human slug, resolved to id
	ResolvedFromToken   = "token"   // derived from the authenticated principal
	ResolvedFromSession = "session" // (future) derived from server-side session state
)

// TenantContext is the canonical tenant identity handed to internal services.
// Internal authorization, joins, ownership checks, RLS scoping, and data tagging
// use TenantID (opaque, immutable). Slug/name are display/routing only.
type TenantContext struct {
	OrgID        string `json:"org_id"`
	OrgSlug      string `json:"org_slug,omitempty"`
	TenantID     string `json:"tenant_id"`
	TenantSlug   string `json:"tenant_slug,omitempty"`
	TenantRegion string `json:"tenant_region,omitempty"`
	TenantStatus string `json:"tenant_status,omitempty"`
	ResolvedFrom string `json:"resolved_from,omitempty"`
}

// auditTenantDetail is the identity snapshot for an audit record on a tenant
// mutation: stable ids for security joins + slug/name snapshots for human
// investigation (the snapshot survives a later rename). See AuditEvent.Detail.
func auditTenantDetail(t Tenant) map[string]any {
	return map[string]any{
		"org_id":      orgOf(t),
		"tenant_id":   t.ID,
		"tenant_slug": t.Slug,
		"tenant_name": t.Name,
	}
}

// auditOrgDetail is the identity snapshot for an audit record on an org mutation.
func auditOrgDetail(o Org) map[string]any {
	return map[string]any{
		"org_id":   o.ID,
		"org_slug": o.Slug,
		"org_name": o.Name,
	}
}

// recordIdentityAudit writes an explicit, detailed audit entry for an identity
// control-plane action (org/tenant create/delete). It captures the stable actor +
// opaque-id snapshot the generic request-envelope audit (withAudit) can't see, so
// investigators get both "who did what, when, from where" AND the id/slug/name
// snapshot that survives a later rename. Best-effort — never breaks the request.
func (s *server) recordIdentityAudit(r *http.Request, c jwtClaims, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(c)
	d := map[string]any{"action": action}
	for k, v := range detail {
		d[k] = v
	}
	s.audit.Record(AuditEvent{
		Actor:    c.Sub,
		Tenant:   tenant,
		Cross:    cross,
		Method:   r.Method,
		Path:     r.URL.Path,
		Decision: "allow",
		Remote:   auditClientIP(r),
		Detail:   d,
	})
}
