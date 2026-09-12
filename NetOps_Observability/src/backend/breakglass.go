// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// breakglass.go — PBAC Phase C: access-as-an-event for the platform operator.
//
// Ratified posture (§7.1): operators have NO standing access to a tenant whose
// data is marked OperatorRestricted (the compliance switch). When an operator
// genuinely needs in — incident response — they open a BREAK-GLASS session: a
// time-boxed, fully audited allow binding at that tenant's scope, carrying a
// mandatory reason and a short expiry. It self-expires; nothing lingers.
//
// This is purely additive and behaviour-preserving by default: with no active
// break-glass binding, a restricted tenant stays hidden from the operator exactly
// as before. A live session temporarily un-hides ONLY that tenant, ONLY for its
// window, and every grant/use is on the record.
//
// The live re-pointing of RLS / OpenSearch / VictoriaMetrics off the global
// tenant onto a dedicated system scope is deferred (it needs the regional data
// plane + a staged rollout) — see docs/design/saas-identity-pbac.md §6 Phase C.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/elevation"
	"netops/backend/internal/rbac"
	"netops/backend/internal/ssoidp"
)

// breakGlassDefaultTTL bounds a session if the caller doesn't specify one; the
// max keeps a session from being effectively standing access.
const (
	breakGlassDefaultTTL = 60 * time.Minute
	breakGlassMaxTTL     = 8 * time.Hour
)

// conditionBreakGlass marks a binding as an emergency-access grant. The
// predicate is RoleBinding.IsBreakGlass (internal/rbac).
const conditionBreakGlass = rbac.ConditionBreakGlass

// Elevation-binding condition keys (internal/rbac owns the vocabulary; the
// predicates are RoleBinding.IsElevation / ConditionString).
const (
	ConditionElevation         = rbac.ConditionElevation
	ConditionElevationProvider = rbac.ConditionElevationProvider
	ConditionElevationSID      = rbac.ConditionElevationSID
	ConditionElevationTenant   = rbac.ConditionElevationTenant
)

// hasBreakGlass reports whether the principal holds an ACTIVE break-glass binding
// that reaches the given tenant.
func (s *server) hasBreakGlass(principalID, tenantID string) bool {
	if s.bindings == nil {
		return false
	}
	target := scopeTenant(tenantID)
	now := time.Now().UTC()
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if b.Effect == EffectAllow && b.IsBreakGlass() && b.Active(now) && s.scopeAncestorOrSelf(b.ScopeID, target) {
			return true
		}
	}
	return false
}

// effectiveRestrictedIDs returns the OperatorRestricted tenant ids that remain
// hidden from THIS operator right now — i.e. restricted tenants MINUS the ones it
// currently holds a live break-glass session into. This is what the telemetry
// visibility gate consults, so break-glass transparently un-hides a tenant for
// the duration of the session and no longer afterwards.
func (s *server) effectiveRestrictedIDs(principalID string) []string {
	if s.tenants == nil {
		return nil
	}
	restricted := s.tenants.RestrictedIDs()
	if len(restricted) == 0 {
		return nil
	}
	out := make([]string, 0, len(restricted))
	for _, id := range restricted {
		if !s.hasBreakGlass(principalID, id) {
			out = append(out, id)
		}
	}
	return out
}

type breakGlassRequest struct {
	TenantID       string `json:"tenant_id"`
	Reason         string `json:"reason"`
	DurationMinute int    `json:"duration_minutes"`
}

// handleBreakGlass: POST opens a session, GET lists the caller's active sessions.
// Platform owner only — it is the operator elevating itself into a restricted
// tenant. A tenant's own users never need it (they already see their own data).
func (s *server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !isPlatformOwner(claims) {
		writeError(w, http.StatusForbidden, errors.New("platform operator required"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		now := time.Now().UTC()
		out := make([]RoleBinding, 0)
		for _, b := range s.bindings.ListByPrincipal(claims.Sub) {
			if b.IsBreakGlass() && b.Active(now) {
				out = append(out, b)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req breakGlassRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant := strings.ToLower(strings.TrimSpace(req.TenantID))
		if tenant == "" || tenant == TenantGlobal {
			writeError(w, http.StatusBadRequest, errors.New("a specific tenant is required"))
			return
		}
		if _, ok := s.tenants.Get(tenant); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown tenant"))
			return
		}
		if strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, errors.New("a reason is required for break-glass access"))
			return
		}
		ttl := time.Duration(req.DurationMinute) * time.Minute
		if ttl <= 0 {
			ttl = breakGlassDefaultTTL
		}
		if ttl > breakGlassMaxTTL {
			ttl = breakGlassMaxTTL
		}
		exp := time.Now().UTC().Add(ttl)
		b, err := s.bindings.Add(RoleBinding{
			PrincipalID: claims.Sub,
			RoleID:      RoleSuperAdmin,
			ScopeID:     scopeTenant(tenant),
			Effect:      EffectAllow,
			Condition:   map[string]any{conditionBreakGlass: true},
			ExpiresAt:   &exp,
			GrantedBy:   claims.Sub,
			Reason:      strings.TrimSpace(req.Reason),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// First-class audited event (also captured by the audit middleware).
		logWarn("breakglass", "break-glass session opened", map[string]any{
			"operator": claims.Sub, "tenant": tenant, "reason": b.Reason,
			"expires_at": exp.Format(time.RFC3339),
		})
		writeJSON(w, http.StatusCreated, b)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBreakGlassByID: DELETE ends a session early.
func (s *server) handleBreakGlassByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/breakglass/")
	// A caller may only end its own break-glass session.
	var target *RoleBinding
	for _, b := range s.bindings.ListByPrincipal(claims.Sub) {
		if b.ID == id && b.IsBreakGlass() {
			bb := b
			target = &bb
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, errors.New("break-glass session not found"))
		return
	}
	if err := s.bindings.Remove(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logWarn("breakglass", "break-glass session ended", map[string]any{"operator": claims.Sub, "id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ═══════════════════════════════════════════════════════════════════════════
// ELEVATION PROVIDERS — the "second IdP for JIT access" pattern (2026-09-07)
// ═══════════════════════════════════════════════════════════════════════════
//
// Owner, from customers: "in extreme secure environments they maintain
// different IdPs, one for regular auth and another one to maintain the JIT
// access." Break-glass above is the OPERATOR's version of that idea, opened
// from inside the product by the platform owner. This section is the
// CUSTOMER's version, opened from OUTSIDE it by a separately governed identity
// provider — which is what an environment that will not let the product decide
// who may elevate actually requires.
//
// The two share the artefact deliberately: an elevation is a role binding with
// a condition, a reason, a grantor and an expiry, so it lands in the same
// governance screen, the same audit trail and the same self-expiry as
// break-glass. What is new is only where the decision comes from.
//
// THE THREE REFUSALS, which are the reason the pattern is safe:
//   1. An elevation sign-in NEVER creates an account. Unknown ⇒ refused by
//      name, pointing at the standing provider.
//   2. It NEVER moves a tenant. The grant is stamped with the ACCOUNT's tenant;
//      a claim is not consulted and cannot be.
//   3. It NEVER changes the standing role. MergeFederated is not called at all
//      on this path — the stored account is read, not written.
//
// WHAT IT DOES NOT DO, stated so nobody assumes otherwise: an elevation binding
// does not (yet) widen the general permission decider. It is the credential a
// STEP-UP gate demands (elevatedOnly below), and it is recorded on every action
// taken while it is held. Making the elevated ROLE itself authoritative is the
// PBAC Phase-B union decider, a separate change to the whole authorization
// path; doing it here, one gate at a time, is how you get an inconsistent one.

// elevationProviderRefs renders the configured elevation doors for a refusal
// body. Reads the live provider list, so a provider added or removed from the
// admin UI is reflected in the next 403 without a restart.
func (s *server) elevationProviderRefs() []elevation.ProviderRef {
	p := s.oidcProvider()
	if !p.Ready() {
		return nil
	}
	var out []elevation.ProviderRef
	for _, pi := range p.ElevationProviders() {
		// A provider whose stored record has been DISABLED is not a door. The
		// store is optional (env-only deployments, and every harness that wires
		// SSO without it), so its absence means "no record to contradict the
		// button", not "no door".
		if s.ssoIdPCfg != nil {
			if c, ok := s.ssoIdPCfg.Get(pi.ID); ok && !c.Enabled {
				continue
			}
		}
		out = append(out, elevation.ProviderRef{ID: pi.ID, Name: pi.Name})
	}
	return out
}

// elevationConfigured reports whether this deployment has an elevation door at
// all.
//
// This is the switch that makes step-up ADDITIVE. Every existing deployment has
// no elevation provider, so every elevated-only route behaves exactly as it did
// before — anything else would mean shipping a change that locks operators out
// of routes they administer today, on the strength of a feature they have not
// configured. The gate turns on the moment an operator configures the door.
func (s *server) elevationConfigured() bool { return len(s.elevationProviderRefs()) > 0 }

// elevationPolicy resolves the rules for a provider alias. The stored record
// (Administration → SSO/IdP) is authoritative; a provider marked `elevation`
// only in the OIDC_PROVIDERS string — an env-only deployment with no GUI record
// — still elevates, under the package defaults, rather than silently behaving
// like a standing door.
func (s *server) elevationPolicy(alias string) (elevation.Policy, bool) {
	p := s.oidcProvider()
	if !p.Ready() {
		return elevation.Policy{}, false
	}
	pi, ok := p.ProviderByID(alias)
	if !ok {
		return elevation.Policy{}, false
	}
	var rec ssoIdPConfig
	stored := false
	if s.ssoIdPCfg != nil {
		rec, stored = s.ssoIdPCfg.Get(alias)
	}
	if stored && rec.IsElevation() {
		if !rec.Enabled {
			return elevation.Policy{}, false
		}
		e := rec.Elevation.Normalize()
		return elevation.Policy{
			Provider:    alias,
			TTLClaim:    e.TTLClaim,
			MaxMinutes:  e.MaxMinutes,
			ReasonClaim: e.ReasonClaim,
			ScopeClaim:  e.ScopeClaim,
		}, true
	}
	if stored && !rec.IsElevation() {
		return elevation.Policy{}, false // the record says standing; the record wins
	}
	if !pi.IsElevation() {
		return elevation.Policy{}, false
	}
	return elevation.Policy{Provider: alias, MaxMinutes: ssoidp.ElevationMaxMinutesDefault}, true
}

// elevationScopeID turns the resource id a token asked to be confined to into a
// canonical scope id, PROVING first that the resource belongs to the account's
// own tenant (§3a). A resource in another tenant is refused — never widened to
// the tenant scope, never accepted: a token that names someone else's device is
// either misconfigured or hostile, and both deserve the same answer.
//
// Only device resources are resolvable today; that is the one resource kind
// with an owning tenant the server can check. Any other kind is refused by
// name rather than accepted on faith.
func (s *server) elevationScopeID(u User, raw string) (string, error) {
	kind, id := "device", strings.TrimSpace(raw)
	if i := strings.IndexByte(id, ':'); i >= 0 {
		kind, id = strings.ToLower(strings.TrimSpace(id[:i])), strings.TrimSpace(id[i+1:])
	}
	if kind != "device" {
		return "", fmt.Errorf("elevation scope %q: only device resources can be verified", kind)
	}
	if id == "" {
		return "", errors.New("elevation scope names no resource")
	}
	claims := jwtClaims{Sub: u.Username, Role: u.Role, Tenant: u.TenantID}
	tenant, cross := principalTenant(claims)
	if s.discovery == nil {
		return "", errors.New("elevation scope cannot be verified: inventory unavailable")
	}
	for _, d := range s.discovery.Devices() {
		if d.ID != id {
			continue
		}
		if !canSeeDevice(d, tenant, cross) {
			// Same answer as an unknown device on purpose: confirming that the
			// id EXISTS in another tenant is itself a cross-tenant disclosure.
			break
		}
		return scopeTypeResource + ":device:" + id, nil
	}
	return "", errors.New("elevation scope names a resource this account cannot reach")
}

// elevationGrant is a VALIDATED but not yet persisted elevation grant. It is
// the output of prepareElevationGrant and the input to commitElevationGrant.
// Holding it as a value is the whole point of the split: everything that can
// refuse the sign-in happens while this is still only a value in memory.
type elevationGrant struct {
	binding RoleBinding
	expires time.Time
	source  string
}

// prepareElevationGrant turns a verified sign-in through an elevation provider
// into the one artefact it is allowed to produce — WITHOUT writing anything.
// The account is READ, never written: no UpsertFederated, no MergeFederated, no
// tenant, no role change.
//
// Every refusal an elevation sign-in owes (an expired window, a scope naming a
// resource the account cannot reach, an unavailable binding store) is made
// here, so the caller can run the remaining sign-in gates knowing that nothing
// durable exists yet. Nothing in this function touches s.bindings.
func (s *server) prepareElevationGrant(pol elevation.Policy, u User, role, sid string, claim elevation.Claim) (elevationGrant, error) {
	if s.bindings == nil {
		return elevationGrant{}, errors.New("role bindings are unavailable")
	}
	now := time.Now().UTC()
	notBefore, expires, source, ok := pol.Window(now, claim)
	if !ok {
		return elevationGrant{}, errors.New("the identity provider says this elevated access has already expired")
	}
	scopeID := scopeTenant(firstNonEmpty(u.TenantID, TenantGlobal))
	if raw, err := pol.Scope(claim); err != nil {
		return elevationGrant{}, err
	} else if raw != "" {
		resolved, serr := s.elevationScopeID(u, raw)
		if serr != nil {
			return elevationGrant{}, serr
		}
		scopeID = resolved
	}
	cond := map[string]any{
		ConditionElevation:         true,
		ConditionElevationProvider: pol.Provider,
		ConditionElevationTenant:   strings.ToLower(strings.TrimSpace(firstNonEmpty(u.TenantID, TenantGlobal))),
		"elevation_expiry_source":  source,
	}
	if sid != "" {
		cond[ConditionElevationSID] = sid
	}
	return elevationGrant{
		binding: RoleBinding{
			PrincipalID:   u.Username,
			PrincipalType: PrincipalUser,
			RoleID:        role,
			ScopeID:       scopeID,
			Effect:        EffectAllow,
			Condition:     cond,
			NotBefore:     &notBefore,
			ExpiresAt:     &expires,
			GrantedBy:     pol.Provider,
			Reason:        pol.Reason(claim),
		},
		expires: expires,
		source:  source,
	}, nil
}

// commitElevationGrant PERSISTS a prepared grant. It is deliberately the last
// durable write of an elevation sign-in: by the time it runs, the sign-in can no
// longer be refused, so live elevated access can never outlast a sign-in the
// server reported as failed (2026-09-07: elevation is a time-bound binding, not
// a standing grant, and a refused sign-in must leave none of it).
//
// Re-login REFRESHES rather than stacks: every elevation binding the principal
// holds is dropped first, so the second sign-in cannot leave the first one's
// (possibly wider, possibly longer) grant standing behind it. That has to be a
// sweep and not a same-id overwrite, because the deterministic binding id
// covers (principal, role, scope, effect) — a login that maps to a different
// role or a different resource would otherwise mint a SECOND live grant. The
// sweep lives here, not in prepare, for the same reason: a refused sign-in must
// not silently drop the elevated access the operator already holds either.
func (s *server) commitElevationGrant(r *http.Request, pol elevation.Policy, u User, g elevationGrant, sid string) (RoleBinding, error) {
	if s.bindings == nil {
		return RoleBinding{}, errors.New("role bindings are unavailable")
	}
	// Drop every prior elevation for this principal BEFORE adding the new one.
	for _, b := range s.bindings.ListByPrincipal(u.Username) {
		if !b.IsElevation() {
			continue
		}
		if err := s.bindings.Remove(b.ID); err != nil {
			return RoleBinding{}, fmt.Errorf("replace prior elevation: %w", err)
		}
	}
	b, err := s.bindings.Add(g.binding)
	if err != nil {
		return RoleBinding{}, err
	}
	logWarn("elevation", "elevated access granted", map[string]any{
		"user": u.Username, "provider": pol.Provider, "role": b.RoleID, "scope": b.ScopeID,
		"expires_at": g.expires.Format(time.RFC3339), "expiry_source": g.source, "binding": b.ID,
	})
	s.auditElevation(r, "ELEVATION_GRANTED", b, u.Username, u.TenantID, sid)
	return b, nil
}

// activeElevation returns the principal's live elevation grant, if any.
//
// It is also where EXPIRY is observed. An expired grant stops being honoured
// the instant Active() says so — there is no logout, no session change and no
// sweeper involved — and this is the first request that NOTICES, so it is where
// the grant is reaped and the expiry is audited. Reaping is best-effort: a
// store that will not delete must not turn an expired (already powerless)
// binding into a failed request.
func (s *server) activeElevation(r *http.Request, principalID, tenant string) (RoleBinding, bool) {
	if s.bindings == nil || strings.TrimSpace(principalID) == "" {
		return RoleBinding{}, false
	}
	now := time.Now().UTC()
	want := strings.ToLower(strings.TrimSpace(tenant))
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if !b.IsElevation() || b.Effect != EffectAllow {
			continue
		}
		if !b.Active(now) {
			if err := s.bindings.Remove(b.ID); err != nil {
				logError("elevation", "expired elevation could not be reaped", map[string]any{
					"binding": b.ID, "user": principalID, "err": err.Error()})
			}
			logInfo("elevation", "elevated access expired", map[string]any{
				"user": principalID, "binding": b.ID, "provider": b.ConditionString(ConditionElevationProvider)})
			s.auditElevation(r, "ELEVATION_EXPIRED", b, principalID, tenant, "")
			continue
		}
		// A grant is spendable only in the tenant it was made in. The account's
		// tenant cannot move, so this normally always matches; it is here so a
		// platform owner viewing AS another tenant cannot spend a grant that was
		// never made there.
		if got := b.ConditionString(ConditionElevationTenant); got != "" && want != "" && got != want {
			continue
		}
		return b, true
	}
	return RoleBinding{}, false
}

// requireElevated is the STEP-UP gate. The caller must already be
// authenticated (withAuth) and must already have passed the route's own
// permission gate — elevation is an EXTRA credential, never a substitute for
// one. With no elevation provider configured it is a no-op, so the gate is
// additive for every deployment that has not opted in.
func (s *server) requireElevated(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return jwtClaims{}, false
	}
	if !s.elevationConfigured() {
		return claims, true
	}
	if _, held := s.activeElevation(r, claims.Sub, claims.Tenant); held {
		return claims, true
	}
	writeJSON(w, http.StatusForbidden, elevation.NewRefusal(s.elevationProviderRefs()))
	return jwtClaims{}, false
}

// elevatedOnly wraps a handler so the route demands an active elevation. Used
// at registration in main.go, which keeps the tag visible in the route table
// beside the route it applies to rather than buried in a handler.
func (s *server) elevatedOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.requireElevated(w, r); !ok {
			return
		}
		next(w, r)
	}
}

// elevatedOnlyMutations is elevatedOnly for a route whose READS and whose
// REVOCATIONS must stay reachable without elevation.
//
// Revocation is deliberately never gated. A safety control you cannot exercise
// without first passing the control is not a safety control — if the elevation
// IdP is down, an admin must still be able to take access away. So DELETE (and
// every read) goes through untouched; only the grant path steps up.
func (s *server) elevatedOnlyMutations(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
			next(w, r)
			return
		}
		if _, ok := s.requireElevated(w, r); !ok {
			return
		}
		next(w, r)
	}
}

// auditElevation records an elevation lifecycle event with the binding id, so
// the trail can answer "what did grant X do" by filtering on it.
func (s *server) auditElevation(r *http.Request, event string, b RoleBinding, actor, tenant, sid string) {
	if s.audit == nil {
		return
	}
	detail := map[string]any{
		"event": event, "provider": b.ConditionString(ConditionElevationProvider),
		"role": b.RoleID, "scope": b.ScopeID, "reason": b.Reason,
	}
	if b.ExpiresAt != nil {
		detail["expires_at"] = b.ExpiresAt.Format(time.RFC3339)
	}
	remote := ""
	if r != nil {
		remote = auditClientIP(r)
	}
	decision := "allow"
	if event == "ELEVATION_EXPIRED" || event == "ELEVATION_REVOKED" {
		decision = "deny"
	}
	s.audit.Record(AuditEvent{
		Actor: actor, Tenant: tenant, Method: "ELEVATION", Path: "/elevation/" + event,
		Decision: decision, Remote: remote, BindingID: b.ID, SessionID: sid, Detail: detail,
	})
}

// elevationStatus is what the account menu renders: whether elevated access is
// live, where it came from and when it ends. Never the binding's condition map
// verbatim — a UI does not need the IdP session id.
type elevationStatus struct {
	Active     bool                    `json:"active"`
	BindingID  string                  `json:"binding_id,omitempty"`
	Provider   string                  `json:"provider,omitempty"`
	Role       string                  `json:"role,omitempty"`
	Scope      string                  `json:"scope,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	ExpiresAt  string                  `json:"expires_at,omitempty"`
	Configured bool                    `json:"configured"`
	Providers  []elevation.ProviderRef `json:"elevation_providers"`
}

// handleElevation: GET the caller's OWN elevated-access state; DELETE ends it.
// Self-scoped by construction — the principal id is the token's subject and is
// never taken from the request, so there is no cross-tenant read to make.
//
// DELETE here is "step down", the counterpart of the admin revoke on
// /api/bindings/{id}. Ending your own elevation must never need a permission.
func (s *server) handleElevation(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		st := elevationStatus{Providers: s.elevationProviderRefs()}
		st.Configured = len(st.Providers) > 0
		if st.Providers == nil {
			st.Providers = []elevation.ProviderRef{}
		}
		if b, held := s.activeElevation(r, claims.Sub, claims.Tenant); held {
			st.Active = true
			st.BindingID = b.ID
			st.Provider = b.ConditionString(ConditionElevationProvider)
			st.Role, st.Scope, st.Reason = b.RoleID, b.ScopeID, b.Reason
			if b.ExpiresAt != nil {
				st.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
			}
		}
		writeJSON(w, http.StatusOK, st)
	case http.MethodDelete:
		b, held := s.activeElevation(r, claims.Sub, claims.Tenant)
		if !held {
			w.WriteHeader(http.StatusNoContent) // idempotent: already down
			return
		}
		if err := s.bindings.Remove(b.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logWarn("elevation", "elevated access ended by the holder", map[string]any{
			"user": claims.Sub, "binding": b.ID})
		s.auditElevation(r, "ELEVATION_REVOKED", b, claims.Sub, claims.Tenant, claims.Sid)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
