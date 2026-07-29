package main

// verify_http.go — Active Verification HTTP surface (RCA spec item 8):
//
//   GET  /api/correlations/{id}/verify — latest run + per-check results
//        (infrastructure:read; cross-tenant case → 404)
//   POST /api/correlations/{id}/verify — manual "Verify now"
//        (infrastructure:write; rate-limited per tenant; audited; cross-tenant
//        case → 404; tenant opt-in + FEATURE_ACTIVE_VERIFICATION required)
//   GET/PUT /api/settings/verification — tenant opt-in flag + read-only SSH
//        credential (PUT admin-only + audited; secrets write-only)
//
// Dormant posture: with FEATURE_ACTIVE_VERIFICATION unset the correlation
// subresource is a 404 (capability not disclosed), matching device_ssh.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/verify"
)

// handleCorrelationVerify serves GET/POST /api/correlations/{id}/verify.
// The id was already shape-validated by handleCorrelationByID.
func (s *server) handleCorrelationVerify(w http.ResponseWriter, r *http.Request, id string) {
	if !s.verifyFeatureOn() {
		http.NotFound(w, r) // dormant: don't disclose the capability
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		scope := tenant
		if cross {
			scope = "__all__"
		}
		row, found := s.verifyCaseLookup(r.Context(), scope, id)
		if !found {
			http.NotFound(w, r) // out-of-tenant: never reveal the id exists
			return
		}
		caseTenant := row.TenantID
		if caseTenant == "" {
			caseTenant = tenant
		}
		resp := map[string]any{
			"enabled": s.verifyEnabledFor(caseTenant),
			"run":     nil,
		}
		if rec, ok := s.verifyRuns.Latest(caseTenant, id); ok {
			resp["run"] = rec
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		scope := tenant
		if cross {
			scope = "__all__"
		}
		// Rate limit keyed by the AUTHENTICATED tenant (never client IP).
		if !s.verifyLimiter.AllowN("verify:"+tenant, envInt("VERIFY_RATE_PER_MIN", 6)) {
			writeError(w, http.StatusTooManyRequests, errors.New("verification rate limit reached — try again shortly"))
			return
		}
		row, found := s.verifyCaseLookup(r.Context(), scope, id)
		if !found {
			http.NotFound(w, r) // cross-tenant write refused as not-found (§3a)
			return
		}
		if row.State != "open" {
			writeError(w, http.StatusConflict, fmt.Errorf("case is %s — verification runs only against open cases", row.State))
			return
		}
		caseTenant := row.TenantID
		if caseTenant == "" {
			caseTenant = tenant
		}
		why := fmt.Sprintf("manual verify (case verdict %s)", row.Verdict)
		rec, err := s.startVerificationRun(caseTenant, id, "manual", claims.Sub, why, row.Devices, row.caseContext())
		switch {
		case errors.Is(err, verify.ErrDisabled):
			writeError(w, http.StatusForbidden, errors.New("active verification is not enabled for this tenant — opt in under Settings"))
		case errors.Is(err, errVerifyRunning):
			writeError(w, http.StatusConflict, err)
		case errors.Is(err, errVerifyNoTargets):
			writeError(w, http.StatusUnprocessableEntity, err)
		case err != nil:
			writeError(w, http.StatusInternalServerError, err)
		default:
			writeJSON(w, http.StatusAccepted, map[string]any{
				"run_id": rec.RunID, "status": rec.Status, "devices": rec.Devices,
			})
		}

	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleVerificationSettings serves GET/PUT /api/settings/verification.
func (s *server) handleVerificationSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeJSON(w, http.StatusOK, s.verifyCfg.PublicView(tenant, s.verifyFeatureOn()))

	case http.MethodPut:
		// Tenant-scoped opt-in + credential → scope-aware admin gate (§3a rule
		// 3): a tenant admin configures its OWN tenant, never another's by id.
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var patch verifySettingsPatch
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		tenant, cross := principalTenant(claims)
		cfg, err := s.verifyCfg.Set(tenant, patch)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if s.audit != nil {
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{
					// No secret material — booleans about what changed only.
					"action":      "set_verification_config",
					"enabled":     cfg.Enabled,
					"ssh_user":    cfg.SSHUser,
					"ssh_secret":  patch.SSHPassword != "" || patch.SSHKey != "",
					"cleared_ssh": patch.ClearSSH,
				},
			})
		}
		writeJSON(w, http.StatusOK, s.verifyCfg.PublicView(tenant, s.verifyFeatureOn()))

	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}
