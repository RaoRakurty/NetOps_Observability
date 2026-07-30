package backend

// onboard.go — operator-driven customer onboarding (the AWS Control-Tower /
// Azure-CSP analog): create an org AND its first tenant (the data boundary) in one
// audited, platform-owner-only step, so a customer is never left as a tenant-less
// org (which would have nowhere for data to land — see docs/design/org-tenant-model.md).
//
//	POST /api/onboard  { org_name, org_slug?, home_region?, sso_connection?,
//	                     tenant_name, tenant_slug?, isolation_mode?, operator_restricted? }
//	→ 201 { org, tenant }   (both carry opaque ids + slugs)
//
// Provisioning is a privileged control-plane action (requirePlatformAdmin) — the
// human operator onboards customers, never an unauthenticated/agentic actor. Org +
// tenant ids are minted opaque server-side; supplied slugs are validated/unique.

import (
	"encoding/json"
	"errors"
	"net/http"
)

type onboardRequest struct {
	OrgName       string `json:"org_name"`
	OrgSlug       string `json:"org_slug"`
	HomeRegion    string `json:"home_region"`
	SSOConnection string `json:"sso_connection"`

	TenantName         string `json:"tenant_name"`
	TenantSlug         string `json:"tenant_slug"`
	IsolationMode      string `json:"isolation_mode"`
	OperatorRestricted bool   `json:"operator_restricted"`
}

type onboardResponse struct {
	Org    Org    `json:"org"`
	Tenant Tenant `json:"tenant"`
}

func (s *server) handleOnboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	var req onboardRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.TenantName == "" {
		writeError(w, http.StatusBadRequest, errors.New("tenant_name required (an org must be onboarded with its first tenant)"))
		return
	}

	// 1) Org — opaque id minted, slug validated/unique, SSO bound at the org.
	org, err := s.orgs.Create(req.OrgName, req.OrgSlug, "", req.HomeRegion, req.SSOConnection)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// 2) First tenant under the new org (the data/isolation boundary).
	t, err := s.tenants.Create(req.TenantName, req.TenantSlug, "", req.IsolationMode, org.ID)
	if err != nil {
		// Roll back the org so a failed onboard never leaves a tenant-less shell.
		_ = s.orgs.Delete(org.ID)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// F-81: the error was discarded here too, so onboarding a customer who
	// requires operator-visibility restriction returned 201 with the switch OFF.
	// The rollback below already exists for a failed tenant create; a failed
	// PRIVACY control deserves exactly the same treatment.
	if req.OperatorRestricted {
		updated, e := s.tenants.SetOperatorRestricted(t.ID, true)
		if e != nil {
			logError("onboard", "operator_restricted could not be applied — rolling back",
				map[string]any{"tenant_id": t.ID, "err": e.Error()})
			if derr := s.tenants.Delete(t.ID); derr != nil {
				logError("onboard", "ROLLBACK FAILED — tenant exists and is NOT operator-restricted",
					map[string]any{"tenant_id": t.ID, "err": derr.Error()})
			}
			if derr := s.orgs.Delete(org.ID); derr != nil {
				logError("onboard", "org rollback failed", map[string]any{"org_id": org.ID, "err": derr.Error()})
			}
			writeError(w, http.StatusInternalServerError,
				errors.New("onboarding aborted: the operator-visibility restriction could not be applied"))
			return
		}
		t = updated
	}

	logInfo("onboard", "customer onboarded", map[string]any{
		"org_id": org.ID, "org_slug": org.Slug, "tenant_id": t.ID, "tenant_slug": t.Slug,
	})
	detail := auditOrgDetail(org)
	for k, v := range auditTenantDetail(t) {
		detail[k] = v
	}
	s.recordIdentityAudit(r, claims, "CUSTOMER_ONBOARDED", detail)

	writeJSON(w, http.StatusCreated, onboardResponse{Org: org, Tenant: t})
}
