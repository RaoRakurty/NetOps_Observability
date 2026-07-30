package backend

// cloud_resource_detail.go — Wave 6 #20: the permanent per-resource read.
// GET /api/cloud/resources/{id} returns ONE cloud resource by its canonical
// opaque id, within the caller's tenant scope. Backs the #/resource/cloud/{id}
// detail page: the id in the URL is the resource_id, and a cross-tenant or
// unknown id is an indistinguishable 404 (§3a.1 — never reveal another
// tenant's id). Rides the same store read, manual-override overlay, live-state
// join and console-link resolver as the list surface, so the detail page can
// never disagree with the table it was opened from.

import (
	"net/http"
	"net/url"
	"strings"

	"netops/backend/cloud"
)

func (s *server) handleCloudResourceByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only", "method_not_allowed")
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/api/cloud/resources/")
	id, err := url.PathUnescape(raw)
	if err != nil || id == "" || strings.Contains(id, "/") {
		writeJSONError(w, http.StatusNotFound, "resource not found", "not_found")
		return
	}
	tenant, cross := principalTenant(claims)
	res, found, err := s.cloud.GetResource(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		// Unknown and other-tenant ids are the SAME answer (§3a.1).
		writeJSONError(w, http.StatusNotFound, "resource not found", "not_found")
		return
	}
	one := []cloud.CloudResource{res}
	// Manual operator overrides win over inference everywhere this inventory
	// is read — the detail page must agree with the Resources table.
	if err := s.overlayManualMappings(r, tenant, cross, one); err != nil {
		// Never show the inferred guess where an operator-CONFIRMED assignment
		// exists but could not be read (§10).
		writeError(w, http.StatusBadGateway, err)
		return
	}
	body := map[string]any{"resource": one[0]}
	// Live state (provider status / traffic / active checks). Absent feeds stay
	// absent — unknown is never rendered as healthy.
	if st, ok := s.cloudLiveStates(r.Context(), chTenantScope(r), one)[one[0].ResourceID]; ok {
		body["health"] = st.Health
		body["health_basis"] = st.HealthBasis
		if st.TrafficBytes != nil {
			body["traffic_bytes"] = *st.TrafficBytes
		}
		if st.CPUPct != nil {
			body["cpu_pct"] = *st.CPUPct
		}
	}
	if u := resourceConsoleURL(one[0]); u != "" {
		body["console_url"] = u
	}
	writeJSON(w, http.StatusOK, body)
}
