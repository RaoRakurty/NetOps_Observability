package backend

// wireless_http.go — read-only API surface over the wireless canonical
// inventory (tracker #128 Phase 1). Writers are platform-side connectors
// (Phase 2); nothing here mutates.
//
// §3a: every list is scoped by the principal's tenant (default-closed);
// a cross-tenant resource id returns 404, never 403 — another tenant's id
// must not be revealed as existing.

import (
	"context"
	"net/http"
	"strings"
)

// handleWirelessListOrGet is the shared GET list-or-get surface (#147 T4) for
// the controller and AP inventories. §3a: the list is scoped by the principal's
// tenant; a cross-tenant (or absent) id reads as 404 — another tenant's id must
// not be revealed as existing.
func handleWirelessListOrGet[L, T any](s *server, w http.ResponseWriter, r *http.Request, prefix string,
	list func(ctx context.Context, tenant string, cross bool) (L, error),
	get func(ctx context.Context, tenant string, cross bool, id string) (T, bool, error)) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if id == "" {
		out, err := list(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	v, found, err := get(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleWirelessControllers — GET /api/wireless/controllers[/{id}].
func (s *server) handleWirelessControllers(w http.ResponseWriter, r *http.Request) {
	handleWirelessListOrGet(s, w, r, "/api/wireless/controllers",
		s.wireless.ListControllers, s.wireless.GetController)
}

// handleWirelessAPs — GET /api/wireless/aps[/{id}].
func (s *server) handleWirelessAPs(w http.ResponseWriter, r *http.Request) {
	handleWirelessListOrGet(s, w, r, "/api/wireless/aps",
		s.wireless.ListAPs, s.wireless.GetAP)
}

// handleWirelessWLANs — GET /api/wireless/wlans.
func (s *server) handleWirelessWLANs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	out, err := s.wireless.ListWLANs(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleWirelessBSSIDs — GET /api/wireless/bssids.
func (s *server) handleWirelessBSSIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	out, err := s.wireless.ListBSSIDs(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
