package backend

// cloud_slo.go — main-side wiring for per-tenant SLOs / error budgets
// (cloud/slo.go, extracted P2 RA.9). This file keeps the env path, the
// principal resolution, the VM transport injection and the handler; the
// store (three-state load, refuse-to-overwrite-unread, rollback), the
// validator, the budget math and the measurement live in the package.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
)

const (
	cloudSLOMaxPerTenant = cloud.SLOMaxPerTenant
	cloudSLOQueryTimeout = 6 * time.Second
)

type (
	cloudSLO       = cloud.SLO
	cloudSLOStatus = cloud.SLOStatus
	cloudSLOStore  = cloud.SLOStore
)

func cloudSLOPath() string {
	if p := strings.TrimSpace(os.Getenv("CLOUD_SLO_PATH")); p != "" {
		return p
	}
	return "/data/cloud_slos.json"
}

func newCloudSLOStore(path string) *cloudSLOStore { return cloud.NewSLOStore(path) }

// handleCloudSLOs serves GET/PUT /api/cloud/slos.
func (s *server) handleCloudSLOs(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string, withStatus bool) {
		defs := s.cloudSLOs.List(tenant)
		type row struct {
			cloudSLO
			Status *cloudSLOStatus `json:"status,omitempty"`
		}
		rows := make([]row, 0, len(defs))
		if withStatus && len(defs) > 0 {
			res, _, _, err := s.cloudResources(r)
			idx := map[string][]string{}
			if err == nil {
				for _, cr := range res {
					if cr.AppName == "" {
						continue
					}
					k := strings.ToLower(cr.AppName)
					idx[k] = append(idx[k], cr.ResourceID)
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), cloudSLOQueryTimeout)
			defer cancel()
			for _, d := range defs {
				st := cloud.MeasureSLO(ctx, d, idx, vmQuery)
				rows = append(rows, row{cloudSLO: d, Status: &st})
			}
		} else {
			for _, d := range defs {
				rows = append(rows, row{cloudSLO: d})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": tenant, "slos": rows, "count": len(rows),
			"max_slos": cloudSLOMaxPerTenant,
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant, true)
	case http.MethodPut:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			SLOs  []cloudSLO `json:"slos"`
			Reset bool       `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		var defs []cloudSLO
		if !body.Reset {
			var err error
			if defs, err = cloud.NormalizeSLOs(body.SLOs); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.cloudSLOs.Set(tenant, defs); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("SLOs were not saved"))
			return
		}
		if s.audit != nil {
			apps := make([]string, 0, len(defs))
			for _, d := range defs {
				apps = append(apps, d.AppName)
			}
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_cloud_slos", "apps": apps, "reset": body.Reset},
			})
		}
		writeState(tenant, true)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}
