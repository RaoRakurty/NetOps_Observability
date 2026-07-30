package main

// cloud_monitors.go — per-tenant cloud monitor authoring (Wave 5 #14 slice 3).
// A monitor is a tenant-owned rule on ONE cloud metric of the closed catalog
// (cloud_metrics_series.go): either a threshold (above/below a value) or an
// anomaly toggle (deviation from the metric's own recent behaviour). Evaluated
// by the bounded poll loop in cloud_monitor_eval.go against the SAME
// tenant-scoped resource_id selectors the chart endpoint uses.
//
//	GET    /api/cloud/monitors        — list (alerts:read)
//	POST   /api/cloud/monitors        — create (alerts:write, audited)
//	GET    /api/cloud/monitors/{id}   — read one (cross-tenant id → 404)
//	PUT    /api/cloud/monitors/{id}   — update (alerts:write, audited)
//	DELETE /api/cloud/monitors/{id}   — delete (alerts:write, audited)
//
// §3a: the store is tenant-keyed (file/kv pattern of tenant_governance.go);
// TenantID is stamped from the principal, never the body; every by-id access
// resolves inside the caller's tenant bucket only.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
)

// The monitor store + metric registry moved to cloud/monitors.go (Phase-2
// W4.5). Aliases keep the evaluator, handlers and tests source-compatible.
type (
	cloudMonitor      = cloud.Monitor
	cloudMonitorStore = cloud.MonitorStore
)

const cloudMonitorsMaxPerTenant = cloud.MonitorsMaxPerTenant

func newCloudMonitorStore(path string) *cloudMonitorStore { return cloud.NewMonitorStore(path) }

func cloudMonitorsPath() string {
	if p := strings.TrimSpace(os.Getenv("CLOUD_MONITORS_PATH")); p != "" {
		return p
	}
	return "/data/cloud_monitors.json"
}

func (s *server) auditMonitor(r *http.Request, claims jwtClaims, action string, m cloudMonitor) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r),
		Detail: map[string]any{"action": action, "monitor_id": m.ID, "name": m.Name, "metric": m.Metric, "mode": m.Mode},
	})
}

// handleCloudMonitors serves GET/POST /api/cloud/monitors.
func (s *server) handleCloudMonitors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		list := s.cloudMonitors.List(tenant)
		if list == nil {
			list = []cloudMonitor{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"monitors": list, "count": len(list), "max_monitors": cloudMonitorsMaxPerTenant,
		})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		var body cloudMonitor
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		m, err := cloud.NormalizeMonitor(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		m.ID = randID()
		now := time.Now().UTC().Format(time.RFC3339)
		m.CreatedAt, m.UpdatedAt = now, now
		m.LastState = cloud.MonitorStateNever
		tenant, _ := principalTenant(claims) // §3a rule 2: owner from the token
		fits, err := s.cloudMonitors.Upsert(tenant, m)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not saved"))
			return
		}
		if !fits {
			writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d monitors per tenant", cloudMonitorsMaxPerTenant))
			return
		}
		m.TenantID = tenant
		s.auditMonitor(r, claims, "create_cloud_monitor", m)
		writeJSON(w, http.StatusCreated, m)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleCloudMonitorByID serves GET/PUT/DELETE /api/cloud/monitors/{id}.
func (s *server) handleCloudMonitorByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cloud/monitors/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, errors.New("monitor not found"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		m, found := s.cloudMonitors.Get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		writeJSON(w, http.StatusOK, m)
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		existing, found := s.cloudMonitors.Get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		var body cloudMonitor
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		m, err := cloud.NormalizeMonitor(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Definition changed → the old verdict no longer describes this rule.
		m.ID = existing.ID
		m.CreatedAt = existing.CreatedAt
		m.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		m.LastState = cloud.MonitorStateNever
		if _, err := s.cloudMonitors.Upsert(tenant, m); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not saved"))
			return
		}
		m.TenantID = tenant
		s.auditMonitor(r, claims, "update_cloud_monitor", m)
		writeJSON(w, http.StatusOK, m)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		m, found := s.cloudMonitors.Get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		if _, err := s.cloudMonitors.Delete(tenant, id); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not deleted"))
			return
		}
		s.auditMonitor(r, claims, "delete_cloud_monitor", m)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}
