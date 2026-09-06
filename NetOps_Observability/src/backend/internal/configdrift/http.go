// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"netops/backend/internal/configstore"
)

// http.go — the bulk drift list: GET /api/config/drift?state=&cursor=&limit=.
//
// The per-device status route lives in internal/configstore (it already owns the
// /api/devices/{id}/config subtree); this package supplies the verdict behind it
// through StatusFor. The bulk list is here because it is a DRIFT query, not a
// device query: the caller is asking "which of my devices are out of sync",
// which is this package's model.
//
// §3a: own-only. The list is paged with a keyset cursor INSIDE the tenant scope,
// so no cursor value a caller can invent pages into another tenant's devices.

// StatusFor is the configstore.StatusSource: one device's badge status. It is
// wired into the device subtree handler, which has ALREADY authorized the caller
// and confirmed the device is visible — this function only reads the row.
func (e *Evaluator) StatusFor(ctx context.Context, tenant string, cross bool, deviceID string) (configstore.DriftStatus, bool, error) {
	st, ok, err := e.deps.Store.Get(ctx, tenant, cross, deviceID)
	if err != nil || !ok {
		return configstore.DriftStatus{}, false, err
	}
	return toStatus(st), true, nil
}

// toStatus projects a stored row onto the API shape. Optional fields are real
// nulls, never zero values dressed as data: a device with no golden baseline
// reports golden_sha: null, not "".
func toStatus(st State) configstore.DriftStatus {
	out := configstore.DriftStatus{State: st.State, LastError: st.LastError}
	if out.State == "" {
		out.State = StateUnknown
	}
	if st.LastSHA != "" {
		sha := st.LastSHA
		out.LastSHA = &sha
	}
	if st.GoldenSHA != "" {
		sha := st.GoldenSHA
		out.GoldenSHA = &sha
	}
	if !st.LastCapture.IsZero() {
		at := st.LastCapture.UTC()
		out.LastCapture = &at
	}
	return out
}

// driftItem is one row of the bulk list: the per-device status object plus the
// device name the inventory badge renders next to it.
type driftItem struct {
	DeviceID    string     `json:"device_id"`
	DeviceName  string     `json:"device_name"`
	State       string     `json:"state"`
	LastSHA     *string    `json:"last_sha"`
	GoldenSHA   *string    `json:"golden_sha"`
	LastCapture *time.Time `json:"last_capture_at"`
	LastError   string     `json:"last_error,omitempty"`
	Added       int        `json:"added,omitempty"`
	Removed     int        `json:"removed,omitempty"`
}

// HandleDriftList serves GET /api/config/drift.
func (e *Evaluator) HandleDriftList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, ok := e.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	// Reject unknown query parameters rather than ignoring them: a typo'd
	// ?states= that silently returns everything reads as "nothing is drifted".
	//
	// as_tenant is the ONE exception, and it is the platform-wide convention
	// (httppage.alwaysAllowedQuery, parsercov, secapi): the acting-tenant
	// switcher is applied UPSTREAM of this handler by the auth middleware, which
	// folds it into the claims Deps.Authz resolves — so by the time we run it has
	// already become p.Tenant/p.Cross and there is nothing here to do with it but
	// let it through. It can only ever NARROW (principalTenant honours it for the
	// platform owner; a non-owner's selection is applied only to a tenant it
	// actually reaches, and is otherwise IGNORED), so accepting it cannot widen
	// this list. Refusing it with a 400 — the previous behaviour — did not make
	// the endpoint safer, it just made the drift page the one surface the
	// selector could not reach.
	for k := range q {
		switch k {
		case "state", "cursor", "limit", "as_tenant":
		default:
			e.deps.WriteError(w, http.StatusBadRequest, errors.New("unknown query parameter: "+k))
			return
		}
	}
	state := q.Get("state")
	if state != "" && !ValidState(state) {
		e.deps.WriteError(w, http.StatusBadRequest,
			errors.New("state must be one of in_sync, changed, drifted, unknown"))
		return
	}
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			e.deps.WriteError(w, http.StatusBadRequest, errors.New("limit must be a positive integer"))
			return
		}
		limit = n
	}
	rows, next, total, err := e.deps.Store.List(r.Context(), p.Tenant, p.Cross, state, q.Get("cursor"), limit)
	if err != nil {
		e.deps.LogError("drift list failed", map[string]any{"error": e.deps.Scrub(err.Error())})
		e.deps.WriteError(w, http.StatusInternalServerError, errors.New("configuration drift is unavailable"))
		return
	}
	names := e.deviceNames(p)
	items := make([]driftItem, 0, len(rows))
	for _, st := range rows {
		s := toStatus(st)
		items = append(items, driftItem{
			DeviceID: st.DeviceID, DeviceName: names[st.DeviceID],
			State: s.State, LastSHA: s.LastSHA, GoldenSHA: s.GoldenSHA,
			LastCapture: s.LastCapture, LastError: s.LastError,
			Added: st.Added, Removed: st.Removed,
		})
	}
	var cursor any
	if next != "" {
		cursor = next
	}
	e.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"items": items, "next_cursor": cursor, "total": total,
	})
}

// deviceNames resolves the caller's device id → name map. A cross-tenant caller
// gets no names rather than a fleet-wide enumeration built here — the inventory
// API is where a platform admin lists every device.
func (e *Evaluator) deviceNames(p Principal) map[string]string {
	out := map[string]string{}
	if e.deps.Devices == nil || p.Cross {
		return out
	}
	for _, d := range e.deps.Devices(p.Tenant) {
		out[d.ID] = d.Name
	}
	return out
}
