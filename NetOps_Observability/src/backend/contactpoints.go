// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/notify"
	"strings"
)

// contactpoints.go — reusable, tenant-scoped notification audiences (Phase 1 of
// docs/design/contact-points-and-report-delivery.md).
//
// A contact point is a named destination an operator defines ONCE and reuses:
// an email distribution list ("NOC On-call"), a Slack webhook, a generic
// webhook. Reports (and, later, alerts) reference contact points by id instead
// of carrying raw recipient strings, so audiences are managed in one place and
// scoped to a tenant.
//
// This is an ADDITIVE routing layer — it does NOT replace the notify.Dispatcher
// channel registry or touch the alert path. A contact point is RESOLVED to a
// concrete send at delivery time (Phase 2) by reusing the existing notify
// constructors with the point's recipients; no global channel state is mutated.

// The model, store, validator and the tenant-fenced RESOLUTION GATES live in
// notify/contact_points.go (P2 RA.13); this file keeps the admin handlers
// (principal resolution, the 404-not-403 probe fence, owner stamping).

type (
	ContactPoint      = notify.ContactPoint
	contactPointStore = notify.ContactPointStore
)

func newContactPointStore(path string) (*contactPointStore, error) {
	return notify.NewContactPointStore(path)
}

// ---- handlers (admin-gated, tenant-scoped) ---------------------------------

func (s *server) handleContactPoints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "administration", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out := make([]ContactPoint, 0)
		for _, c := range s.contactPoints.List() {
			if sameTenant(c.TenantID, tenant, cross) {
				out = append(out, c)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var c ContactPoint
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if c.ID != "" {
			if existing, found := s.contactPoints.Get(c.ID); found && !sameTenant(existing.TenantID, tenant, cross) {
				writeError(w, http.StatusNotFound, errors.New("no such contact point"))
				return
			}
		}
		if !cross {
			c.TenantID = tenant // a scoped admin can only own points in its tenant
		}
		saved, err := s.contactPoints.Upsert(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, saved)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleContactPointByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/notify/contact-points/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid contact point id"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	// Strict isolation: 404 (not 403) when out of the caller's tenant so other
	// tenants' ids aren't probeable.
	tenant, cross := principalTenant(claims)
	existing, found := s.contactPoints.Get(id)
	if !found || !sameTenant(existing.TenantID, tenant, cross) {
		writeError(w, http.StatusNotFound, errors.New("no such contact point"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		var c ContactPoint
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		c.ID = id
		if !cross {
			c.TenantID = tenant // can't re-home into another tenant
		} else if c.TenantID == "" {
			c.TenantID = existing.TenantID
		}
		saved, err := s.contactPoints.Upsert(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if err := s.contactPoints.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
