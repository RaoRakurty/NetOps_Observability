package main

// snmp_handlers.go — CRUD for SNMP credential profiles, gated on
// infrastructure:write (managing how devices are polled is an infra task).
// Secrets are write-only: never returned, kept on update when omitted.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// handleSNMPOptions exposes the allowed enum values so the UI can render
// version/security-level/protocol dropdowns (SolarWinds-parity option set).
func (s *server) handleSNMPOptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"versions":        SNMPVersions,
		"security_levels": SNMPSecurityLevels,
		"auth_protocols":  SNMPAuthProtocols,
		"priv_protocols":  SNMPPrivProtocols,
	})
}

func (s *server) handleSNMPCreds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		// Tenant isolation: a scoped principal sees only its own credentials;
		// global/untagged creds are platform-owned (visible cross-tenant only).
		tenant, cross := principalTenant(claims)
		out := make([]publicSNMPCredential, 0)
		for _, c := range s.snmpCreds.List() {
			if sameTenant(c.TenantID, tenant, cross) {
				out = append(out, c)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var c SNMPCredential
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A scoped principal may only write within its own tenant: block
		// overwriting a credential it can't see, and force ownership to itself.
		tenant, cross := principalTenant(claims)
		if c.ID != "" {
			if existing, found := s.snmpCreds.Get(c.ID); found && !sameTenant(existing.TenantID, tenant, cross) {
				writeError(w, http.StatusNotFound, errors.New("no such credential"))
				return
			}
		}
		if !cross {
			c.TenantID = tenant
		}
		saved, err := s.snmpCreds.Upsert(c)
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

func (s *server) handleSNMPCredByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/snmp/credentials/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid credential id"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		// Strict isolation: 404 (not 403) when the credential is out of the
		// caller's tenant, so other tenants' ids aren't probeable.
		tenant, cross := principalTenant(claims)
		existing, found := s.snmpCreds.Get(id)
		if !found || !sameTenant(existing.TenantID, tenant, cross) {
			writeError(w, http.StatusNotFound, errors.New("no such credential"))
			return
		}
		var c SNMPCredential
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		c.ID = id
		if !cross {
			c.TenantID = tenant // a scoped principal can't re-home the credential
		}
		saved, err := s.snmpCreds.Upsert(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		existing, found := s.snmpCreds.Get(id)
		if !found || !sameTenant(existing.TenantID, tenant, cross) {
			writeError(w, http.StatusNotFound, errors.New("no such credential"))
			return
		}
		if err := s.snmpCreds.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
