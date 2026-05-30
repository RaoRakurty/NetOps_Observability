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
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.snmpCreds.List())
	case http.MethodPost:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		var c SNMPCredential
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
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
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		var c SNMPCredential
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		c.ID = id
		saved, err := s.snmpCreds.Upsert(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
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
