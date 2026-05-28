package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// REST surface for saved objects:
//   GET    /api/saved          list (optional ?type=saved_search|dashboard|report)
//   POST   /api/saved          create  {type,name,body}
//   GET    /api/saved/{id}     fetch one
//   PUT    /api/saved/{id}     update  {name?,body?}
//   DELETE /api/saved/{id}     remove

type savedRequest struct {
	Type string          `json:"type"`
	Name string          `json:"name"`
	Body json.RawMessage `json:"body"`
}

func (s *server) handleSaved(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.saved.List(r.URL.Query().Get("type")))
	case http.MethodPost:
		claims, _ := userFrom(r.Context())
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		obj, err := s.saved.Create(req.Type, strings.TrimSpace(req.Name), claims.Sub, req.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("saved", "created", map[string]any{"id": obj.ID, "type": obj.Type, "owner": obj.Owner})
		writeJSON(w, http.StatusCreated, obj)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSavedByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/saved/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		obj, ok := s.saved.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodPut:
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		obj, err := s.saved.Update(id, strings.TrimSpace(req.Name), req.Body)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodDelete:
		if err := s.saved.Delete(id); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
