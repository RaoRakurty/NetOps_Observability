package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
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

// contactPointType enumerates the supported destination kinds.
const (
	contactEmail   = "email"
	contactSlack   = "slack"
	contactWebhook = "webhook"
)

// ContactPoint is one reusable audience. Email-type points carry an address
// list (a distribution group); slack/webhook carry a target URL. No secrets live
// here — the SMTP transport/credentials stay in smtpConfig.
type ContactPoint struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id,omitempty"` // owner; "" = platform/global
	Name     string   `json:"name"`
	Type     string   `json:"type"` // email | slack | webhook
	Email    []string `json:"email,omitempty"`
	Target   string   `json:"target,omitempty"` // slack/generic webhook URL
	Enabled  bool     `json:"enabled"`
}

type contactPointStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]ContactPoint
}

func newContactPointStore(path string) (*contactPointStore, error) {
	if path == "" {
		path = "/data/contact_points.json"
	}
	s := &contactPointStore{path: path, items: make(map[string]ContactPoint)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *contactPointStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return nil // absent store → empty (errors.Is(os.ErrNotExist) for both backends)
	}
	var list []ContactPoint
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, c := range list {
		s.items[c.ID] = c
	}
	return nil
}

func (s *contactPointStore) flushLocked() error {
	list := make([]ContactPoint, 0, len(s.items))
	for _, c := range s.items {
		list = append(list, c)
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// List returns all contact points sorted by name (handler applies tenant scope).
func (s *contactPointStore) List() []ContactPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ContactPoint, 0, len(s.items))
	for _, c := range s.items {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *contactPointStore) Get(id string) (ContactPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[id]
	return c, ok
}

// validateContactPoint normalizes and checks a point. Pure (no I/O) so it is
// unit-testable and shared by Upsert.
func validateContactPoint(c ContactPoint) (ContactPoint, error) {
	c.Name = strings.TrimSpace(c.Name)
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	c.Target = strings.TrimSpace(c.Target)
	if c.Name == "" {
		return ContactPoint{}, errors.New("name required")
	}
	switch c.Type {
	case contactEmail:
		seen := map[string]bool{}
		clean := make([]string, 0, len(c.Email))
		for _, e := range c.Email {
			e = strings.TrimSpace(e)
			if e == "" || seen[strings.ToLower(e)] {
				continue
			}
			if !strings.Contains(e, "@") {
				return ContactPoint{}, fmt.Errorf("invalid email address %q", e)
			}
			seen[strings.ToLower(e)] = true
			clean = append(clean, e)
		}
		if len(clean) == 0 {
			return ContactPoint{}, errors.New("an email contact point needs at least one address")
		}
		c.Email = clean
		c.Target = ""
	case contactSlack, contactWebhook:
		if c.Target == "" {
			return ContactPoint{}, fmt.Errorf("a %s contact point needs a target URL", c.Type)
		}
		c.Email = nil
	default:
		return ContactPoint{}, fmt.Errorf("unknown contact point type %q (want email|slack|webhook)", c.Type)
	}
	return c, nil
}

// Upsert validates and stores a contact point, minting an id on create.
func (s *contactPointStore) Upsert(c ContactPoint) (ContactPoint, error) {
	c, err := validateContactPoint(c)
	if err != nil {
		return ContactPoint{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == "" {
		c.ID = "cp_" + randHex(8)
	}
	prev, existed := s.items[c.ID]
	s.items[c.ID] = c
	if err := s.flushLocked(); err != nil {
		if existed {
			s.items[c.ID] = prev
		} else {
			delete(s.items, c.ID)
		}
		return ContactPoint{}, err
	}
	return c, nil
}

func (s *contactPointStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return errors.New("no such contact point")
	}
	delete(s.items, id)
	return s.flushLocked()
}

// resolveEmailRecipients returns the de-duplicated set of email addresses across
// the named email-type contact points that the given tenant scope may use. Phase
// 2 (report delivery) calls this to turn a report's contact-point ids into a
// recipient list. Disabled points and points outside the caller's tenant are
// skipped. Non-email types are ignored here (resolved per-type at send time).
func (s *contactPointStore) resolveEmailRecipients(ids []string, tenant string, cross bool) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		c, ok := s.items[id]
		if !ok || !c.Enabled || c.Type != contactEmail {
			continue
		}
		if !sameTenant(c.TenantID, tenant, cross) {
			continue
		}
		for _, e := range c.Email {
			if k := strings.ToLower(e); !seen[k] {
				seen[k] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// resolveWebhookPoints returns the enabled slack/webhook-type contact points in
// scope with a usable target — the non-email delivery destinations for a report.
func (s *contactPointStore) resolveWebhookPoints(ids []string, tenant string, cross bool) []ContactPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ContactPoint
	for _, id := range ids {
		c, ok := s.items[id]
		if !ok || !c.Enabled || c.Target == "" {
			continue
		}
		if c.Type != contactSlack && c.Type != contactWebhook {
			continue
		}
		if sameTenant(c.TenantID, tenant, cross) {
			out = append(out, c)
		}
	}
	return out
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
