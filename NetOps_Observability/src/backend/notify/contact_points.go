package notify

// contact_points.go — reusable, tenant-scoped notification audiences (Phase 1
// of docs/design/contact-points-and-report-delivery.md; extracted P2 RA.13).
//
// A contact point is a named destination an operator defines ONCE and reuses.
// This is an ADDITIVE routing layer — it does NOT replace the Dispatcher
// channel registry or touch the alert path; a point is RESOLVED to a concrete
// send at delivery time. The RESOLUTION GATES here are the tenant wall for
// outbound delivery: a report's contact-point ids only ever expand to
// addresses/targets the owning tenant may use — the cross-tenant recipient
// leak lives (and is fenced) HERE, not in the handlers.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netops/backend/internal/platformdb"
)

// Contact point types (the closed destination vocabulary).
const (
	ContactEmail   = "email"
	ContactSlack   = "slack"
	ContactWebhook = "webhook"
)

// ContactPoint is one reusable audience. Email-type points carry an address
// list (a distribution group); slack/webhook carry a target URL. No secrets
// live here — the SMTP transport/credentials stay in SMTPConfig.
type ContactPoint struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id,omitempty"` // owner; "" = platform/global
	Name     string   `json:"name"`
	Type     string   `json:"type"` // email | slack | webhook
	Email    []string `json:"email,omitempty"`
	Target   string   `json:"target,omitempty"` // slack/generic webhook URL
	Enabled  bool     `json:"enabled"`
}

// ContactPointStore is the file-kv-backed registry.
type ContactPointStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]ContactPoint
}

// NewContactPointStore opens the registry ("" → the standard location).
func NewContactPointStore(path string) (*ContactPointStore, error) {
	if path == "" {
		path = "/data/contact_points.json"
	}
	s := &ContactPointStore{path: path, items: make(map[string]ContactPoint)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ContactPointStore) load() error {
	b, err := platformdb.Load(s.path)
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

func (s *ContactPointStore) flushLocked() error {
	list := make([]ContactPoint, 0, len(s.items))
	for _, c := range s.items {
		list = append(list, c)
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// List returns all contact points sorted by name (handler applies tenant scope).
func (s *ContactPointStore) List() []ContactPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ContactPoint, 0, len(s.items))
	for _, c := range s.items {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one point by id.
func (s *ContactPointStore) Get(id string) (ContactPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[id]
	return c, ok
}

// ValidateContactPoint normalizes and checks a point. Pure (no I/O) so it is
// unit-testable and shared by Upsert.
func ValidateContactPoint(c ContactPoint) (ContactPoint, error) {
	c.Name = strings.TrimSpace(c.Name)
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	c.Target = strings.TrimSpace(c.Target)
	if c.Name == "" {
		return ContactPoint{}, errors.New("name required")
	}
	switch c.Type {
	case ContactEmail:
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
	case ContactSlack, ContactWebhook:
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
func (s *ContactPointStore) Upsert(c ContactPoint) (ContactPoint, error) {
	c, err := ValidateContactPoint(c)
	if err != nil {
		return ContactPoint{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == "" {
		c.ID = "cp_" + contactPointID()
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

// Delete removes a point (the handler has already fenced the tenant).
func (s *ContactPointStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return errors.New("no such contact point")
	}
	delete(s.items, id)
	return s.flushLocked()
}

// ResolveEmailRecipients returns the de-duplicated set of email addresses
// across the named email-type contact points that the given tenant scope may
// use. Report delivery calls this to turn a report's contact-point ids into a
// recipient list. Disabled points and points outside the caller's tenant are
// skipped. Non-email types are ignored here (resolved per-type at send time).
func (s *ContactPointStore) ResolveEmailRecipients(ids []string, tenant string, cross bool) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		c, ok := s.items[id]
		if !ok || !c.Enabled || c.Type != ContactEmail {
			continue
		}
		if !scopeAllows(c.TenantID, tenant, cross) {
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

// ResolveWebhookPoints returns the enabled slack/webhook-type contact points in
// scope with a usable target — the non-email delivery destinations for a report.
func (s *ContactPointStore) ResolveWebhookPoints(ids []string, tenant string, cross bool) []ContactPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ContactPoint
	for _, id := range ids {
		c, ok := s.items[id]
		if !ok || !c.Enabled || c.Target == "" {
			continue
		}
		if c.Type != ContactSlack && c.Type != ContactWebhook {
			continue
		}
		if scopeAllows(c.TenantID, tenant, cross) {
			out = append(out, c)
		}
	}
	return out
}

// scopeAllows mirrors main's sameTenant rule (pinned in lock-step): cross sees
// everything; a scoped caller matches its own tenant exactly (case/space-
// insensitive) and global/untagged never matches a scoped tenant.
func scopeAllows(resourceTenant, principalTenant string, cross bool) bool {
	if cross {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}

// contactPointID mints an id (a failed entropy read degrades to a zero id,
// never a panic).
func contactPointID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
