package secapi

// store.go — the MUTABLE control-plane state behind the Security surface: which
// catalog rules a tenant runs, and the filter sets it saved. Two backends behind
// ONE interface (the rcafeedback/maintenance convention): FileStore for the
// default non-Postgres build and tests, pgStore for the Postgres build
// (migration 0037, tenant_iso FORCE-RLS through the injected WithTenant seam).
//
// Isolation is enforced IN the store (CLAUDE.md §3a rule 4): Postgres by the RLS
// policy, the file backend by a tenant-keyed map. There is deliberately no
// unscoped "list all" on either — not even an internal one — so a future caller
// cannot reach for the wrong method.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// Store bounds. A saved view is operator input, so both its count and its size
// are capped: an uncapped JSONB column is an unbounded write surface behind an
// authenticated endpoint (§9 bounded, §3 zero trust).
const (
	MaxViewsPerTenant = 100
	MaxViewNameLen    = 80
	MaxViewFiltersLen = 4096
	MaxRuleWrites     = 500
)

// ErrViewLimit is returned when a tenant already holds MaxViewsPerTenant views.
var ErrViewLimit = errors.New("secapi: saved-view limit reached for this tenant")

// ErrDuplicateView is returned when a view name is already taken in the tenant.
var ErrDuplicateView = errors.New("secapi: a saved view with that name already exists")

// RuleState is one stored enable/disable override.
type RuleState struct {
	RuleID    string    `json:"rule_id"`
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// SavedView is one named filter set. TenantID is stamped from the authenticated
// principal and is never serialized (§3a rule 2 + hygiene).
type SavedView struct {
	TenantID  string          `json:"-"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Filters   json.RawMessage `json:"filters"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitempty"`
}

// Store is the control-plane register. `cross` is the platform-owner
// cross-tenant flag from principalTenant(claims); a non-cross caller can never
// observe or mutate another tenant's rows through any method here.
type Store interface {
	// RuleStates returns the caller-visible overrides as rule id → enabled.
	RuleStates(ctx context.Context, tenant string, cross bool) (map[string]bool, error)
	// SetRuleStates upserts overrides. owner is the tenant the rows are stamped
	// with — derived from the authenticated principal by the handler, NEVER
	// from the request body.
	SetRuleStates(ctx context.Context, tenant string, cross bool, owner string, states []RuleState) error
	// Views lists the caller's saved views, name-ordered.
	Views(ctx context.Context, tenant string, cross bool) ([]SavedView, error)
	// AddView stores one view; the id and timestamp are minted here.
	AddView(ctx context.Context, tenant string, cross bool, v SavedView) (SavedView, error)
	// DeleteView removes one view by id. found=false means "not yours or not
	// there" — the caller answers 404 for both, so another tenant's id is
	// never confirmed to exist (§3a rule 1).
	DeleteView(ctx context.Context, tenant string, cross bool, id string) (found bool, err error)
}

// NormTenant is the single tenant-key normalization this package uses, matching
// the API boundary's (lowercase, trimmed).
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// newUUIDv4 mints an RFC-4122 v4 id. Duplicated per the no-shared-utils rule
// (CLAUDE.md §2: no "utils" dumping ground), same as rcafeedback/store.go.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// defaultFilters normalizes an absent filter blob to the empty JSON object.
// Both backends call it so a view stored through either one round-trips to the
// same shape (and so the JSONB column never receives a zero-length value).
func defaultFilters(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

// visible reports whether a caller scoped to `tenant` (or cross-tenant) may see
// rows owned by `owner`. The ONE place the file backend answers that question.
func visible(tenant string, cross bool, owner string) bool {
	return cross || owner == NormTenant(tenant)
}

// byName orders a view listing deterministically (case-insensitive name, id as
// the tiebreak) so a picker does not reshuffle between polls.
func byName(rows []SavedView) {
	sort.Slice(rows, func(i, j int) bool {
		li, lj := strings.ToLower(rows[i].Name), strings.ToLower(rows[j].Name)
		if li != lj {
			return li < lj
		}
		return rows[i].ID < rows[j].ID
	})
}

// ---- file backend (default build; tenant-filtered IN the store) -------------

// The on-disk shape. Both registers share one file because they share one
// lifecycle (a tenant's security-page configuration).
//
// fileRule carries the tenant explicitly (SavedView carries it as json:"-", so
// the rule rows need their own persisted owner field).
type fileRule struct {
	TenantID  string    `json:"tenant_id"`
	RuleID    string    `json:"rule_id"`
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// fileViewRow wraps a view with its persisted owner (SavedView.TenantID is
// json:"-" so that it can never be serialized to a CLIENT — the file is a
// different surface and must keep the owner).
type fileViewRow struct {
	TenantID  string          `json:"tenant_id"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Filters   json.RawMessage `json:"filters"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitempty"`
}

type filePayload struct {
	Rules []fileRule    `json:"rules"`
	Views []fileViewRow `json:"views"`
}

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory
// (tests); a real path is loaded at construction and rewritten on every write.
type FileStore struct {
	mu   sync.RWMutex
	path string
	// loadErr records a FAILED read of the state file. It exists because "the
	// file could not be read" and "there is nothing configured" are different
	// facts that would otherwise render identically: a tenant whose disabled
	// rules failed to load would see the full shipped catalog and have no way
	// to know its configuration was not applied (§10 no silent failures).
	loadErr error
	rules   map[string]map[string]fileRule    // tenant → rule id → override
	views   map[string]map[string]fileViewRow // tenant → view id → view
}

// LoadErr reports why the persisted state could not be read, or nil. The
// caller surfaces it at boot; a store that failed to load still SERVES (the
// shipped defaults), because refusing to boot over an unreadable preferences
// file would be worse — but the fact is never swallowed.
func (s *FileStore) LoadErr() error { return s.loadErr }

// NewFileStore loads persisted state; a missing or corrupt file starts empty
// (the maintenance/episode convention — this state is operator input, and a
// parse failure must not block boot).
func NewFileStore(path string) *FileStore {
	s := &FileStore{
		path:  path,
		rules: map[string]map[string]fileRule{},
		views: map[string]map[string]fileViewRow{},
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// NOT an error: the file has simply never been written. First boot with
		// nothing configured is the normal state, and logging it would train
		// operators to ignore this line — which is how the real failure below
		// gets missed.
		return s
	case err != nil:
		// A READ FAILURE (permissions, IO, a truncated volume), recorded —
		// never folded into "empty".
		s.loadErr = fmt.Errorf("read security control-plane state %s: %w", path, err)
		return s
	case len(b) == 0:
		// A zero-length file: nothing configured, nothing broken.
		return s
	}
	var p filePayload
	if uerr := json.Unmarshal(b, &p); uerr != nil {
		// A CORRUPT file is likewise a failure, not an empty store.
		s.loadErr = fmt.Errorf("parse security control-plane state %s: %w", path, uerr)
		return s
	}
	for _, r := range p.Rules {
		s.putRuleLocked(r)
	}
	for _, v := range p.Views {
		s.putViewLocked(v)
	}
	return s
}

func (s *FileStore) putRuleLocked(r fileRule) {
	t := NormTenant(r.TenantID)
	if s.rules[t] == nil {
		s.rules[t] = map[string]fileRule{}
	}
	r.TenantID = t
	s.rules[t][r.RuleID] = r
}

func (s *FileStore) putViewLocked(v fileViewRow) {
	t := NormTenant(v.TenantID)
	if s.views[t] == nil {
		s.views[t] = map[string]fileViewRow{}
	}
	v.TenantID = t
	s.views[t][v.ID] = v
}

// flushLocked persists the full set (call with mu held). A marshal or write
// failure is RETURNED, never swallowed — the caller answers 500 rather than
// reporting state that was not stored (§10 no silent failures).
func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	p := filePayload{Rules: []fileRule{}, Views: []fileViewRow{}}
	for _, byRule := range s.rules {
		for _, r := range byRule {
			p.Rules = append(p.Rules, r)
		}
	}
	for _, byID := range s.views {
		for _, v := range byID {
			p.Views = append(p.Views, v)
		}
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		if p.Rules[i].TenantID != p.Rules[j].TenantID {
			return p.Rules[i].TenantID < p.Rules[j].TenantID
		}
		return p.Rules[i].RuleID < p.Rules[j].RuleID
	})
	sort.Slice(p.Views, func(i, j int) bool { return p.Views[i].ID < p.Views[j].ID })
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode security control-plane state: %w", err)
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) RuleStates(_ context.Context, tenant string, cross bool) (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]bool{}
	for owner, byRule := range s.rules {
		if !visible(tenant, cross, owner) {
			continue
		}
		for id, r := range byRule {
			out[id] = r.Enabled
		}
	}
	return out, nil
}

func (s *FileStore) SetRuleStates(_ context.Context, _ string, _ bool, owner string, states []RuleState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.snapshotRulesLocked()
	for _, st := range states {
		s.putRuleLocked(fileRule{
			TenantID: owner, RuleID: st.RuleID, Enabled: st.Enabled,
			UpdatedBy: st.UpdatedBy, UpdatedAt: st.UpdatedAt,
		})
	}
	if err := s.flushLocked(); err != nil {
		// Roll back so the store never reports state the file does not hold.
		s.rules = snapshot
		return err
	}
	return nil
}

// snapshotRulesLocked deep-copies the rule index for rollback (call with mu
// held). Cheap: the map holds only deliberate overrides.
func (s *FileStore) snapshotRulesLocked() map[string]map[string]fileRule {
	out := make(map[string]map[string]fileRule, len(s.rules))
	for t, byRule := range s.rules {
		inner := make(map[string]fileRule, len(byRule))
		for id, r := range byRule {
			inner[id] = r
		}
		out[t] = inner
	}
	return out
}

func (s *FileStore) Views(_ context.Context, tenant string, cross bool) ([]SavedView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []SavedView{}
	for owner, byID := range s.views {
		if !visible(tenant, cross, owner) {
			continue
		}
		for _, v := range byID {
			// The two types differ ONLY in their json tags (the persisted row
			// keeps the owner; the API shape drops it), so the conversion is
			// exact and cannot silently lose a field the way a hand-written
			// literal can when one side gains one.
			out = append(out, SavedView(v))
		}
	}
	byName(out)
	return out, nil
}

func (s *FileStore) AddView(_ context.Context, _ string, _ bool, v SavedView) (SavedView, error) {
	id, err := newUUIDv4()
	if err != nil {
		return SavedView{}, err
	}
	v.ID = id
	v.TenantID = NormTenant(v.TenantID)
	v.Filters = defaultFilters(v.Filters)
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	own := s.views[v.TenantID]
	if len(own) >= MaxViewsPerTenant {
		return SavedView{}, ErrViewLimit
	}
	for _, existing := range own {
		if strings.EqualFold(existing.Name, v.Name) {
			return SavedView{}, ErrDuplicateView
		}
	}
	s.putViewLocked(fileViewRow(v))
	if err := s.flushLocked(); err != nil {
		delete(s.views[v.TenantID], v.ID)
		return SavedView{}, err
	}
	return v, nil
}

func (s *FileStore) DeleteView(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for owner, byID := range s.views {
		if !visible(tenant, cross, owner) {
			continue
		}
		row, ok := byID[id]
		if !ok {
			continue
		}
		delete(byID, id)
		if err := s.flushLocked(); err != nil {
			s.putViewLocked(row)
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// ---- Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0037) --

// DB is the injected relational seam (the rcafeedback idiom): run fn inside a
// transaction whose row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed control-plane register.
func NewPGStore(db DB) Store { return &pgStore{db: db} }

func (p *pgStore) RuleStates(ctx context.Context, tenant string, cross bool) (map[string]bool, error) {
	out := map[string]bool{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT rule_id, enabled FROM security_rule_state`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id      string
				enabled bool
			)
			if err := rows.Scan(&id, &enabled); err != nil {
				return err
			}
			out[id] = enabled
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) SetRuleStates(ctx context.Context, tenant string, cross bool, owner string, states []RuleState) error {
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		for _, st := range states {
			at := st.UpdatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_rule_state
			        (tenant_id, rule_id, enabled, updated_by, updated_at)
			    VALUES ($1,$2,$3,$4,$5)
			    ON CONFLICT (tenant_id, rule_id) DO UPDATE
			        SET enabled = EXCLUDED.enabled,
			            updated_by = EXCLUDED.updated_by,
			            updated_at = EXCLUDED.updated_at`,
				NormTenant(owner), st.RuleID, st.Enabled, st.UpdatedBy, at); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *pgStore) Views(ctx context.Context, tenant string, cross bool) ([]SavedView, error) {
	out := []SavedView{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id, id::text, name, filters::text, created_by, created_at
		    FROM security_saved_views ORDER BY lower(name) ASC, id ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				v       SavedView
				filters string
			)
			if err := rows.Scan(&v.TenantID, &v.ID, &v.Name, &filters, &v.CreatedBy, &v.CreatedAt); err != nil {
				return err
			}
			v.Filters = json.RawMessage(filters)
			v.CreatedAt = v.CreatedAt.UTC()
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) AddView(ctx context.Context, tenant string, cross bool, v SavedView) (SavedView, error) {
	id, err := newUUIDv4()
	if err != nil {
		return SavedView{}, err
	}
	v.ID = id
	v.TenantID = NormTenant(v.TenantID)
	// An empty blob is not valid JSONB and would fail the ::jsonb cast at the
	// database rather than at the boundary; "no filters" is the empty OBJECT.
	v.Filters = defaultFilters(v.Filters)
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_saved_views WHERE tenant_id = $1`,
			v.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxViewsPerTenant {
			return ErrViewLimit
		}
		var dup int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_saved_views
		    WHERE tenant_id = $1 AND lower(name) = lower($2)`, v.TenantID, v.Name).Scan(&dup); err != nil {
			return err
		}
		if dup > 0 {
			return ErrDuplicateView
		}
		_, err := tx.Exec(ctx, `INSERT INTO security_saved_views
		        (id, tenant_id, name, filters, created_by, created_at)
		    VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
			v.ID, v.TenantID, v.Name, string(v.Filters), v.CreatedBy, v.CreatedAt)
		return err
	})
	if err != nil {
		return SavedView{}, err
	}
	return v, nil
}

func (p *pgStore) DeleteView(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM security_saved_views WHERE id = $1::uuid`, id)
		if err != nil {
			return err
		}
		found = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)
