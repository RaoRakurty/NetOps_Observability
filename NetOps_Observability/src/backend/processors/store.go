package processors

// store.go — persistence for processor rules. Two backends behind one
// interface (the wireless/maintenance convention): FileStore for the file/dev
// backend + tests, pgStore for production (migration 0032, tenant_iso
// FORCE-RLS via the injected WithTenant seam). Isolation is enforced IN the
// store (§3a). AllEnabled is the one deliberately cross-tenant read: the
// config-writer worker composes EVERY tenant's rules into the router file
// (platform-side plumbing, like the timeintel backfill worker).

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// MaxPerTenant caps stored rules per tenant (bounded stores, §9).
const MaxPerTenant = 200

// ErrLimit is returned when a tenant hits the rule cap (HTTP 400 upstream).
var ErrLimit = fmt.Errorf("a tenant is capped at %d processor rules", MaxPerTenant)

type Store interface {
	List(ctx context.Context, tenant string, cross bool) ([]Rule, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Rule, bool, error)
	Create(ctx context.Context, tenant string, cross bool, r Rule) (Rule, error)
	Update(ctx context.Context, tenant string, cross bool, id string, r Rule) (Rule, bool, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
	// AllEnabled returns every tenant's enabled rules — the config writer's
	// read (platform-side worker; never exposed through a tenant-scoped API).
	AllEnabled(ctx context.Context) ([]Rule, error)
}

func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// newUUIDv4 mirrors the platform's RFC-4122 v4 minting (duplicated per the
// no-shared-utils rule).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ── file backend (default; tenant-filtered IN the store) ─────────────────────

type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[string]map[string]Rule // tenant → id → rule
}

func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string]Rule{}}
	if b, err := platformdb.Load(path); err == nil {
		var list []Rule
		if json.Unmarshal(b, &list) == nil {
			for _, r := range list {
				t := normTenant(r.TenantID)
				if s.rows[t] == nil {
					s.rows[t] = map[string]Rule{}
				}
				s.rows[t][r.ID] = r
			}
		}
	}
	return s
}

func (s *FileStore) flushLocked() error {
	var list []Rule
	for _, byID := range s.rows {
		for _, r := range byID {
			list = append(list, r)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) List(_ context.Context, tenant string, cross bool) ([]Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	out := []Rule{}
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		for _, r := range byID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) Get(_ context.Context, tenant string, cross bool, id string) (Rule, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		if r, ok := byID[id]; ok {
			return r, true, nil
		}
	}
	return Rule{}, false, nil
}

func (s *FileStore) Create(_ context.Context, _ string, _ bool, r Rule) (Rule, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Rule{}, err
	}
	now := time.Now().UTC()
	r.ID, r.TenantID = id, normTenant(r.TenantID)
	r.CreatedAt, r.UpdatedAt = now, now
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rows[r.TenantID]) >= MaxPerTenant {
		return Rule{}, ErrLimit
	}
	if s.rows[r.TenantID] == nil {
		s.rows[r.TenantID] = map[string]Rule{}
	}
	s.rows[r.TenantID][r.ID] = r
	return r, s.flushLocked()
}

func (s *FileStore) Update(_ context.Context, tenant string, cross bool, id string, in Rule) (Rule, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		cur, ok := byID[id]
		if !ok {
			continue
		}
		in.ID, in.TenantID = cur.ID, cur.TenantID
		in.CreatedBy, in.CreatedAt = cur.CreatedBy, cur.CreatedAt
		in.UpdatedAt = time.Now().UTC()
		byID[id] = in
		return in, true, s.flushLocked()
	}
	return Rule{}, false, nil
}

func (s *FileStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		if _, ok := byID[id]; ok {
			delete(byID, id)
			return true, s.flushLocked()
		}
	}
	return false, nil
}

func (s *FileStore) AllEnabled(_ context.Context) ([]Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Rule{}
	for _, byID := range s.rows {
		for _, r := range byID {
			if r.Enabled {
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0032) ───

// DB is the injected relational seam (the wireless/portintel idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

func NewPGStore(db DB) *pgStore { return &pgStore{db: db} }

func ruleBlob(r Rule) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode processor rule: %w", err)
	}
	return b, nil
}

const pgRuleCols = `tenant_id, rule_id, lane, rule_type, enabled, data, created_by, created_at, updated_at`

func scanPGRule(rows pgx.Rows) (Rule, error) {
	var (
		r                Rule
		tenantID, id     string
		lane, ruleType   string
		enabled          bool
		blob             []byte
		by               string
		created, updated time.Time
	)
	if err := rows.Scan(&tenantID, &id, &lane, &ruleType, &enabled, &blob, &by, &created, &updated); err != nil {
		return Rule{}, err
	}
	if err := json.Unmarshal(blob, &r); err != nil {
		return Rule{}, err
	}
	r.TenantID, r.ID, r.Lane, r.Type, r.Enabled = tenantID, id, lane, ruleType, enabled
	r.CreatedBy, r.CreatedAt, r.UpdatedAt = by, created, updated
	return r, nil
}

func (p *pgStore) list(ctx context.Context, tenant string, cross bool, where string, args ...any) ([]Rule, error) {
	out := []Rule{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgRuleCols+` FROM pipeline_processors`+where+` ORDER BY created_at DESC`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPGRule(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool) ([]Rule, error) {
	return p.list(ctx, tenant, cross, "")
}

func (p *pgStore) AllEnabled(ctx context.Context) ([]Rule, error) {
	return p.list(ctx, "", true, " WHERE enabled")
}

func (p *pgStore) Get(ctx context.Context, tenant string, cross bool, id string) (Rule, bool, error) {
	rules, err := p.list(ctx, tenant, cross, " WHERE rule_id = $1", id)
	if err != nil || len(rules) == 0 {
		return Rule{}, false, err
	}
	return rules[0], true, nil
}

func (p *pgStore) Create(ctx context.Context, tenant string, cross bool, r Rule) (Rule, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Rule{}, err
	}
	now := time.Now().UTC()
	r.ID, r.TenantID = id, normTenant(r.TenantID)
	r.CreatedAt, r.UpdatedAt = now, now
	blob, err := ruleBlob(r)
	if err != nil {
		return Rule{}, err
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pipeline_processors WHERE tenant_id = $1`, r.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPerTenant {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO pipeline_processors
		        (tenant_id, rule_id, lane, rule_type, enabled, data, created_by, created_at, updated_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			r.TenantID, r.ID, r.Lane, r.Type, r.Enabled, blob, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	return r, nil
}

func (p *pgStore) Update(ctx context.Context, tenant string, cross bool, id string, in Rule) (Rule, bool, error) {
	var out Rule
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgRuleCols+` FROM pipeline_processors WHERE rule_id = $1`, id)
		if err != nil {
			return err
		}
		cur, scanErr := func() (Rule, error) {
			defer rows.Close()
			if !rows.Next() {
				return Rule{}, rows.Err()
			}
			return scanPGRule(rows)
		}()
		if scanErr != nil {
			return scanErr
		}
		if cur.ID == "" {
			return nil // not visible → found stays false
		}
		in.ID, in.TenantID = cur.ID, cur.TenantID
		in.CreatedBy, in.CreatedAt = cur.CreatedBy, cur.CreatedAt
		in.UpdatedAt = time.Now().UTC()
		blob, err := ruleBlob(in)
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE pipeline_processors
		    SET lane = $2, rule_type = $3, enabled = $4, data = $5, updated_at = $6
		    WHERE rule_id = $1`, id, in.Lane, in.Type, in.Enabled, blob, in.UpdatedAt)
		if err != nil {
			return err
		}
		if ct.RowsAffected() > 0 {
			out, found = in, true
		}
		return nil
	})
	return out, found, err
}

func (p *pgStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM pipeline_processors WHERE rule_id = $1`, id)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)
