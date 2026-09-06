// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/applog"
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
	// History + rollback (versions.go). Part of the Store contract so every
	// backend keeps an audit trail — an optional history is no history.
	VersionStore
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
	mu       sync.RWMutex
	path     string
	rows     map[string]map[string]Rule // tenant → id → rule
	versions []Version                  // append-only history (bounded per processor)
}

func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string]Rule{}}
	b, loadErr := platformdb.Load(path)
	if loadErr != nil {
		// A corrupt/unreadable store must be LOUD: silently loading an empty set
		// would generate an empty router config and stop every redaction with no
		// log line at all — the worst failure mode a redaction feature has (§10).
		applog.Error("processors", "processor store could not be read — redaction rules are NOT loaded",
			map[string]any{"path": path, "err": loadErr.Error()})
	}
	if loadErr == nil {
		// Two on-disk shapes are accepted: the ORIGINAL flat array (pre-history
		// files must keep loading — backward compatibility is a requirement,
		// not a nicety) and the current {rules,versions} envelope.
		var env versionsJSON
		var list []Rule
		if json.Unmarshal(b, &env) == nil && (len(env.Rules) > 0 || len(env.Versions) > 0) {
			list, s.versions = env.Rules, env.Versions
		} else if err := json.Unmarshal(b, &list); err != nil && len(b) > 0 {
			applog.Error("processors", "processor store is unparseable — redaction rules are NOT loaded",
				map[string]any{"path": path, "err": err.Error()})
		}
		for _, r := range list {
			t := normTenant(r.TenantID)
			if s.rows[t] == nil {
				s.rows[t] = map[string]Rule{}
			}
			s.rows[t][r.ID] = r
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
	b, err := marshalVersions(list, s.versions)
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
	// Listed in EXECUTION order (the order operators reason about), not recency.
	orderRules(out)
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

func (s *FileStore) Create(_ context.Context, tenant string, cross bool, r Rule) (Rule, error) {
	// §3a.2 defense in depth (review B9): the owner comes from the caller's
	// scope, matching what the PG backend's RLS session enforces — so the two
	// backends cannot diverge for a caller that forgets to stamp r.TenantID.
	if !cross {
		r.TenantID = tenant
	}
	id, err := newUUIDv4()
	if err != nil {
		return Rule{}, err
	}
	now := time.Now().UTC()
	r.ID, r.TenantID = id, normTenant(r.TenantID)
	r.CreatedAt, r.UpdatedAt = now, now
	r.Version = 1
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rows[r.TenantID]) >= MaxPerTenant {
		return Rule{}, ErrLimit
	}
	if s.rows[r.TenantID] == nil {
		s.rows[r.TenantID] = map[string]Rule{}
	}
	s.rows[r.TenantID][r.ID] = r
	s.appendVersionLocked(r, r.CreatedBy, "created")
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
		in.Version = cur.Version + 1
		byID[id] = in
		s.appendVersionLocked(in, in.CreatedBy, "updated")
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

const pgRuleCols = `tenant_id, rule_id, lane, rule_type, enabled, data, created_by, created_at, updated_at, rule_order, version, source`

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
	var (
		order   int
		version int
		source  string
	)
	if err := rows.Scan(&tenantID, &id, &lane, &ruleType, &enabled, &blob, &by, &created, &updated,
		&order, &version, &source); err != nil {
		return Rule{}, err
	}
	if err := json.Unmarshal(blob, &r); err != nil {
		return Rule{}, err
	}
	// Typed columns are the truth for identity/lifecycle/ordering; the blob for
	// the rest — so a query can sort/filter without decoding JSONB.
	r.TenantID, r.ID, r.Lane, r.Type, r.Enabled = tenantID, id, lane, ruleType, enabled
	r.CreatedBy, r.CreatedAt, r.UpdatedAt = by, created, updated
	r.Order, r.Version, r.Source = order, version, source
	return r, nil
}

func (p *pgStore) list(ctx context.Context, tenant string, cross bool, where string, args ...any) ([]Rule, error) {
	out := []Rule{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgRuleCols+` FROM pipeline_processors`+where+` ORDER BY rule_order ASC, created_at ASC, rule_id ASC`, args...)
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
	if !cross {
		r.TenantID = tenant // §3a.2 (review B9) — mirrors the file backend
	}
	r.ID, r.TenantID = id, normTenant(r.TenantID)
	r.CreatedAt, r.UpdatedAt = now, now
	r.Version = 1
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
		if _, err := tx.Exec(ctx, `INSERT INTO pipeline_processors
		        (tenant_id, rule_id, lane, rule_type, enabled, data, created_by, created_at, updated_at,
		         rule_order, version, source)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			r.TenantID, r.ID, r.Lane, r.Type, r.Enabled, blob, r.CreatedBy, r.CreatedAt, r.UpdatedAt,
			r.Order, r.Version, r.Source); err != nil {
			return err
		}
		return insertVersionTx(ctx, tx, r, r.CreatedBy, "created")
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
		in.Version = cur.Version + 1
		blob, err := ruleBlob(in)
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE pipeline_processors
		    SET lane = $2, rule_type = $3, enabled = $4, data = $5, updated_at = $6,
		        rule_order = $7, version = $8, source = $9
		    WHERE rule_id = $1`, id, in.Lane, in.Type, in.Enabled, blob, in.UpdatedAt,
			in.Order, in.Version, in.Source)
		if err != nil {
			return err
		}
		if ct.RowsAffected() > 0 {
			if err := insertVersionTx(ctx, tx, in, in.CreatedBy, "updated"); err != nil {
				return err
			}
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

// ── history: file backend ───────────────────────────────────────────────────

// appendVersionLocked records an immutable snapshot (call with mu held).
func (s *FileStore) appendVersionLocked(r Rule, actor, kind string) {
	s.versions = append(s.versions, Version{
		ProcessorID: r.ID,
		Version:     r.Version,
		Config:      cloneConfig(r),
		ChangedBy:   actor,
		ChangeKind:  kind,
		CreatedAt:   time.Now().UTC(),
	})
	s.versions = trimVersions(s.versions, r.ID)
}

func (s *FileStore) ListVersions(_ context.Context, tenant string, cross bool, id string) ([]Version, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	visible := false
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		if _, ok := byID[id]; ok {
			visible = true
			break
		}
	}
	if !visible {
		return nil, false, nil // cross-tenant id is indistinguishable from absent
	}
	out := []Version{}
	for _, v := range s.versions {
		if v.ProcessorID == id {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version }) // newest first
	return out, true, nil
}

func (s *FileStore) Rollback(_ context.Context, tenant string, cross bool, id string, version int, actor string) (Rule, bool, error) {
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
		for _, v := range s.versions {
			if v.ProcessorID != id || v.Version != version {
				continue
			}
			// Append-only: the restored config becomes the NEXT version, so the
			// history still shows that a rollback happened and from what.
			next := cloneConfig(v.Config)
			next.ID, next.TenantID = cur.ID, cur.TenantID
			next.CreatedBy, next.CreatedAt = cur.CreatedBy, cur.CreatedAt
			next.Version = cur.Version + 1
			next.UpdatedAt = time.Now().UTC()
			byID[id] = next
			s.appendVersionLocked(next, actor, "rolled_back")
			return next, true, s.flushLocked()
		}
		return Rule{}, false, nil // processor visible, that version is not
	}
	return Rule{}, false, nil
}

// ── history: Postgres backend (migration 0033) ──────────────────────────────

// insertVersionTx appends a snapshot inside the caller's transaction, so the
// processor write and its history entry commit together (an audit row that can
// be lost independently of the change it records is worse than none).
func insertVersionTx(ctx context.Context, tx pgx.Tx, r Rule, actor, kind string) error {
	blob, err := ruleBlob(cloneConfig(r))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO processor_versions
	        (tenant_id, processor_id, version, config, changed_by, change_kind)
	    VALUES ($1,$2,$3,$4,$5,$6)
	    ON CONFLICT (tenant_id, processor_id, version) DO NOTHING`,
		r.TenantID, r.ID, r.Version, blob, actor, kind); err != nil {
		return err
	}
	// Bounded retention (§9, review B8): the file backend trimmed but PG grew
	// forever and shipped the whole history on every drawer open.
	_, err = tx.Exec(ctx, `DELETE FROM processor_versions
	    WHERE processor_id = $1 AND version <= $2`, r.ID, r.Version-MaxVersionsPerProcessor)
	return err
}

func (p *pgStore) ListVersions(ctx context.Context, tenant string, cross bool, id string) ([]Version, bool, error) {
	out := []Version{}
	visible := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) > 0 FROM pipeline_processors WHERE rule_id = $1`, id).Scan(&visible); err != nil {
			return err
		}
		if !visible {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT processor_id, version, config, changed_by, change_kind, created_at
		    FROM processor_versions WHERE processor_id = $1
		    ORDER BY version DESC LIMIT `+strconv.Itoa(MaxVersionsPerProcessor), id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				v    Version
				blob []byte
			)
			if err := rows.Scan(&v.ProcessorID, &v.Version, &blob, &v.ChangedBy, &v.ChangeKind, &v.CreatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(blob, &v.Config); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, visible, err
}

func (p *pgStore) Rollback(ctx context.Context, tenant string, cross bool, id string, version int, actor string) (Rule, bool, error) {
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
			return nil
		}
		var blob []byte
		if err := tx.QueryRow(ctx, `SELECT config FROM processor_versions
		    WHERE processor_id = $1 AND version = $2`, id, version).Scan(&blob); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // processor visible, that version is not
			}
			return err
		}
		var restored Rule
		if err := json.Unmarshal(blob, &restored); err != nil {
			return err
		}
		restored.ID, restored.TenantID = cur.ID, cur.TenantID
		restored.CreatedBy, restored.CreatedAt = cur.CreatedBy, cur.CreatedAt
		restored.Version = cur.Version + 1
		restored.UpdatedAt = time.Now().UTC()
		nb, err := ruleBlob(restored)
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE pipeline_processors
		    SET lane = $2, rule_type = $3, enabled = $4, data = $5, updated_at = $6,
		        rule_order = $7, version = $8, source = $9
		    WHERE rule_id = $1`,
			id, restored.Lane, restored.Type, restored.Enabled, nb, restored.UpdatedAt,
			restored.Order, restored.Version, restored.Source)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil
		}
		if err := insertVersionTx(ctx, tx, restored, actor, "rolled_back"); err != nil {
			return err
		}
		out, found = restored, true
		return nil
	})
	return out, found, err
}
