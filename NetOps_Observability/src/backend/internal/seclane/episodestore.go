// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// episodestore.go — the three EpisodeStore backends.
//
//   - PGEpisodes   — Postgres, migration 0069 (security_finding_episodes +
//     security_finding_episode_seeds), tenant_iso FORCE-RLS, every statement
//     inside WithTenant(tenant, cross=false). The production backend.
//   - FileEpisodes — one JSON file per tenant, for the file-store build. The
//     file carries its owner and a load refuses a file owned by anyone else.
//   - MemEpisodes  — in-process only. What the lane uses when the integrator
//     injects nothing (tests); a restart then re-seeds from the findings store.
//
// Episode state is scan bookkeeping derived from the tenant's own verdicts: a
// native_id, a first-seen time and the last verdict's classification. It holds
// no config excerpt, no log line and no credential.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/secbus"
)

// subjectJSONMax bounds one stored subject (§9; bounded() keeps real subjects
// far below it).
const subjectJSONMax = 8 << 10

func normEpisodeTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func cloneEpisodes(in map[string]Episode) map[string]Episode {
	out := make(map[string]Episode, len(in))
	for k, v := range in {
		v.Subject.EntityTokens = append([]string(nil), v.Subject.EntityTokens...)
		out[k] = v
	}
	return out
}

func validBasis(b string) string {
	if b == secbus.BasisSeed {
		return secbus.BasisSeed
	}
	return secbus.BasisObserved
}

// ── in-memory ───────────────────────────────────────────────────────────────

// MemEpisodes is the in-process EpisodeStore.
type MemEpisodes struct {
	mu      sync.Mutex
	tenants map[string]TenantEpisodes
}

// NewMemEpisodes returns an empty in-memory store.
func NewMemEpisodes() *MemEpisodes { return &MemEpisodes{tenants: map[string]TenantEpisodes{}} }

// Load implements EpisodeStore.
func (m *MemEpisodes) Load(_ context.Context, tenant string) (TenantEpisodes, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.tenants[normEpisodeTenant(tenant)]
	return TenantEpisodes{Seeded: st.Seeded, Open: cloneEpisodes(st.Open)}, nil
}

// Commit implements EpisodeStore.
func (m *MemEpisodes) Commit(_ context.Context, tenant string, c EpisodeCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := normEpisodeTenant(tenant)
	st := m.tenants[key]
	if st.Open == nil {
		st.Open = map[string]Episode{}
	}
	applyCommit(st.Open, c)
	st.Seeded = true
	m.tenants[key] = st
	return nil
}

func applyCommit(open map[string]Episode, c EpisodeCommit) {
	for nid, ep := range c.Upserts {
		ep.Subject = ep.Subject.bounded()
		ep.Basis = validBasis(ep.Basis)
		open[nid] = ep
	}
	for _, nid := range c.Deletes {
		delete(open, nid)
	}
}

// ── file ────────────────────────────────────────────────────────────────────

// FileEpisodes keeps one JSON file per tenant under a directory, written 0600
// through a temp file + rename.
type FileEpisodes struct {
	dir string
	seg func(string) string

	mu    sync.Mutex
	cache map[string]TenantEpisodes
}

type fileEpisodeDoc struct {
	Tenant     string             `json:"tenant"`
	SeedSource string             `json:"seed_source,omitempty"`
	Episodes   map[string]Episode `json:"episodes"`
}

// NewFileEpisodes returns the file-backed store rooted at dir. seg renders a
// tenant id as a filesystem-safe token (TenantSeg); the tenant id itself is
// stored inside the file and verified on load, so two ids that render to the
// same token can never read each other's state.
func NewFileEpisodes(dir string, seg func(string) string) *FileEpisodes {
	return &FileEpisodes{dir: dir, seg: seg, cache: map[string]TenantEpisodes{}}
}

func (f *FileEpisodes) path(tenant string) (string, error) {
	if f.dir == "" {
		return "", fmt.Errorf("seclane: no episode state directory is configured (%s is empty)", EnvEpisodeDir)
	}
	s := f.seg(tenant)
	if s == "" || strings.ContainsAny(s, `/\`) || strings.HasPrefix(s, ".") {
		return "", fmt.Errorf("seclane: tenant segment %q is not a safe file name", s)
	}
	return filepath.Join(f.dir, s+".json"), nil
}

func (f *FileEpisodes) loadLocked(tenant string) (TenantEpisodes, error) {
	key := normEpisodeTenant(tenant)
	if st, ok := f.cache[key]; ok {
		return st, nil
	}
	p, err := f.path(key)
	if err != nil {
		return TenantEpisodes{}, err
	}
	raw, err := os.ReadFile(p) // #nosec G304 -- operator-configured state dir + sanitized tenant segment
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			st := TenantEpisodes{Open: map[string]Episode{}}
			f.cache[key] = st
			return st, nil
		}
		return TenantEpisodes{}, fmt.Errorf("seclane: episode state at %s could not be read: %w", p, err)
	}
	var doc fileEpisodeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return TenantEpisodes{}, fmt.Errorf("seclane: episode state at %s is not readable JSON: %w", p, err)
	}
	if normEpisodeTenant(doc.Tenant) != key {
		// §3a: a file whose owner is not this tenant is never read as this
		// tenant's state, whatever its name says.
		return TenantEpisodes{}, fmt.Errorf("seclane: episode state at %s belongs to another tenant", p)
	}
	open := map[string]Episode{}
	applyCommit(open, EpisodeCommit{Upserts: doc.Episodes})
	st := TenantEpisodes{Seeded: true, Open: open}
	f.cache[key] = st
	return st, nil
}

// Load implements EpisodeStore.
func (f *FileEpisodes) Load(_ context.Context, tenant string) (TenantEpisodes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, err := f.loadLocked(tenant)
	if err != nil {
		return TenantEpisodes{}, err
	}
	return TenantEpisodes{Seeded: st.Seeded, Open: cloneEpisodes(st.Open)}, nil
}

// Commit implements EpisodeStore. The file is rewritten whole: it holds one
// tenant's open episodes, bounded by the per-run findings cap.
func (f *FileEpisodes) Commit(_ context.Context, tenant string, c EpisodeCommit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := normEpisodeTenant(tenant)
	st, err := f.loadLocked(key)
	if err != nil {
		return err
	}
	next := cloneEpisodes(st.Open)
	applyCommit(next, c)
	p, err := f.path(key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(fileEpisodeDoc{Tenant: key, SeedSource: c.SeedSource, Episodes: next})
	if err != nil {
		return fmt.Errorf("seclane: episode state could not be encoded: %w", err)
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("seclane: episode state directory could not be created: %w", err)
	}
	tmp, err := os.CreateTemp(f.dir, ".episodes-*")
	if err != nil {
		return fmt.Errorf("seclane: episode state could not be staged: %w", err)
	}
	name := tmp.Name()
	// best-effort: a no-op once the rename succeeded; on a failure path the caller already has the real error.
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("seclane: episode state could not be secured: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("seclane: episode state could not be written: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("seclane: episode state could not be flushed: %w", err)
	}
	if err := os.Rename(name, p); err != nil {
		return fmt.Errorf("seclane: episode state could not be committed: %w", err)
	}
	f.cache[key] = TenantEpisodes{Seeded: true, Open: next}
	return nil
}

// ── Postgres ────────────────────────────────────────────────────────────────

// EpisodeDB is the injected relational seam (the secapi/rcafeedback idiom): run
// fn inside a transaction whose row-level security is scoped to tenant.
type EpisodeDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGEpisodes is the Postgres EpisodeStore (migration 0069).
type PGEpisodes struct{ db EpisodeDB }

// NewPGEpisodes builds the Postgres-backed store.
func NewPGEpisodes(db EpisodeDB) *PGEpisodes { return &PGEpisodes{db: db} }

// Load implements EpisodeStore. Both statements also carry an explicit
// tenant_id predicate under the RLS policy (defense in depth).
func (p *PGEpisodes) Load(ctx context.Context, tenant string) (TenantEpisodes, error) {
	key := normEpisodeTenant(tenant)
	if key == "" {
		return TenantEpisodes{}, errors.New("seclane: episode state needs a tenant")
	}
	out := TenantEpisodes{Open: map[string]Episode{}}
	err := p.db.WithTenant(ctx, key, false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM security_finding_episode_seeds WHERE tenant_id = $1`, key).Scan(&n); err != nil {
			return err
		}
		out.Seeded = n > 0
		rows, err := tx.Query(ctx, `SELECT native_id, first_seen, first_seen_basis, subject
		    FROM security_finding_episodes WHERE tenant_id = $1`, key)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				nid, basis string
				first      time.Time
				subject    []byte
			)
			if err := rows.Scan(&nid, &first, &basis, &subject); err != nil {
				return err
			}
			if len(subject) > subjectJSONMax {
				return fmt.Errorf("seclane: stored episode subject for one finding exceeds %d bytes", subjectJSONMax)
			}
			var s EpisodeSubject
			if err := json.Unmarshal(subject, &s); err != nil {
				return fmt.Errorf("seclane: stored episode subject is not readable JSON: %w", err)
			}
			out.Open[nid] = Episode{FirstSeen: first.UTC(), Basis: validBasis(basis), Subject: s.bounded()}
		}
		return rows.Err()
	})
	if err != nil {
		return TenantEpisodes{}, err
	}
	return out, nil
}

// Commit implements EpisodeStore: the scan's upserts, deletes and the seed mark
// in ONE transaction, so a crash can never persist half a scan.
func (p *PGEpisodes) Commit(ctx context.Context, tenant string, c EpisodeCommit) error {
	key := normEpisodeTenant(tenant)
	if key == "" {
		return errors.New("seclane: episode state needs a tenant")
	}
	nids := make([]string, 0, len(c.Upserts))
	firsts := make([]time.Time, 0, len(c.Upserts))
	bases := make([]string, 0, len(c.Upserts))
	subjects := make([]string, 0, len(c.Upserts))
	for nid, ep := range c.Upserts {
		body, err := json.Marshal(ep.Subject.bounded())
		if err != nil {
			return fmt.Errorf("seclane: episode subject could not be encoded: %w", err)
		}
		nids = append(nids, nid)
		firsts = append(firsts, ep.FirstSeen.UTC())
		bases = append(bases, validBasis(ep.Basis))
		subjects = append(subjects, string(body))
	}
	src := c.SeedSource
	if src != SeedSourceIndex && src != SeedSourceScan {
		src = ""
	}
	return p.db.WithTenant(ctx, key, false, func(tx pgx.Tx) error {
		if len(nids) > 0 {
			// The owner is the SCANNED tenant ($1), never a value carried in the
			// rows; FORCE-RLS WITH CHECK refuses anything else.
			if _, err := tx.Exec(ctx, `INSERT INTO security_finding_episodes
			        (tenant_id, native_id, first_seen, first_seen_basis, subject, updated_at)
			    SELECT $1, u.nid, u.first, u.basis, u.subject::jsonb, now()
			      FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::text[])
			           AS u(nid, first, basis, subject)
			    ON CONFLICT (tenant_id, native_id) DO UPDATE
			        SET first_seen = EXCLUDED.first_seen,
			            first_seen_basis = EXCLUDED.first_seen_basis,
			            subject = EXCLUDED.subject,
			            updated_at = EXCLUDED.updated_at`,
				key, nids, firsts, bases, subjects); err != nil {
				return err
			}
		}
		if len(c.Deletes) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM security_finding_episodes
			    WHERE tenant_id = $1 AND native_id = ANY($2::text[])`, key, c.Deletes); err != nil {
				return err
			}
		}
		if src != "" {
			if _, err := tx.Exec(ctx, `INSERT INTO security_finding_episode_seeds (tenant_id, source)
			    VALUES ($1, $2) ON CONFLICT (tenant_id) DO NOTHING`, key, src); err != nil {
				return err
			}
		}
		return nil
	})
}
