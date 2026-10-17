// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package incidentfp

// store.go — fingerprints of closed incidents, per tenant (migration 0059).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Store keeps fingerprints. tenant is always the subject incident's own.
type Store interface {
	// Get returns the stored fingerprints among ids (missing ids are absent).
	Get(ctx context.Context, tenant string, ids []string) (map[string]Fingerprint, error)
	// Put stores one fingerprint (replacing an older one).
	Put(ctx context.Context, tenant string, f Fingerprint) error
}

// MaxGet bounds one read.
const MaxGet = 64

var errNoTenant = errors.New("incidentfp: no tenant")

// MemStore is the file-backend store: keyed by tenant, bounded per tenant.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]Fingerprint
	max  int
}

// NewMemStore keeps at most perTenant fingerprints per tenant (oldest dropped).
func NewMemStore(perTenant int) *MemStore {
	if perTenant <= 0 {
		perTenant = 5000
	}
	return &MemStore{rows: map[string]map[string]Fingerprint{}, max: perTenant}
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant string, ids []string) (map[string]Fingerprint, error) {
	if tenant == "" {
		return nil, errNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Fingerprint{}
	for i, id := range ids {
		if i == MaxGet {
			break
		}
		if f, ok := m.rows[tenant][id]; ok {
			out[id] = f
		}
	}
	return out, nil
}

// Put implements Store.
func (m *MemStore) Put(_ context.Context, tenant string, f Fingerprint) error {
	if tenant == "" || f.CorrelationID == "" {
		return errNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]Fingerprint{}
	}
	if _, exists := m.rows[tenant][f.CorrelationID]; !exists && len(m.rows[tenant]) >= m.max {
		var oldest string
		var at time.Time
		for id, r := range m.rows[tenant] {
			if oldest == "" || r.ComputedAt.Before(at) {
				oldest, at = id, r.ComputedAt
			}
		}
		delete(m.rows[tenant], oldest)
	}
	f.TenantID = tenant
	m.rows[tenant][f.CorrelationID] = f
	return nil
}

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres store (FORCE-RLS, queried via WithTenant).
type PGStore struct{ db DB }

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

const pgTimeout = 5 * time.Second

// Get implements Store.
func (p *PGStore) Get(ctx context.Context, tenant string, ids []string) (map[string]Fingerprint, error) {
	if tenant == "" {
		return nil, errNoTenant
	}
	if len(ids) > MaxGet {
		ids = ids[:MaxGet]
	}
	out := map[string]Fingerprint{}
	if len(ids) == 0 {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT correlation_id, fp_version, fingerprint FROM incident_fingerprints
		     WHERE tenant_id = $1::text AND correlation_id = ANY($2::text[])`, tenant, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var ver int
			var raw []byte
			if err := rows.Scan(&id, &ver, &raw); err != nil {
				return err
			}
			if ver != FPVersion {
				continue // an older derivation: recompute rather than compare apples to pears
			}
			var f Fingerprint
			if err := json.Unmarshal(raw, &f); err != nil {
				continue // a row that does not parse is ignored, never trusted
			}
			if f.CorrelationID != id {
				continue
			}
			f.TenantID = tenant
			out[id] = f
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("incidentfp: get: %w", err)
	}
	return out, nil
}

// Put implements Store.
func (p *PGStore) Put(ctx context.Context, tenant string, f Fingerprint) error {
	if tenant == "" || f.CorrelationID == "" {
		return errNoTenant
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("incidentfp: encode: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var occurred *time.Time
	if !f.OccurredAt.IsZero() {
		occurred = &f.OccurredAt
	}
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO incident_fingerprints (tenant_id, correlation_id, fp_version, fingerprint, signature, chain_key, occurred_at, computed_at)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		    ON CONFLICT (tenant_id, correlation_id) DO UPDATE SET fp_version = EXCLUDED.fp_version, fingerprint = EXCLUDED.fingerprint,
		      signature = EXCLUDED.signature, chain_key = EXCLUDED.chain_key, occurred_at = EXCLUDED.occurred_at, computed_at = EXCLUDED.computed_at`,
			tenant, f.CorrelationID, FPVersion, raw, f.Signature, f.ChainKey, occurred, f.ComputedAt)
		return err
	})
	if err != nil {
		return fmt.Errorf("incidentfp: put: %w", err)
	}
	return nil
}
