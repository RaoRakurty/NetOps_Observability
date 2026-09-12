// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// catalog_store.go — the operator app-catalog stores (#81 P1c, extracted P2
// RA.15): the mem backend ENCODES the RLS-equivalent tenant visibility (cross
// sees all; a scoped tenant sees its own rows + shared global) and refuses
// cross-tenant deletes; the pg backend rides the tenant_iso FORCE-RLS policy
// via WithTenant. Operator entries are AUTHORITATIVE (SrcOperator) — the
// validator and the override builders live here beside the resolver they feed.
// Handlers + the three-state overridesFor composition stay with the entrypoint.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/internal/platformdb"
)

// catalogNormTenant mirrors main's normTenant (lock-step: lowercase + trim).
func catalogNormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// catalogIsCIDRToken is duplicated BY COPY from main's isCIDRToken (SR-011 —
// never by recall: mask 0-32 when present, four octets 0-255, no leading
// zeros; IPv4 only, bare IPs allowed).
func catalogIsCIDRToken(s string) bool {
	host, mask, hasMask := strings.Cut(s, "/")
	if hasMask {
		m, err := strconv.Atoi(mask)
		if err != nil || m < 0 || m > 32 {
			return false
		}
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 || (len(o) > 1 && o[0] == '0') {
			return false
		}
	}
	return true
}

// catalogUUIDv4 is duplicated BY COPY from main's newUUIDv4.
func catalogUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

var validMatchKind = map[string]bool{"prefix": true, "domain": true, "asn": true, "port": true}

// AppCatalogEntry is one operator override row.
type AppCatalogEntry struct {
	CatalogID  string    `json:"catalog_id"`
	TenantID   string    `json:"tenant_id"`
	MatchKind  string    `json:"match_kind"`
	MatchValue string    `json:"match_value"`
	AppLabel   string    `json:"app_label"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	Version    int       `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
}

// ValidateCatalogInput is a pure guard (unit-tested).
func ValidateCatalogInput(kind, value, app string) error {
	if !validMatchKind[kind] {
		return errors.New("match_kind must be one of prefix|domain|asn|port")
	}
	if strings.TrimSpace(value) == "" {
		return errors.New("match_value is required")
	}
	if strings.TrimSpace(app) == "" {
		return errors.New("app_label is required")
	}
	switch kind {
	case "prefix":
		if !catalogIsCIDRToken(value) {
			return errors.New("prefix match_value must be a valid IPv4 CIDR or address")
		}
	case "port":
		if n, err := parsePort(value); err != nil || n < 0 || n > 65535 {
			return errors.New("port match_value must be 0..65535")
		}
	}
	return nil
}

func parsePort(s string) (int, error) {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

type CatalogStore interface {
	List(ctx context.Context, tenant string, cross bool) ([]AppCatalogEntry, error)
	Create(ctx context.Context, tenant string, cross bool, in AppCatalogEntry) (AppCatalogEntry, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
}

func NewCatalogStore() CatalogStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return &pgCatalogStore{db: ps.DB()}
	}
	return &memCatalogStore{by: map[string]AppCatalogEntry{}}
}

// TenantOverrides bundles the per-tenant operator overrides built from app_catalog:
// a prefix catalog (IP→app) and a domain matcher (host→app), both SrcOperator
// (authoritative). asn/port kinds are reserved for later phases.
type TenantOverrides struct {
	Prefixes *Catalog
	Domains  *DomainIndex
}

// BuildOverrides turns operator entries into the per-tenant override structures.
func BuildOverrides(entries []AppCatalogEntry) TenantOverrides {
	ces := make([]CatalogEntry, 0, len(entries))
	di := NewDomainIndex()
	for _, e := range entries {
		switch e.MatchKind {
		case "prefix":
			ces = append(ces, CatalogEntry{
				Prefix: e.MatchValue, App: e.AppLabel, Source: SrcOperator,
				Feed: "operator", Confidence: 0.9,
			})
		case "domain":
			di.Add(e.MatchValue, e.AppLabel, SrcOperator, 0.9)
		}
	}
	return TenantOverrides{Prefixes: NewCatalog(ces), Domains: di}
}

// ── in-memory backend ──────────────────────────────────────────────────────────

type memCatalogStore struct {
	mu sync.RWMutex
	by map[string]AppCatalogEntry // catalog_id → entry
}

func (m *memCatalogStore) visible(e AppCatalogEntry, tenant string, cross bool) bool {
	// RLS-equivalent: cross sees all; a scoped tenant sees its own rows + shared global.
	return cross || e.TenantID == catalogNormTenant(tenant) || e.TenantID == ""
}

func (m *memCatalogStore) List(_ context.Context, tenant string, cross bool) ([]AppCatalogEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []AppCatalogEntry{}
	for _, e := range m.by {
		if m.visible(e, tenant, cross) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memCatalogStore) Create(_ context.Context, _ string, _ bool, in AppCatalogEntry) (AppCatalogEntry, error) {
	id, err := catalogUUIDv4()
	if err != nil {
		return AppCatalogEntry{}, err
	}
	in.CatalogID = id
	in.TenantID = catalogNormTenant(in.TenantID)
	if in.Confidence <= 0 {
		in.Confidence = 0.9
	}
	if in.Source == "" {
		in.Source = "operator"
	}
	if in.Version <= 0 {
		in.Version = 1
	}
	in.CreatedAt = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.by[id] = in
	return in, nil
}

func (m *memCatalogStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.by[id]
	if !ok {
		return false, nil
	}
	if !cross && e.TenantID != catalogNormTenant(tenant) { // can't delete another tenant's / shared global row
		return false, nil
	}
	delete(m.by, id)
	return true, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ──────────────────────

type pgCatalogStore struct{ db *platformdb.DB }

func (st *pgCatalogStore) List(ctx context.Context, tenant string, cross bool) ([]AppCatalogEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := make([]AppCatalogEntry, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT catalog_id, tenant_id, match_kind, match_value, app_label, confidence, source, version, created_at
              FROM app_catalog ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AppCatalogEntry
			if err := rows.Scan(&e.CatalogID, &e.TenantID, &e.MatchKind, &e.MatchValue, &e.AppLabel, &e.Confidence, &e.Source, &e.Version, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (st *pgCatalogStore) Create(ctx context.Context, tenant string, cross bool, in AppCatalogEntry) (AppCatalogEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id, err := catalogUUIDv4()
	if err != nil {
		return AppCatalogEntry{}, err
	}
	in.CatalogID = id
	if in.Confidence <= 0 {
		in.Confidence = 0.9
	}
	if in.Source == "" {
		in.Source = "operator"
	}
	if in.Version <= 0 {
		in.Version = 1
	}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO app_catalog (catalog_id, tenant_id, match_kind, match_value, app_label, confidence, source, version)
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			in.CatalogID, in.TenantID, in.MatchKind, in.MatchValue, in.AppLabel, in.Confidence, in.Source, in.Version)
		return row.Scan(&in.CreatedAt)
	})
	return in, err
}

func (st *pgCatalogStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	affected := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM app_catalog WHERE catalog_id = $1`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}
