// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

// file_store.go — the file backend: one record per scope on the platform kv's
// per-record capability,
//
//	<path>.d/scopes/<sha256hex(tenant NUL id)>
//
// The identity lives INSIDE the record and is authoritative; a record whose
// name does not match its content, that does not decode, or that does not
// validate refuses the WHOLE load (a partially-read set would make the scanner
// silently drop a customer's scan). §3a rule 4: the store itself filters by
// tenant — there is no unscoped read for a non-cross caller.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// PrefixKV is the per-record capability of the platform kv (platformdb).
type PrefixKV interface {
	Save(key string, data []byte) error
	LoadPrefix(prefix string) (map[string][]byte, error)
	Delete(key string) error
}

// FileStore is the file Store.
type FileStore struct {
	kv     PrefixKV
	prefix string
	mu     sync.Mutex // serializes a write's check-then-save against other writes and loads
}

// NewFileStore builds the file backend under path.
func NewFileStore(path string, kv PrefixKV) *FileStore {
	return &FileStore{kv: kv, prefix: path + ".d/scopes/"}
}

func (s *FileStore) keyFor(tenant, id string) string {
	sum := sha256.Sum256([]byte(NormTenant(tenant) + "\x00" + id))
	return s.prefix + hex.EncodeToString(sum[:])
}

// loadLocked reads and validates every record. Caller holds s.mu.
func (s *FileStore) loadLocked() ([]Scope, error) {
	recs, err := s.kv.LoadPrefix(s.prefix)
	if err != nil {
		return nil, fmt.Errorf("read discovery scopes: %w", err)
	}
	out := make([]Scope, 0, len(recs))
	for key, b := range recs {
		var sc Scope
		if err := json.Unmarshal(b, &sc); err != nil {
			return nil, fmt.Errorf("decode discovery scope %s: %w", key, err)
		}
		if err := Validate(&sc); err != nil {
			return nil, fmt.Errorf("discovery scope %s: %w", key, err)
		}
		if want := s.keyFor(sc.TenantID, sc.ID); want != key {
			return nil, fmt.Errorf("discovery scope %s carries %s/%s which names %s — record name and content disagree", key, sc.TenantID, sc.ID, want)
		}
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// List implements Store.
func (s *FileStore) List(ctx context.Context, tenant string, cross bool) ([]Scope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	if cross {
		return all, nil
	}
	want := NormTenant(tenant)
	out := all[:0:0]
	for _, sc := range all {
		if sc.TenantID == want {
			out = append(out, sc)
		}
	}
	return out, nil
}

// Get implements Store.
func (s *FileStore) Get(ctx context.Context, tenant string, cross bool, id string) (Scope, bool, error) {
	list, err := s.List(ctx, tenant, cross)
	if err != nil {
		return Scope{}, false, err
	}
	for _, sc := range list {
		if sc.ID == id {
			return sc, true, nil
		}
	}
	return Scope{}, false, nil
}

// Put implements Store.
func (s *FileStore) Put(ctx context.Context, sc Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := Validate(&sc); err != nil {
		return err
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return fmt.Errorf("encode discovery scope: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.loadLocked()
	if err != nil {
		return err
	}
	mine, total := 0, 0
	for _, o := range all {
		if o.ID == sc.ID && o.TenantID != sc.TenantID {
			return fmt.Errorf("%w: id %s belongs to another tenant", ErrInvalid, sc.ID)
		}
		if o.ID == sc.ID {
			continue // an update does not count against the bounds
		}
		total++
		if o.TenantID == sc.TenantID {
			mine++
		}
	}
	if mine >= MaxPerTenant || total >= MaxTotal {
		return fmt.Errorf("%w: at most %d scans per customer and %d in all", ErrInvalid, MaxPerTenant, MaxTotal)
	}
	if err := s.kv.Save(s.keyFor(sc.TenantID, sc.ID), b); err != nil {
		return fmt.Errorf("save discovery scope: %w", err)
	}
	return nil
}

// Delete implements Store.
func (s *FileStore) Delete(ctx context.Context, tenant, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.loadLocked()
	if err != nil {
		return false, err
	}
	want := NormTenant(tenant)
	for _, sc := range all {
		if sc.TenantID == want && sc.ID == id {
			if err := s.kv.Delete(s.keyFor(want, id)); err != nil {
				return false, fmt.Errorf("delete discovery scope: %w", err)
			}
			return true, nil
		}
	}
	return false, nil
}
