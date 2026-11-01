// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// found_store.go — durable memory for what the SNMP subnet sweep has FOUND
// (tracker 366).
//
// THE DEFECT. SNMPSource.found was the only record of a scanned device. After
// an outage plus an api restart, every device that was not answering at boot
// was simply gone: the inventory lost its id, device_tenant.csv lost its tenant
// attribution, the topology lost its node, and a controller twin with a
// different id took its place. History and alerts keyed on the old id stopped
// lining up with anything. That is the opposite of what correlation needs
// during an outage — the devices that are DOWN are the evidence.
//
// WHAT THIS STORE IS. One record per (tenant, source, address) the sweep has
// found, with the liveness the scanner needs to age it on evidence rather than
// on a reboot (last_answered, stale_since). The scanner is the only writer and
// the only reader; it restores the records into its own `found` map before the
// first poll, so the aggregator ingests them through the normal admission path
// (tombstones, source precedence, the first-seen ledger) — never into the
// aggregator cache directly, which every poll legitimately rebuilds.
//
// THIS IS NOT DevStore. DevStore deliberately persists only operator-created
// devices and tombstones, because a persisted shadow of a SOURCE's devices
// would fight the source's own pruning. Here the source IS the writer and the
// pruning is its own (snmp_source.go: three missed completed sweeps → stale;
// stale ≥ 7 days AND at least one answer in the sweep → pruned), so there is
// nothing to fight.
//
// TENANCY (§3a). The tenant lives INSIDE the record and every read is scoped
// by the caller: Load(tenant, cross=false) returns that tenant's rows only;
// cross=true is the platform-wide boot read. The file backend filters in the
// store itself; the Postgres backend (found_store_pg.go) runs under FORCE-RLS.
// Discovered infrastructure is platform-scoped ("") until an operator assigns
// it, and "" is its own partition, never a wildcard.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// FoundRecord is one device the sweep found, as persisted.
type FoundRecord struct {
	TenantID      string    `json:"tenant_id"`
	Source        string    `json:"source"`
	Address       string    `json:"address"`
	DeviceID      string    `json:"device_id"`
	Name          string    `json:"name,omitempty"`
	Vendor        string    `json:"vendor,omitempty"`
	OS            string    `json:"os,omitempty"`
	CredentialRef string    `json:"credential_ref,omitempty"`
	FirstFound    time.Time `json:"first_found"`
	LastAnswered  time.Time `json:"last_answered"`
	// StaleSince is zero while the device is answering (or has missed fewer
	// than staleAfterMisses completed sweeps).
	StaleSince time.Time `json:"stale_since"`
	// Data is reserved for forward-compatible per-device fields. The scanner
	// writes back exactly what it read, so a newer binary's fields survive an
	// older one's rewrite. Empty means "{}".
	Data json.RawMessage `json:"data,omitempty"`
}

// FoundKey identifies one record.
type FoundKey struct {
	TenantID string
	Source   string
	Address  string
}

// Key is the record's identity, normalized.
func (r FoundRecord) Key() FoundKey {
	return FoundKey{TenantID: normFoundTenant(r.TenantID), Source: r.Source, Address: r.Address}
}

// FoundStore is the persistence seam for the scanner's memory.
type FoundStore interface {
	// Load returns the records visible to (tenant, cross): one tenant's rows,
	// or every row when cross. A read failure is an error, never an empty
	// slice — the caller must be able to tell "nothing stored" from "unread".
	Load(ctx context.Context, tenant string, cross bool) ([]FoundRecord, error)
	// Apply upserts and deletes in one call. Each record is written under its
	// OWN tenant; a record that fails validation refuses the whole call.
	Apply(ctx context.Context, upserts []FoundRecord, prunes []FoundKey) error
}

func normFoundTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// errFoundRecord marks a record that is not something the scanner could have
// written. At load it refuses the whole read (corruption, like DevStore's
// misnamed record); at write it refuses the call.
var errFoundRecord = errors.New("invalid discovered-device record")

// validateFoundRecord is the boundary check both backends apply on the way in
// AND on the way out (§3: never trust stored data without validation).
func validateFoundRecord(r FoundRecord) error {
	switch {
	case strings.TrimSpace(r.Source) == "" || len(r.Source) > 64:
		return fmt.Errorf("%w: source %q", errFoundRecord, r.Source)
	case net.ParseIP(r.Address) == nil:
		return fmt.Errorf("%w: address %q is not an IP", errFoundRecord, r.Address)
	case strings.TrimSpace(r.DeviceID) == "" || len(r.DeviceID) > 512:
		return fmt.Errorf("%w: device id %q", errFoundRecord, r.DeviceID)
	case len(r.Name) > 512 || len(r.Vendor) > 256 || len(r.OS) > 1024 || len(r.CredentialRef) > 512 || len(r.TenantID) > 256:
		return fmt.Errorf("%w: oversized field for %s", errFoundRecord, r.Address)
	case len(r.Data) > 0 && !json.Valid(r.Data):
		return fmt.Errorf("%w: data for %s is not JSON", errFoundRecord, r.Address)
	}
	return nil
}

// ── file backend (the platform kv's per-record capability) ──────────────────

// FileFoundStore persists one record per device on a PrefixKV:
//
//	<path>.d/found/<sha256hex(tenant NUL source NUL address)>
//
// The record name is a hash because the identity is a tuple and tenant ids are
// opaque; the identity itself lives INSIDE the record and is authoritative —
// a record whose name does not match its content is refused as corruption, as
// is one that does not decode or validate. Any such record refuses the WHOLE
// load: a partially-read memory would make the scanner prune what it could not
// see.
type FileFoundStore struct {
	kv     PrefixKV
	prefix string
	// mu serializes Apply against Load so a load never sees half an Apply.
	mu sync.Mutex
}

// NewFileFoundStore builds the file backend under path.
func NewFileFoundStore(path string, kv PrefixKV) *FileFoundStore {
	return &FileFoundStore{kv: kv, prefix: path + ".d/found/"}
}

func (s *FileFoundStore) keyFor(k FoundKey) string {
	return s.prefix + recName(normFoundTenant(k.TenantID)+"\x00"+k.Source+"\x00"+k.Address)
}

// Load implements FoundStore.
func (s *FileFoundStore) Load(ctx context.Context, tenant string, cross bool) ([]FoundRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.kv.LoadPrefix(s.prefix)
	if err != nil {
		return nil, fmt.Errorf("read discovered-device records: %w", err)
	}
	want := normFoundTenant(tenant)
	out := make([]FoundRecord, 0, len(recs))
	for key, b := range recs {
		var r FoundRecord
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("decode discovered-device record %s: %w", key, err)
		}
		if err := validateFoundRecord(r); err != nil {
			return nil, fmt.Errorf("discovered-device record %s: %w", key, err)
		}
		r.TenantID = normFoundTenant(r.TenantID)
		if name := s.keyFor(r.Key()); name != key {
			return nil, fmt.Errorf("discovered-device record %s carries %s/%s/%s which names %s — record name and content disagree",
				key, r.TenantID, r.Source, r.Address, name)
		}
		if !cross && r.TenantID != want {
			continue // §3a: the store itself never hands one tenant another's row
		}
		out = append(out, r)
	}
	return out, nil
}

// Apply implements FoundStore. Every record is validated before anything is
// written, so an invalid record cannot leave a half-applied batch behind it.
func (s *FileFoundStore) Apply(ctx context.Context, upserts []FoundRecord, prunes []FoundKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	enc := make(map[string][]byte, len(upserts))
	order := make([]string, 0, len(upserts))
	for _, r := range upserts {
		if err := validateFoundRecord(r); err != nil {
			return err
		}
		r.TenantID = normFoundTenant(r.TenantID)
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode discovered-device record %s: %w", r.Address, err)
		}
		k := s.keyFor(r.Key())
		if _, dup := enc[k]; !dup {
			order = append(order, k)
		}
		enc[k] = b
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range order {
		if err := s.kv.Save(k, enc[k]); err != nil {
			return fmt.Errorf("save discovered-device record: %w", err)
		}
	}
	for _, p := range prunes {
		if err := s.kv.Delete(s.keyFor(p)); err != nil {
			return fmt.Errorf("delete discovered-device record: %w", err)
		}
	}
	return nil
}
