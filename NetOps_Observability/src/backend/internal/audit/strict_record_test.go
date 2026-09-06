// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package audit

// strict_record_test.go — M19. Record is deliberately best-effort (an audit
// blip must not break ordinary requests), which meant the sealed-PII reveal
// completed even when its audit write failed: a disclosure the trail never
// witnessed. RecordStrict is the propagating sibling the reveal path uses for
// audit-BEFORE-commit; these tests pin that the error actually surfaces on
// both backends instead of being logged and swallowed.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// failKV persists nothing — the way a full disk or a dead kv layer would.
type failKV struct{ err error }

func (f failKV) Load(string) ([]byte, error) { return nil, errors.New("not found") }
func (f failKV) Save(string, []byte) error   { return f.err }

func TestFileStoreRecordStrictPropagatesPersistError(t *testing.T) {
	errDown := errors.New("kv save failed")
	s, err := NewFileStore("audit.json", failKV{err: errDown})
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := s.RecordStrict(Event{Actor: "a", Path: "/api/x", Method: "POST"}); !errors.Is(err, errDown) {
		t.Fatalf("RecordStrict must propagate the persistence error, got %v", err)
	}
	// The best-effort sibling keeps its contract: no error escapes.
	s.Record(Event{Actor: "a", Path: "/api/x", Method: "POST"})
	// A healthy store's strict write succeeds.
	ok, err := NewFileStore("audit.json", failKV{})
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := ok.RecordStrict(Event{Actor: "a"}); err != nil {
		t.Fatalf("healthy RecordStrict: %v", err)
	}
}

// failDB answers every transaction with an error — a dead pool / broken RLS.
type failDB struct{ err error }

func (f failDB) WithTenant(context.Context, string, bool, func(pgx.Tx) error) error {
	return f.err
}

func TestPGStoreRecordStrictPropagatesPersistError(t *testing.T) {
	errDown := errors.New("pg pool down")
	s := NewPGStore(failDB{err: errDown}, nil)
	if err := s.RecordStrict(Event{Actor: "a", Path: "/api/x", Method: "POST"}); !errors.Is(err, errDown) {
		t.Fatalf("RecordStrict must propagate the INSERT error, got %v", err)
	}
	// Best-effort Record still swallows (observably, via errf) — unchanged.
	s.Record(Event{Actor: "a", Path: "/api/x", Method: "POST"})
}
