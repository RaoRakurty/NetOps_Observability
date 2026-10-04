// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeledger

// target.go — how a handler tells the audit middleware WHAT it changed.
//
// The audit trail records the request envelope (method, path, status); only the
// handler knows which object the request actually changed. The middleware puts
// an empty TargetSlot into the request context before the handler runs; a
// handler that knows its target calls SetTarget; the middleware reads the slot
// after the handler returns. A handler that sets nothing produces no ledger
// entry — the audit trail still has the request, the change feed just does not
// claim to know what changed.

import (
	"context"
	"strings"
	"sync"
)

// Target is the object a mutation changed.
type Target struct {
	Kind string // device | site | …
	ID   string
}

// TargetSlot is the per-request holder. Safe for concurrent use: a handler may
// hand the request to a helper goroutine.
type TargetSlot struct {
	mu     sync.Mutex
	target Target
}

type slotKey struct{}

// WithTargetSlot returns a context carrying a fresh, empty slot, and the slot.
func WithTargetSlot(ctx context.Context) (context.Context, *TargetSlot) {
	s := &TargetSlot{}
	return context.WithValue(ctx, slotKey{}, s), s
}

// SetTarget records the target of this request's mutation. It is a no-op when
// the request carries no slot (a handler reached outside the audit middleware)
// or when kind/id are not a safe label — a target is data, and a value that is
// not a plain identifier is refused rather than stored.
func SetTarget(ctx context.Context, kind, id string) {
	s, ok := ctx.Value(slotKey{}).(*TargetSlot)
	if !ok || s == nil {
		return
	}
	kind, id = strings.TrimSpace(kind), strings.TrimSpace(id)
	if !safeLabel(kind, 32) || !safeLabel(id, 128) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.target = Target{Kind: kind, ID: id}
}

// Get returns the recorded target; ok=false when the handler set none.
func (s *TargetSlot) Get() (Target, bool) {
	if s == nil {
		return Target{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target, s.target.ID != ""
}

// safeLabel admits a bounded identifier of [A-Za-z0-9_.:@/-].
func safeLabel(v string, max int) bool {
	if v == "" || len(v) > max {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.', r == ':', r == '@', r == '/':
		default:
			return false
		}
	}
	return true
}
