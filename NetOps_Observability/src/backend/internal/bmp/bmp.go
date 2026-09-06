// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// bmp.go — the module's injected collaborators and its constructor.
//
// This package holds NO ambient authority (§5). It cannot read the environment,
// reach the inventory, mint a log line or decide who the caller is except
// through the Deps assembled by the composition root. New refuses an incomplete
// Deps rather than returning an API that silently reads unscoped.

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Gate is the permission a route needs. This package states WHAT; the
// integrator maps it onto the RBAC model. Every route here is a READ.
type Gate int

// GateRead is per-tenant operator read access.
const GateRead Gate = 0

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Deps are the module's injected collaborators.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time

	// ListenAddr is the TCP bind address for the receiver. Empty means
	// DefaultListen. Only Run reads it.
	ListenAddr string

	// The four bounds. Zero means "use the package constant" — never
	// "unbounded", so a miswired zero fails safe.
	MaxConnections       int
	MaxSessionRecords    int
	MaxUpdatesPerSession int

	// IdleTimeout / MessageTimeout bound a session's reads. Zero means the
	// package constants.
	IdleTimeout    time.Duration
	MessageTimeout time.Duration

	// ResolveDevice maps a BMP session's remote IP onto an inventory device and
	// its OWNING TENANT. ok=false (or an empty tenant) closes the connection —
	// an unattributable feed is never stored (§3a). Required.
	ResolveDevice func(addr netip.Addr) (deviceID, tenant string, ok bool)

	// Authz authorizes the caller at the given gate and returns the resolved
	// principal. It has already written the error response when ok is false.
	// Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)

	// Metrics is the Prometheus counter surface. Optional (nil = no counters);
	// every method on *Metrics is nil-safe.
	Metrics *Metrics

	// OnAnnounce receives the prefixes a stored update announced, tenant-stamped
	// by the store, the moment the message is applied. Optional (nil = nobody is
	// watching). It runs ON THE SESSION'S READ GOROUTINE and outside the store
	// lock, so an implementation MUST be cheap and non-blocking: a slow observer
	// slows exactly one router's feed and is never allowed to slow the store.
	// This receiver stays a leaf — it does not know or care what the observer
	// does with the prefixes (today: the bogon sighting register).
	OnAnnounce func(prefixes []AnnouncedPrefix)

	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)

	// LogInfo / LogWarn / LogError are the structured logger (§10). Required.
	// They are called with SESSION facts only — never with frame contents.
	LogInfo  func(msg string, fields map[string]any)
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)
}

func (d Deps) validate() error {
	missing := make([]string, 0, 8)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("ResolveDevice", d.ResolveDevice != nil)
	check("Authz", d.Authz != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogInfo", d.LogInfo != nil)
	check("LogWarn", d.LogWarn != nil)
	check("LogError", d.LogError != nil)
	if len(missing) > 0 {
		return fmt.Errorf("bmp: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// API is the module: the read surface plus the receiver that feeds it.
type API struct {
	deps     Deps
	store    *Store
	listener *Listener
}

// New builds the module over the injected Deps, failing CLOSED on an incomplete
// Deps rather than returning a handler set that reads unscoped.
func New(d Deps) (*API, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	store := NewStore(d.Now, d.MaxSessionRecords, d.MaxUpdatesPerSession)
	return &API{deps: d, store: store, listener: NewListener(d, store)}, nil
}

// Metrics exposes the counter set for the /metrics writer. Nil-safe on the API
// so a dormant (flag-off) module needs no branch at the call site.
func (a *API) Metrics() *Metrics {
	if a == nil {
		return nil
	}
	return a.deps.Metrics
}

// Store exposes the record store. It is used by the composition root's tests
// and by nothing else; every read on it still demands a (tenant, cross) pair.
func (a *API) Store() *Store {
	if a == nil {
		return nil
	}
	return a.store
}

// Listener exposes the receiver, so the root can report its bound address.
func (a *API) Listener() *Listener {
	if a == nil {
		return nil
	}
	return a.listener
}

// Run is the tracked-worker entry point: it binds the listener and serves until
// ctx is cancelled. A nil API is a no-op, so a flag-off deployment starts no
// goroutine at all.
func (a *API) Run(ctx context.Context) {
	if a == nil || a.listener == nil {
		return
	}
	a.listener.Run(ctx)
}
