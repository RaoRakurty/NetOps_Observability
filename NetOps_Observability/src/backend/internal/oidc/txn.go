// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oidc

import (
	"errors"
	"sync"
	"time"
)

// txn.go — server-side login transactions for the SSO code flow (#135
// hardening, "Okta dashboard launch" capability). The state cookie binds the
// BROWSER to the flow; this store binds the FLOW to exactly one server-created
// transaction, making state single-use and carrying the nonce and PKCE
// verifier that must never reach the browser. In-process is correct here: the
// API is a single instance per deployment, and the design's SaaS phase moves
// this behind the same store interface as the SAML pending-request cache.

const (
	// txnTTL is exact — no clock-skew grace. Skew tolerances apply to IdP
	// assertions, never to our own transaction lifetimes (design §7.1).
	txnTTL = 10 * time.Minute
	// txnCap bounds the map (§9 bounded queues): beyond it, new logins are
	// refused rather than the store growing without limit under a login flood.
	txnCap = 4096
)

var ErrTxnFull = errors.New("sso: too many logins in flight — try again shortly")

type Txn struct {
	Nonce    string
	Verifier string // PKCE code_verifier: lives ONLY here, never in a cookie/URL/log
	// FEState is the SPA-minted nonce (sessionStorage) that the SPA requires the
	// callback fragment to echo, binding the delivered token to the tab that
	// started the flow — the login-CSRF / session-fixation defence (M20). It is
	// opaque to the server; carried here so it never rides the browser URL.
	FEState string
	expires time.Time
}

type TxnStore struct {
	mu sync.Mutex
	m  map[string]Txn // keyed by the opaque state value
}

func NewTxnStore() *TxnStore {
	return &TxnStore{m: make(map[string]Txn)}
}

// Create registers a login transaction under its state. Expired entries are
// evicted first so an abandoned-login flood cannot wedge the store; if the cap
// is still hit the login is refused (callers surface 503, not silence).
func (st *TxnStore) Create(state, nonce, verifier string, now time.Time) error {
	return st.CreateFlow(state, nonce, verifier, "", now)
}

// CreateFlow is Create with the SPA-minted FEState (M20). Create delegates here
// with an empty FEState so existing callers are unchanged.
func (st *TxnStore) CreateFlow(state, nonce, verifier, feState string, now time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.m) >= txnCap {
		for k, v := range st.m {
			if now.After(v.expires) {
				delete(st.m, k)
			}
		}
		if len(st.m) >= txnCap {
			return ErrTxnFull
		}
	}
	st.m[state] = Txn{Nonce: nonce, Verifier: verifier, FEState: feState, expires: now.Add(txnTTL)}
	return nil
}

// Consume atomically claims the transaction for this state: delete-on-read
// under the lock, so concurrent callbacks with the same state yield exactly
// one winner. Expired transactions are a miss (and are removed).
func (st *TxnStore) Consume(state string, now time.Time) (Txn, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.m[state]
	if !ok {
		return Txn{}, false
	}
	delete(st.m, state)
	if now.After(t.expires) {
		return Txn{}, false
	}
	return t, true
}
