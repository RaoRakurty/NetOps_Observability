// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// session_wiring.go — composition root for the session-lifecycle stores.
//
// internal/session owns login lifecycle (idle/absolute/revocation) and refresh-
// token rotation, and deliberately does NOT know how this platform persists
// bytes or reports errors: it takes both as dependencies so it can be tested
// against a hanging or failing store without the process-global kv layer.
// Supplying them is the entrypoint package's job (§2: main is wiring).

import (
	"netops/backend/internal/platformdb"
	"netops/backend/internal/session"
)

// platformKV adapts the platform kv layer to the injected persistence seams of
// the extracted stores (session.KV, apikey.KV — structurally identical).
type platformKV struct{}

func (platformKV) Load(key string) ([]byte, error) { return platformdb.Load(key) }
func (platformKV) Save(key string, b []byte) error { return platformdb.Save(key, b) }

// platformPrefixKV additionally exposes the OPTIONAL per-record prefix
// capability (platformdb.PrefixBackend). Wire it ONLY when
// platformdb.ActivePrefix() reports the active backend supports it — handing
// it out unconditionally would defeat the capability type-assertion in stores
// (they would see the methods and then hit ErrNoPrefixCapability at runtime).
type platformPrefixKV struct{ platformKV }

func (platformPrefixKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	return platformdb.LoadPrefix(prefix)
}
func (platformPrefixKV) Delete(key string) error { return platformdb.Delete(key) }

// sessionDeps returns the store backend and error sink the session stores run
// against.
func sessionDeps() (session.KV, session.Errorf) {
	return platformKV{}, func(component, msg string, fields map[string]any) {
		logError(component, msg, fields)
	}
}
