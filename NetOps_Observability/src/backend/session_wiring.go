package main

// session_wiring.go — composition root for the session-lifecycle stores.
//
// internal/session owns login lifecycle (idle/absolute/revocation) and refresh-
// token rotation, and deliberately does NOT know how this platform persists
// bytes or reports errors: it takes both as dependencies so it can be tested
// against a hanging or failing store without the process-global kv layer.
// Supplying them is the entrypoint package's job (§2: main is wiring).

import "netops/backend/internal/session"

// platformKV adapts the platform kv layer to the injected persistence seams of
// the extracted stores (session.KV, apikey.KV — structurally identical).
type platformKV struct{}

func (platformKV) Load(key string) ([]byte, error) { return kvLoad(key) }
func (platformKV) Save(key string, b []byte) error { return kvSave(key, b) }

// sessionDeps returns the store backend and error sink the session stores run
// against.
func sessionDeps() (session.KV, session.Errorf) {
	return platformKV{}, func(component, msg string, fields map[string]any) {
		logError(component, msg, fields)
	}
}
