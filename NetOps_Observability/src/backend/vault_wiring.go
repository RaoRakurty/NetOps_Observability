package main

// vault_wiring.go — composition root for the secret-custody vault.
//
// internal/vault owns key custody and deliberately does NOT know how this
// platform persists bytes or reports warnings: it takes both as dependencies so
// it can be tested against a failing or empty store without standing up the kv
// layer. Supplying them is the entrypoint package's job, which is what §2 means
// by keeping main to wiring.

import (
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
)

// kvVaultStore adapts the platform kv layer to vault.Store.
type kvVaultStore struct{}

func (kvVaultStore) Load(key string) ([]byte, error) { return platformdb.Load(key) }
func (kvVaultStore) Save(key string, b []byte) error { return platformdb.Save(key, b) }

// vaultDeps returns the store and warning sink the vault runs against.
func vaultDeps() (vault.Store, vault.Warnf) {
	return kvVaultStore{}, func(component, msg string, fields map[string]any) {
		logWarn(component, msg, fields)
	}
}
