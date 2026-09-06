// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vault

// testdeps_test.go — in-memory Store/Warnf for this package's tests.
//
// The whole point of injecting these is that key-custody behaviour can be
// exercised WITHOUT the platform's kv layer — including the failure paths a
// real store makes awkward to produce on demand.

import (
	"fmt"
	"os"
	"sync"
)

type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
	// loadErr/saveErr let a test drive the failure branches deliberately.
	loadErr, saveErr error
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Load(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	b, ok := m.data[key]
	if !ok {
		// MUST be os.ErrNotExist-shaped: loadWrapped treats that specific
		// sentinel as "first run, no wrapped keys yet" and anything else as a
		// real failure. Returning a generic error here made every test look
		// like a corrupt store.
		return nil, fmt.Errorf("vault test store: %q: %w", key, os.ErrNotExist)
	}
	return b, nil
}

func (m *memStore) Save(key string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.data[key] = append([]byte(nil), b...)
	return nil
}

func discardWarn(string, string, map[string]any) {}

// testDeps is the pair every test in this package uses unless it needs to
// inject a failure.
func testDeps() (Store, Warnf) { return newMemStore(), discardWarn }
