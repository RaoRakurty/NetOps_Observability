package tlsconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
)

// TrustBundle is an explicit set of CA roots loaded from PEM file(s). It is the
// ONLY trust anchor for internal mTLS — we never fall back to the host's system
// pool there, so a compromised public CA cannot mint a cert our services accept.
// Reloadable so a CA rotation (adding the next root before retiring the old) is a
// zero-downtime operation: load both, reload, retire.
type TrustBundle struct {
	mu    sync.RWMutex
	pool  *x509.CertPool
	paths []string
}

// LoadTrustBundle reads one or more PEM bundles into an explicit cert pool.
// Fail-closed: an unreadable file, an unparseable PEM, or an empty result is an
// error — the caller must refuse to start rather than trust nothing (which would
// make every verification fail anyway) or everything.
func LoadTrustBundle(paths ...string) (*TrustBundle, error) {
	if len(paths) == 0 {
		return nil, errors.New("tlsconfig: no CA bundle paths provided")
	}
	b := &TrustBundle{paths: append([]string(nil), paths...)}
	if err := b.Reload(); err != nil {
		return nil, err
	}
	return b, nil
}

// Reload rebuilds the pool from disk and atomically swaps it in. Safe to call
// concurrently with Pool().
func (b *TrustBundle) Reload() error {
	pool := x509.NewCertPool()
	added := 0
	for _, p := range b.paths {
		// #nosec G304 -- p is an operator-configured CA bundle path (env/flag), not
		// user-controlled input; reading it is the function's whole purpose.
		pem, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("tlsconfig: read CA bundle %q: %w", p, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("tlsconfig: no valid certificates in CA bundle %q", p)
		}
		added++
	}
	if added == 0 {
		return errors.New("tlsconfig: CA bundle is empty")
	}
	b.mu.Lock()
	b.pool = pool
	b.mu.Unlock()
	return nil
}

// Pool returns the current root pool (caller must not mutate it).
func (b *TrustBundle) Pool() *x509.CertPool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool
}
