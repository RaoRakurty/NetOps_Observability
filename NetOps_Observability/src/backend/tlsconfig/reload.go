// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRecheckInterval bounds how often a handshake re-stats the key pair.
// Tracker 351: a reloader nobody runs WatchInterval for (the api's and the
// prober's CLIENT SVID) kept its start-time cert for the process lifetime and
// mTLS died one TTL after the last restart. Re-checking on use makes every
// reloader self-renewing, watcher or not; the stat pair is cheap and bounded.
const DefaultRecheckInterval = 30 * time.Second

// CertReloader holds a TLS key pair and hot-reloads it from disk when the files
// change, so a certificate rotation never requires a process restart or drops a
// connection. A single *tls.Config installed once keeps serving the latest cert
// because it resolves the cert through GetCertificate / GetClientCertificate on
// every handshake rather than capturing it at build time.
//
// Change detection is a modtime check — on use (at most every recheck interval,
// so no caller can forget it) and optionally on a WatchInterval poll. Deliberately
// stdlib-only, no fsnotify dependency. Rotation tooling (cert-manager, the #17 sealed store,
// SPIRE) just needs to atomically replace the files; the next poll picks them up.
type CertReloader struct {
	certPath, keyPath string

	mu      sync.RWMutex
	cert    *tls.Certificate
	modCert time.Time
	modKey  time.Time

	recheck   atomic.Int64 // nanoseconds between on-use checks; <= 0 checks every use
	nextCheck atomic.Int64 // unix nanos of the next on-use check
	onErr     atomic.Pointer[func(error)]
}

// NewCertReloader loads the initial key pair. Fail-closed: a missing or invalid
// pair is an error so the caller refuses to start.
func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	r := &CertReloader{certPath: certPath, keyPath: keyPath}
	r.recheck.Store(int64(DefaultRecheckInterval))
	if err := r.reload(true); err != nil {
		return nil, err
	}
	r.nextCheck.Store(time.Now().Add(DefaultRecheckInterval).UnixNano())
	return r, nil
}

// SetRecheckInterval changes how often a handshake re-checks the files on disk
// (d <= 0 checks on every handshake — tests only).
func (r *CertReloader) SetRecheckInterval(d time.Duration) {
	r.recheck.Store(int64(d))
	r.nextCheck.Store(0)
}

// SetOnReloadError registers the observer for a failed on-use reload (the old
// cert is kept; a half-written rotation simply retries at the next check), so
// the failure is logged rather than silent.
func (r *CertReloader) SetOnReloadError(f func(error)) {
	if f == nil {
		r.onErr.Store(nil)
		return
	}
	r.onErr.Store(&f)
}

// maybeReload is the on-use check. Exactly one caller wins the CAS per interval,
// so a handshake storm stats the files once, not once per handshake.
func (r *CertReloader) maybeReload() {
	now := time.Now().UnixNano()
	next := r.nextCheck.Load()
	if now < next || !r.nextCheck.CompareAndSwap(next, now+r.recheck.Load()) {
		return
	}
	if err := r.reload(false); err != nil {
		if f := r.onErr.Load(); f != nil {
			(*f)(err)
		}
	}
}

func (r *CertReloader) reload(force bool) error {
	cm, err := modTime(r.certPath)
	if err != nil {
		return err
	}
	km, err := modTime(r.keyPath)
	if err != nil {
		return err
	}
	r.mu.RLock()
	unchanged := !force && cm.Equal(r.modCert) && km.Equal(r.modKey) && r.cert != nil
	r.mu.RUnlock()
	if unchanged {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("tlsconfig: load key pair: %w", err)
	}
	// Parse the leaf once so expiry inspection and identity checks don't re-parse
	// on every handshake.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			cert.Leaf = leaf
		}
	}
	r.mu.Lock()
	r.cert, r.modCert, r.modKey = &cert, cm, km
	r.mu.Unlock()
	return nil
}

// Reload forces a re-read from disk (e.g. on SIGHUP).
func (r *CertReloader) Reload() error { return r.reload(true) }

// GetCertificate is the server-side hook for tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current(), nil
}

// GetClientCertificate is the client-side hook for tls.Config.GetClientCertificate
// (mTLS).
func (r *CertReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current(), nil
}

func (r *CertReloader) current() *tls.Certificate {
	r.maybeReload()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert
}

// Leaf returns the parsed leaf certificate (for expiry metrics / identity).
func (r *CertReloader) Leaf() *x509.Certificate {
	r.maybeReload()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil
	}
	return r.cert.Leaf
}

// WatchInterval polls the files every d and reloads on change until ctx is done.
// A reload error is reported to onErr (if non-nil) and the old cert is kept —
// serving a slightly stale but valid cert beats crashing the listener.
func (r *CertReloader) WatchInterval(ctx context.Context, d time.Duration, onErr func(error)) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.reload(false); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

func modTime(path string) (time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("tlsconfig: stat %q: %w", path, err)
	}
	return fi.ModTime(), nil
}
