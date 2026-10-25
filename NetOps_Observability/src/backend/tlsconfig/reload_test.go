// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsconfig

import (
	"crypto/x509"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// reload_test.go — tracker 351: a CertReloader must renew on USE, with no
// WatchInterval goroutine. The api's and the prober's client SVIDs were built
// with a reloader nobody watched, so they presented their start-time cert until
// it expired and every mTLS hop they dial died one TTL after the last restart.

// rotateInto copies a freshly issued pair over the reloader's paths (rename into
// place, as the internal CA does) and moves the mtime forward so a coarse
// filesystem clock still registers the change.
func rotateInto(t *testing.T, srcCert, srcKey, dstCert, dstKey string, files ...string) {
	t.Helper()
	pairs := map[string]string{dstCert: srcCert, dstKey: srcKey}
	only := map[string]bool{}
	for _, f := range files {
		only[f] = true
	}
	for dst, src := range pairs {
		if len(only) > 0 && !only[dst] {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		tmp := dst + ".new"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", tmp, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			t.Fatalf("rename %s: %v", dst, err)
		}
		future := time.Now().Add(time.Minute)
		if err := os.Chtimes(dst, future, future); err != nil {
			t.Fatalf("chtimes %s: %v", dst, err)
		}
	}
}

func serialOf(t *testing.T, r *CertReloader) string {
	t.Helper()
	c, err := r.GetClientCertificate(nil)
	if err != nil || c == nil || c.Leaf == nil {
		t.Fatalf("GetClientCertificate: cert=%v err=%v", c, err)
	}
	return c.Leaf.SerialNumber.String()
}

func TestReloaderRenewsOnUseWithoutWatcher(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "client", leafOpts{client: true})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	rl.SetRecheckInterval(0)
	before := serialOf(t, rl)

	ncp, nkp := ca.issue(t, "client-next", leafOpts{client: true})
	rotateInto(t, ncp, nkp, cp, kp)

	if after := serialOf(t, rl); after == before {
		t.Fatal("reloader kept the start-time cert after the files were renewed (tracker 351)")
	}
}

func TestReloaderRecheckIsRateLimited(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "client", leafOpts{client: true})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	// Default interval: a rotation inside the window is not seen yet — a
	// handshake storm must not stat the files once per handshake.
	before := serialOf(t, rl)
	ncp, nkp := ca.issue(t, "client-next", leafOpts{client: true})
	rotateInto(t, ncp, nkp, cp, kp)
	if got := serialOf(t, rl); got != before {
		t.Fatal("on-use check ran before the recheck interval elapsed")
	}
	if DefaultRecheckInterval > time.Minute {
		t.Fatalf("DefaultRecheckInterval %v: a renewed SVID must be picked up well inside the ~84h re-mint margin, keep it short", DefaultRecheckInterval)
	}
	rl.SetRecheckInterval(0)
	if got := serialOf(t, rl); got == before {
		t.Fatal("renewed cert not picked up once the interval elapsed")
	}
}

func TestReloaderKeepsOldCertOnHalfWrittenRotation(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "client", leafOpts{client: true})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	rl.SetRecheckInterval(0)
	var errs atomic.Int32
	rl.SetOnReloadError(func(error) { errs.Add(1) })
	before := serialOf(t, rl)

	// The cert lands first, the key a moment later: the mismatched pair must be
	// refused (old cert kept, error observed), then the completed pair adopted.
	ncp, nkp := ca.issue(t, "client-next", leafOpts{client: true})
	rotateInto(t, ncp, nkp, cp, kp, cp)
	if got := serialOf(t, rl); got != before {
		t.Fatal("adopted a cert whose key had not been written yet")
	}
	if errs.Load() == 0 {
		t.Fatal("a failed on-use reload was silent")
	}
	rotateInto(t, ncp, nkp, cp, kp, kp)
	if got := serialOf(t, rl); got == before {
		t.Fatal("completed rotation was not adopted")
	}
}

func TestReloaderMissingFileKeepsServing(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "client", leafOpts{client: true})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	rl.SetRecheckInterval(0)
	var last atomic.Value
	rl.SetOnReloadError(func(e error) { last.Store(e) })
	before := serialOf(t, rl)
	if err := os.Remove(cp); err != nil {
		t.Fatal(err)
	}
	if got := serialOf(t, rl); got != before {
		t.Fatal("lost the cert when its file vanished mid-rotation")
	}
	e, _ := last.Load().(error)
	if e == nil || !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("want a not-exist reload error, got %v", e)
	}
}

// The incident itself, end to end: a client whose SVID expired after start is
// refused by an mTLS server, and the SAME client config succeeds once the files
// are renewed — no restart, no watcher.
func TestMutualTLSClientRecoversAfterRenewalWithoutRestart(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	sc := serverCfg(t, ca, ServerOptions{RequireClientCert: true, ClientCAs: clientCAs},
		"server", leafOpts{dns: []string{"localhost"}})

	cp, kp := ca.issue(t, "client", leafOpts{client: true, notAfter: time.Now().Add(-time.Minute)})
	crl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	crl.SetRecheckInterval(0)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, err := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})
	if err != nil {
		t.Fatal(err)
	}
	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("server accepted an expired client SVID")
	}

	ncp, nkp := ca.issue(t, "client-next", leafOpts{client: true})
	rotateInto(t, ncp, nkp, cp, kp)
	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("renewed client SVID not presented without a restart: client=%v server=%v", ce, se)
	}
}

// OnAccept reports the leaf each accepted client presented, and never fires
// for a peer the policy refused (tracker 351: the client-cert expiry gauge).
func TestPeerPolicyOnAcceptSeesPresentedClientLeaf(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	var seen atomic.Value
	var rejected atomic.Int32
	policy := PeerPolicy{
		AllowedURIs: []string{"spiffe://netops/ns/default/sa/vmalert"},
		OnAccept:    func(leaf *x509.Certificate) { seen.Store(leaf) },
		OnReject:    func(string, error) { rejected.Add(1) },
	}
	sc := serverCfg(t, ca, ServerOptions{RequireClientCert: true, ClientCAs: clientCAs, Peer: policy},
		"server", leafOpts{dns: []string{"localhost"}})
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())

	want := time.Now().Add(5 * time.Hour).Truncate(time.Second)
	cp, kp := ca.issue(t, "vmalert", leafOpts{client: true, uris: []string{"spiffe://netops/ns/default/sa/vmalert"}, notAfter: want})
	crl, _ := NewCertReloader(cp, kp)
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})
	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("handshake: client=%v server=%v", ce, se)
	}
	leaf, _ := seen.Load().(*x509.Certificate)
	if leaf == nil || !leaf.NotAfter.Equal(want) {
		t.Fatalf("OnAccept leaf = %v, want NotAfter %v", leaf, want)
	}

	seen.Store((*x509.Certificate)(nil))
	op, ok := ca.issue(t, "other", leafOpts{client: true, uris: []string{"spiffe://netops/ns/default/sa/other"}})
	orl, _ := NewCertReloader(op, ok)
	oc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: orl})
	if _, se := handshake(sc, oc); se == nil {
		t.Fatal("disallowed identity accepted")
	}
	if l, _ := seen.Load().(*x509.Certificate); l != nil {
		t.Fatal("OnAccept fired for a rejected peer")
	}
	if rejected.Load() == 0 {
		t.Fatal("OnReject did not fire")
	}
}
