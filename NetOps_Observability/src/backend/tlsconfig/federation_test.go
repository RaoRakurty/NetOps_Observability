// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsconfig

import (
	"crypto/tls"
	"path/filepath"
	"testing"
)

// fedTrust builds a FederationTrust mapping each domain to a testCA's root PEM.
func fedTrust(t *testing.T, m map[string]*testCA) *FederationTrust {
	t.Helper()
	entries := make([]FederationEntry, 0, len(m))
	for d, ca := range m {
		entries = append(entries, FederationEntry{Domain: d, Path: ca.bundlePath()})
	}
	ft, err := LoadFederationTrust(entries)
	if err != nil {
		t.Fatalf("LoadFederationTrust: %v", err)
	}
	return ft
}

func TestParseSpiffeID_Valid(t *testing.T) {
	id, err := parseSpiffeID("spiffe://NetOps-East/ns/default/sa/api")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.trustDomain != "netops-east" { // host lower-cased
		t.Errorf("trustDomain = %q, want netops-east", id.trustDomain)
	}
	if id.path != "/ns/default/sa/api" {
		t.Errorf("path = %q", id.path)
	}
	// Scheme is case-insensitive per RFC 3986.
	if _, err := parseSpiffeID("SPIFFE://netops/x"); err != nil {
		t.Errorf("uppercase scheme must parse: %v", err)
	}
}

func TestParseSpiffeID_Rejects(t *testing.T) {
	for _, raw := range []string{
		"https://netops/x",       // wrong scheme
		"spiffe:///x",            // empty trust domain
		"spiffe://a@b/x",         // userinfo (spiffe://A@B confusion)
		"spiffe://b:9/x",         // port
		"spiffe://netops/x?q=1",  // query
		"spiffe://netops/x#frag", // fragment
		"spiffe://%zz",           // unparseable
	} {
		if _, err := parseSpiffeID(raw); err == nil {
			t.Errorf("parseSpiffeID(%q) must fail", raw)
		}
	}
}

func TestLoadFederationTrust_FailClosed(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)

	if _, err := LoadFederationTrust(nil); err == nil {
		t.Error("no entries must fail")
	}
	// Duplicate domain.
	if _, err := LoadFederationTrust([]FederationEntry{
		{Domain: "d", Path: caA.bundlePath()},
		{Domain: "d", Path: caB.bundlePath()},
	}); err == nil {
		t.Error("duplicate domain must fail")
	}
	// Same root claimed by two domains.
	if _, err := LoadFederationTrust([]FederationEntry{
		{Domain: "x", Path: caA.bundlePath()},
		{Domain: "y", Path: caA.bundlePath()},
	}); err == nil {
		t.Error("same root under two domains must fail")
	}
	// Empty / missing PEM.
	if _, err := LoadFederationTrust([]FederationEntry{
		{Domain: "x", Path: filepath.Join(t.TempDir(), "nope.pem")},
	}); err == nil {
		t.Error("missing PEM must fail")
	}
}

func TestFederationReload(t *testing.T) {
	caX := newTestCA(t)
	caY := newTestCA(t)
	path := filepath.Join(t.TempDir(), "fed.pem")
	copyFile(t, caX.bundlePath(), path)

	ft, err := LoadFederationTrust([]FederationEntry{{Domain: "reg", Path: path}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if d, ok := ft.domainForRoot(caX.cert); !ok || d != "reg" {
		t.Fatalf("caX should map to reg, got %q ok=%v", d, ok)
	}
	if _, ok := ft.domainForRoot(caY.cert); ok {
		t.Fatal("caY must not map before rotation")
	}

	// Rotate the region's root on disk and reload (zero-downtime).
	copyFile(t, caY.bundlePath(), path)
	if err := ft.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if d, ok := ft.domainForRoot(caY.cert); !ok || d != "reg" {
		t.Fatalf("after reload caY should map to reg, got %q ok=%v", d, ok)
	}
	if _, ok := ft.domainForRoot(caX.cert); ok {
		t.Fatal("after reload caX must no longer map")
	}
}

// TestFederationImpersonationRejected is the headline test: a peer whose chain
// anchors to domain B's root may NOT present a domain-A SPIFFE ID. Without the
// binding check this handshake succeeds; with it the server rejects.
func TestFederationImpersonationRejected(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, err := LoadTrustBundle(caA.bundlePath(), caB.bundlePath()) // combined pool
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	// Server serves a caA cert; requires + federates client certs.
	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	// Client cert is issued by caB but claims a NETA identity (impersonation).
	cp, kp := caB.issue(t, "imposter", leafOpts{client: true, uris: []string{"spiffe://neta/ns/default/sa/api"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("server must reject a peer whose SPIFFE domain != chain-anchor domain")
	}
}

func TestFederationLegitimateCrossDomainAccepted(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	// caB-issued cert with a matching NETB identity — a legitimate federated peer.
	cp, kp := caB.issue(t, "peer", leafOpts{client: true, uris: []string{"spiffe://netb/ns/default/sa/api"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("legitimate cross-domain peer rejected: client=%v server=%v", ce, se)
	}
}

func TestFederationUnmappedRootRejected(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	caC := newTestCA(t) // trusted for chain building, NOT in the registry
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath(), caC.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := caC.issue(t, "peer", leafOpts{client: true, uris: []string{"spiffe://netc/ns/default/sa/api"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("a chain anchored to an unmapped root must be rejected")
	}
}

func TestFederationNoSpiffeURIRejected(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	// caB-issued cert with only a DNS SAN — no SPIFFE identity under federation.
	cp, kp := caB.issue(t, "peer", leafOpts{client: true, dns: []string{"peer.netb"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("a federated peer with no SPIFFE ID must be rejected")
	}
}

func TestFederationOnRejectFires(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	var gotID string
	var gotErr error
	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft, OnReject: func(id string, err error) { gotID, gotErr = id, err }},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := caB.issue(t, "imposter", leafOpts{client: true, uris: []string{"spiffe://neta/ns/default/sa/api"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	handshake(sc, cc)
	if gotErr == nil {
		t.Fatal("OnReject must fire on a federation rejection")
	}
	if gotID != "spiffe://neta/ns/default/sa/api" {
		t.Fatalf("OnReject identity = %q, want the imposter SVID", gotID)
	}
}

// TestFederationSingleDomainUnchanged guards that configuring federation with the
// only CA doesn't break the common same-domain path.
func TestFederationSingleDomainUnchanged(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"netops": ca})

	id := "spiffe://netops/ns/default/sa/api"
	sc := serverCfg(t, ca, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{AllowedURIs: []string{id}, Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := ca.issue(t, "api", leafOpts{client: true, uris: []string{id}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("single-domain federated peer rejected: client=%v server=%v", ce, se)
	}
}

// TestFederationDormantIsNoop confirms a nil Federation leaves verify behaving
// exactly as before (the existing allowlist still governs).
func TestFederationDormantIsNoop(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	id := "spiffe://netops/ns/default/sa/api"
	sc := serverCfg(t, ca, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{AllowedURIs: []string{id}}, // Federation nil
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := ca.issue(t, "api", leafOpts{client: true, uris: []string{id}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("dormant federation must not change behavior: client=%v server=%v", ce, se)
	}
}

// TestFederationTrustDomainCaseInsensitive: a peer SVID whose URI host differs
// only in case from the registered domain still binds (trust domains are
// DNS-name-like / case-insensitive). Regression against a strict ==.
func TestFederationTrustDomainCaseInsensitive(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := caB.issue(t, "peer", leafOpts{client: true, uris: []string{"spiffe://NETB/ns/default/sa/api"}}) // upper-case
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("case-different domain must still bind: client=%v server=%v", ce, se)
	}
}

// TestFederationAmbiguousMultiDomainRejected: a leaf carrying SPIFFE IDs from two
// different trust domains is ambiguous and must be rejected (it could otherwise
// straddle the binding check).
func TestFederationAmbiguousMultiDomainRejected(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := caB.issue(t, "peer", leafOpts{client: true,
		uris: []string{"spiffe://netb/ns/default/sa/api", "spiffe://neta/ns/default/sa/api"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("a leaf with SPIFFE IDs from two domains must be rejected")
	}
}

// TestFederationMultipleSameDomainURIsAccepted: multiple SPIFFE IDs in the SAME
// domain are not ambiguous and bind normally.
func TestFederationMultipleSameDomainURIsAccepted(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})

	sc := serverCfg(t, caA, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{Federation: ft},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := caB.issue(t, "peer", leafOpts{client: true,
		uris: []string{"spiffe://netb/ns/default/sa/api", "spiffe://netb/ns/default/sa/api-alt"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(caA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("same-domain multi-URI must bind: client=%v server=%v", ce, se)
	}
}

// TestFederationLayersWithAllowlist: federation binding and the identity allowlist
// are independent AND-ed gates — passing the binding does not bypass the allowlist.
func TestFederationLayersWithAllowlist(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(caA.bundlePath(), caB.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})
	allowed := "spiffe://netb/ns/default/sa/api"

	mkServer := func() *tls.Config {
		return serverCfg(t, caA, ServerOptions{
			RequireClientCert: true, ClientCAs: clientCAs,
			Peer: PeerPolicy{AllowedURIs: []string{allowed}, Federation: ft},
		}, "server", leafOpts{dns: []string{"localhost"}})
	}
	mkClient := func(uri string) *tls.Config {
		cp, kp := caB.issue(t, "peer", leafOpts{client: true, uris: []string{uri}})
		crl, _ := NewCertReloader(cp, kp)
		rootCAs, _ := LoadTrustBundle(caA.bundlePath())
		cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})
		return cc
	}

	// Binding passes (netb), but identity not on the allowlist → rejected.
	if _, se := handshake(mkServer(), mkClient("spiffe://netb/ns/default/sa/other")); se == nil {
		t.Fatal("binding-OK but allowlist-miss must still be rejected")
	}
	// Binding passes AND identity allowed → accepted.
	if ce, se := handshake(mkServer(), mkClient(allowed)); ce != nil || se != nil {
		t.Fatalf("binding-OK and allowlisted must be accepted: client=%v server=%v", ce, se)
	}
}

// FuzzParseSpiffeID: the parser must never panic on arbitrary input, and any
// success must yield a non-empty trust domain.
func FuzzParseSpiffeID(f *testing.F) {
	for _, s := range []string{
		"spiffe://netops/ns/default/sa/api", "spiffe://", "spiffe:///x",
		"://", "spiffe://a@b/x", "spiffe://b:9/x", "%zz", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		id, err := parseSpiffeID(raw)
		if err == nil && id.trustDomain == "" {
			t.Fatalf("parseSpiffeID(%q) returned ok with empty trust domain", raw)
		}
	})
}

// TestClientBuildersInstallVerifyForEmptyAllowlistFederation guards the install
// guard fix: an empty-allowlist policy with Federation set must still wire
// VerifyConnection on both outbound builders.
func TestClientBuildersInstallVerifyForEmptyAllowlistFederation(t *testing.T) {
	ca := newTestCA(t)
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	ft := fedTrust(t, map[string]*testCA{"netops": ca})

	cc, err := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "x", Peer: PeerPolicy{Federation: ft}})
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if cc.VerifyConnection == nil {
		t.Error("ClientConfig must install VerifyConnection when Federation is set")
	}
	hc, err := HTTPClientConfig(ClientOptions{RootCAs: bundle, Peer: PeerPolicy{Federation: ft}})
	if err != nil {
		t.Fatalf("HTTPClientConfig: %v", err)
	}
	if hc.VerifyConnection == nil {
		t.Error("HTTPClientConfig must install VerifyConnection when Federation is set")
	}
}
