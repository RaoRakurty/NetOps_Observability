package tlsconfig

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"
)

// handshake drives a TLS handshake between a server and client config over an
// in-memory pipe, returning the client-side and server-side errors.
func handshake(serverCfg, clientCfg *tls.Config) (clientErr, serverErr error) {
	c1, c2 := net.Pipe()
	// Generous hang-safety net: a healthy handshake is sub-ms, but under `-race`
	// on a contended CI runner (instrumentation + parallel packages) scheduling
	// latency can spike, so don't set a tight deadline that flakes.
	_ = c1.SetDeadline(time.Now().Add(15 * time.Second))
	_ = c2.SetDeadline(time.Now().Add(15 * time.Second))
	srv := tls.Server(c1, serverCfg)
	cli := tls.Client(c2, clientCfg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = srv.Handshake()
		c1.Close() // close the RAW pipe — unblocks the peer immediately (no close_notify stall)
	}()
	clientErr = cli.Handshake()
	c2.Close()
	wg.Wait()
	return clientErr, serverErr
}

func serverCfg(t *testing.T, ca *testCA, o ServerOptions, certName string, leaf leafOpts) *tls.Config {
	t.Helper()
	cp, kp := ca.issue(t, certName, leaf)
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatalf("server reloader: %v", err)
	}
	o.Reloader = rl
	cfg, err := ServerConfig(o)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	return cfg
}

func TestHandshakeValid(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, err := LoadTrustBundle(ca.bundlePath())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	cc, err := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("valid handshake failed: client=%v server=%v", ce, se)
	}
	// Policy floor: 1.2 minimum, AEAD/ECDHE cipher list, no renegotiation.
	if sc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want 1.2 floor", sc.MinVersion)
	}
	if sc.Renegotiation != tls.RenegotiateNever {
		t.Error("renegotiation must be disabled")
	}
}

func TestUntrustedCARejected(t *testing.T) {
	serverCA := newTestCA(t)
	otherCA := newTestCA(t) // client trusts a DIFFERENT root
	sc := serverCfg(t, serverCA, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, _ := LoadTrustBundle(otherCA.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "localhost"})
	if ce, _ := handshake(sc, cc); ce == nil {
		t.Fatal("client must reject a cert from an untrusted CA")
	}
}

func TestHostnameMismatchRejected(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "wrong.example.com"})
	if ce, _ := handshake(sc, cc); ce == nil {
		t.Fatal("client must reject a hostname/SAN mismatch")
	}
}

func TestExpiredCertRejected(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server",
		leafOpts{dns: []string{"localhost"}, notAfter: time.Now().Add(-time.Minute)})
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "localhost"})
	if ce, _ := handshake(sc, cc); ce == nil {
		t.Fatal("client must reject an expired server cert")
	}
}

func TestMutualTLSSuccess(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	sc := serverCfg(t, ca, ServerOptions{RequireClientCert: true, ClientCAs: clientCAs},
		"server", leafOpts{dns: []string{"localhost"}})

	// Client presents its own cert from the same trust root.
	cp, kp := ca.issue(t, "client", leafOpts{client: true, dns: []string{"client.netops"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("mTLS handshake failed: client=%v server=%v", ce, se)
	}
}

func TestMutualTLSMissingClientCertRejected(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	sc := serverCfg(t, ca, ServerOptions{RequireClientCert: true, ClientCAs: clientCAs},
		"server", leafOpts{dns: []string{"localhost"}})
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost"}) // no client cert
	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("server must reject a client with no certificate under mTLS")
	}
}

func TestMutualTLSWrongIdentityRejected(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	// Server only accepts a specific SPIFFE-style identity.
	sc := serverCfg(t, ca, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{AllowedURIs: []string{"spiffe://netops/ns/default/sa/api"}},
	}, "server", leafOpts{dns: []string{"localhost"}})

	// Client has a valid cert from the trust root but the WRONG identity.
	cp, kp := ca.issue(t, "intruder", leafOpts{client: true, uris: []string{"spiffe://netops/ns/default/sa/intruder"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	if _, se := handshake(sc, cc); se == nil {
		t.Fatal("server must reject a trusted-but-unauthorized peer identity")
	}
}

func TestPeerPolicyOnRejectFires(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	var gotID string
	var gotErr error
	sc := serverCfg(t, ca, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{
			AllowedURIs: []string{"spiffe://netops/ns/default/sa/api"},
			OnReject:    func(id string, err error) { gotID, gotErr = id, err },
		},
	}, "server", leafOpts{dns: []string{"localhost"}})

	cp, kp := ca.issue(t, "intruder", leafOpts{client: true, uris: []string{"spiffe://netops/ns/default/sa/intruder"}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})

	handshake(sc, cc)
	if gotErr == nil {
		t.Fatal("OnReject must fire on a disallowed identity")
	}
	if gotID != "spiffe://netops/ns/default/sa/intruder" {
		t.Fatalf("OnReject identity = %q, want the intruder SVID", gotID)
	}
}

func TestMutualTLSAllowedIdentityAccepted(t *testing.T) {
	ca := newTestCA(t)
	clientCAs, _ := LoadTrustBundle(ca.bundlePath())
	id := "spiffe://netops/ns/default/sa/api"
	sc := serverCfg(t, ca, ServerOptions{
		RequireClientCert: true, ClientCAs: clientCAs,
		Peer: PeerPolicy{AllowedURIs: []string{id}},
	}, "server", leafOpts{dns: []string{"localhost"}})
	cp, kp := ca.issue(t, "api", leafOpts{client: true, uris: []string{id}})
	crl, _ := NewCertReloader(cp, kp)
	rootCAs, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: rootCAs, ServerName: "localhost", Reloader: crl})
	if ce, se := handshake(sc, cc); ce != nil || se != nil {
		t.Fatalf("allowed identity must be accepted: client=%v server=%v", ce, se)
	}
}

func TestCertReloaderPicksUpRotation(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "server", leafOpts{dns: []string{"localhost"}, notAfter: time.Now().Add(time.Hour)})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	first := rl.Leaf().SerialNumber.String()

	// Rotate: overwrite the same paths with a freshly minted pair.
	cp2, kp2 := ca.issue(t, "server2", leafOpts{dns: []string{"localhost"}})
	copyFile(t, cp2, cp)
	copyFile(t, kp2, kp)
	// Force modtime to advance so the poll detects the change deterministically.
	future := time.Now().Add(2 * time.Second)
	_ = touch(cp, future)
	_ = touch(kp, future)
	if err := rl.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rl.Leaf().SerialNumber.String() == first {
		t.Fatal("reloader did not pick up the rotated certificate")
	}
}

func TestClientConfigRequiresServerNameAndRoots(t *testing.T) {
	ca := newTestCA(t)
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	if _, err := ClientConfig(ClientOptions{RootCAs: bundle}); err == nil {
		t.Error("ClientConfig must require a ServerName (hostname verification)")
	}
	if _, err := ClientConfig(ClientOptions{ServerName: "localhost"}); err == nil {
		t.Error("ClientConfig must require an explicit RootCAs bundle")
	}
}

func TestServerConfigMTLSRequiresClientCAs(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "server", leafOpts{dns: []string{"localhost"}})
	rl, _ := NewCertReloader(cp, kp)
	if _, err := ServerConfig(ServerOptions{Reloader: rl, RequireClientCert: true}); err == nil {
		t.Error("mTLS ServerConfig must require a ClientCAs bundle (fail closed)")
	}
}

func TestTrustBundleErrors(t *testing.T) {
	if _, err := LoadTrustBundle(); err == nil {
		t.Error("empty path list must error")
	}
	if _, err := LoadTrustBundle("/nonexistent/ca.pem"); err == nil {
		t.Error("missing bundle file must error")
	}
}
