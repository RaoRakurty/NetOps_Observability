package tlsconfig

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// policy_test.go — regression guards that lock in this package's SECURITY POLICY
// (not Go's TLS implementation, which is tested upstream). These fail the build if
// someone weakens the cipher/curve/version policy, disables verification, or
// breaks the reload concurrency contract. Maps to the crypto-policy + security
// regression rows of the test matrix.

// handshakeState drives a handshake and returns the client-observed connection
// state plus both sides' errors (so tests can assert the negotiated version).
func handshakeState(serverCfg, clientCfg *tls.Config) (tls.ConnectionState, error, error) {
	c1, c2 := net.Pipe()
	// Generous hang-safety net (see handshake in tlsconfig_test.go) — avoids a
	// tight deadline flaking under `-race` on contended CI runners.
	_ = c1.SetDeadline(time.Now().Add(15 * time.Second))
	_ = c2.SetDeadline(time.Now().Add(15 * time.Second))
	srv := tls.Server(c1, serverCfg)
	cli := tls.Client(c2, clientCfg)
	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = srv.Handshake()
		c1.Close()
	}()
	clientErr := cli.Handshake()
	cs := cli.ConnectionState()
	c2.Close()
	wg.Wait()
	return cs, clientErr, serverErr
}

// TestCipherPolicyNoWeakSuites is THE regression gate for "weak cipher
// reintroduced": every configured TLS 1.2 suite must be one Go classifies as
// secure (not in tls.InsecureCipherSuites) and must use ECDHE (perfect forward
// secrecy). Adding a CBC / RC4 / 3DES / static-RSA suite fails this test.
func TestCipherPolicyNoWeakSuites(t *testing.T) {
	insecure := make(map[uint16]string)
	for _, cs := range tls.InsecureCipherSuites() {
		insecure[cs.ID] = cs.Name
	}
	if len(secureCipherSuites()) == 0 {
		t.Fatal("cipher list must not be empty (would break the 1.2 handshake)")
	}
	for _, id := range secureCipherSuites() {
		name := tls.CipherSuiteName(id)
		if n, bad := insecure[id]; bad {
			t.Errorf("insecure cipher in policy: %s", n)
		}
		// ECDHE prefix ⇒ perfect forward secrecy and rules out static-RSA key
		// exchange (the "RSA" in ECDHE_RSA is auth/signature, not key exchange).
		if !strings.HasPrefix(name, "TLS_ECDHE_") {
			t.Errorf("non-PFS cipher in policy (no ECDHE key exchange): %s", name)
		}
		for _, weak := range []string{"RC4", "3DES", "_CBC_"} {
			if strings.Contains(name, weak) {
				t.Errorf("weak token %q in cipher %s", weak, name)
			}
		}
	}
}

// TestCurveAndVersionPolicy locks the curve preference and the protocol floor /
// renegotiation stance.
func TestCurveAndVersionPolicy(t *testing.T) {
	want := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	got := secureCurves()
	if len(got) != len(want) {
		t.Fatalf("curve list = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("curve[%d] = %v, want %v", i, got[i], want[i])
		}
	}
	base := baseConfig()
	if base.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2 floor", base.MinVersion)
	}
	if base.Renegotiation != tls.RenegotiateNever {
		t.Error("renegotiation must be RenegotiateNever")
	}
}

// TestNoInsecureSkipVerify proves none of the three builders can emit a config
// with verification disabled — structurally impossible by design.
func TestNoInsecureSkipVerify(t *testing.T) {
	ca := newTestCA(t)
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cp, kp := ca.issue(t, "x", leafOpts{dns: []string{"localhost"}})
	rl, _ := NewCertReloader(cp, kp)

	sc, err := ServerConfig(ServerOptions{Reloader: rl})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	hc, err := HTTPClientConfig(ClientOptions{RootCAs: bundle})
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*tls.Config{"server": sc, "client": cc, "http": hc} {
		if cfg.InsecureSkipVerify {
			t.Errorf("%s config has InsecureSkipVerify=true", name)
		}
	}
}

// TestProtocolFloorRejectsBelowTLS12 is the downgrade regression: a client that
// offers only TLS 1.1 is rejected by our server's 1.2 floor.
func TestProtocolFloorRejectsBelowTLS12(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	// Raw client capped below the floor (our ClientConfig can't go this low).
	cc := &tls.Config{RootCAs: bundle.Pool(), ServerName: "localhost", MaxVersion: tls.VersionTLS11}
	if _, ce, _ := handshakeState(sc, cc); ce == nil {
		t.Fatal("server must reject a client offering only TLS 1.1 (below the 1.2 floor)")
	}
}

// TestNegotiatesTLS13ByDefault and the 1.2 path confirm our cipher/curve policy
// actually interoperates at both versions (a broken/empty 1.2 list would fail the
// fallback case).
func TestNegotiatesTLS13ByDefault(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cc, _ := ClientConfig(ClientOptions{RootCAs: bundle, ServerName: "localhost"})
	cs, ce, se := handshakeState(sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("default handshake failed: client=%v server=%v", ce, se)
	}
	if cs.Version != tls.VersionTLS13 {
		t.Errorf("default negotiated version = %x, want TLS 1.3", cs.Version)
	}
}

func TestTLS12FallbackInteroperates(t *testing.T) {
	ca := newTestCA(t)
	sc := serverCfg(t, ca, ServerOptions{}, "server", leafOpts{dns: []string{"localhost"}})
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cc := &tls.Config{RootCAs: bundle.Pool(), ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	cs, ce, se := handshakeState(sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("TLS 1.2 fallback failed: client=%v server=%v", ce, se)
	}
	if cs.Version != tls.VersionTLS12 {
		t.Errorf("negotiated version = %x, want TLS 1.2", cs.Version)
	}
	// The negotiated 1.2 suite must come from our hardened (ECDHE/AEAD) list.
	if name := tls.CipherSuiteName(cs.CipherSuite); !strings.Contains(name, "ECDHE") {
		t.Errorf("TLS 1.2 negotiated a non-PFS suite: %s", name)
	}
}

// TestCertReloaderConcurrentReloadAndGet exercises the reloader's RWMutex under
// concurrent rotation + serving. Run with -race to assert no data race; it must
// never panic and always return a usable cert.
func TestCertReloaderConcurrentReloadAndGet(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "server", leafOpts{dns: []string{"localhost"}})
	rl, err := NewCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(reload bool) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if reload {
					_ = rl.Reload()
				} else if c, _ := rl.GetCertificate(nil); c == nil {
					t.Error("GetCertificate returned nil during concurrent reload")
					return
				}
			}
		}(i%2 == 0)
	}
	wg.Wait()
}

// TestFederationConcurrentReloadAndLookup exercises FederationTrust's RWMutex.
func TestFederationConcurrentReloadAndLookup(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	ft := fedTrust(t, map[string]*testCA{"neta": caA, "netb": caB})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(reload bool) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if reload {
					_ = ft.Reload()
				} else {
					_, _ = ft.domainForRoot(caA.cert)
				}
			}
		}(i%2 == 0)
	}
	wg.Wait()
}

// TestWatchIntervalStopsOnContextCancel guards against a goroutine leak: the
// reload watcher must return promptly when its context is cancelled.
func TestWatchIntervalStopsOnContextCancel(t *testing.T) {
	ca := newTestCA(t)
	cp, kp := ca.issue(t, "server", leafOpts{dns: []string{"localhost"}})
	rl, _ := NewCertReloader(cp, kp)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rl.WatchInterval(ctx, 10*time.Millisecond, nil); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchInterval did not return on context cancel (goroutine leak)")
	}
}
