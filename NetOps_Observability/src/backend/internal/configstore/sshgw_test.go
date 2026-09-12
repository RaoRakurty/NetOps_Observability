// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshgw_test.go — the capture transport, proven against a REAL in-process SSH
// server (x/crypto/ssh's server side). A fake that just returns a string would
// prove nothing about the property that matters here: that the capture refuses a
// device whose host key does not match the platform's pin.

// testSSHServer is a minimal SSH server that answers ONE exec request with a
// fixed payload. It is the "device" in these tests.
type testSSHServer struct {
	ln       net.Listener
	signer   ssh.Signer
	password string
	payload  string

	mu      sync.Mutex
	execCmd string
	wg      sync.WaitGroup
}

func newTestSSHServer(t *testing.T, password, payload string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSSHServer{ln: ln, signer: signer, password: password, payload: payload}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *testSSHServer) addr() (host string, port int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func (s *testSSHServer) fingerprint() string { return Fingerprint(s.signer.PublicKey()) }

func (s *testSSHServer) command() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execCmd
}

func (s *testSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testSSHServer) handle(conn net.Conn) {
	defer conn.Close()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == s.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(s.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range creqs {
				if req.Type != "exec" {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				// The exec payload is a length-prefixed command string.
				cmd := ""
				if len(req.Payload) >= 4 {
					n := binary.BigEndian.Uint32(req.Payload[:4])
					if int(n) <= len(req.Payload)-4 {
						cmd = string(req.Payload[4 : 4+n])
					}
				}
				s.mu.Lock()
				s.execCmd = cmd
				s.mu.Unlock()
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				_, _ = ch.Write([]byte(s.payload))
				status := make([]byte, 4) // exit-status 0
				_, _ = ch.SendRequest("exit-status", false, status)
				_ = ch.Close()
			}
		}()
	}
}

func newGatewayFor(srv *testSSHServer, check func(string, string) (bool, bool)) *SSHGateway {
	return &SSHGateway{
		Credentials: func(context.Context, Device) (Credential, error) {
			return Credential{Username: "capture-ro", Password: srv.password}, nil
		},
		HostKeyCheck: check,
		DialTimeout:  5 * time.Second,
	}
}

func deviceFor(srv *testSSHServer) Device {
	host, port := srv.addr()
	return Device{ID: "d1", Address: host, Port: port, Vendor: "Cisco IOS-XE", TenantID: "acme"}
}

// TestSSHGatewayCapturesThroughHostKeyVerification: the happy path — and the
// host-key check is CONSULTED with the platform's fingerprint format.
func TestSSHGatewayCapturesThroughHostKeyVerification(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	var (
		gotAddr string
		gotFP   string
		calls   int
	)
	gw := newGatewayFor(srv, func(addr, fp string) (bool, bool) {
		calls++
		gotAddr, gotFP = addr, fp
		return true, true
	})
	dev := deviceFor(srv)

	out, err := gw.Run(context.Background(), dev, "show running-config", MaxCaptureBytes)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "hostname edge-01") {
		t.Fatalf("unexpected capture: %q", out)
	}
	if calls != 1 {
		t.Fatalf("host-key check called %d times, want 1", calls)
	}
	if gotAddr != dev.Address {
		t.Errorf("host-key check addr = %q, want %q", gotAddr, dev.Address)
	}
	if gotFP != srv.fingerprint() || !strings.HasPrefix(gotFP, "SHA256:") {
		t.Errorf("fingerprint = %q, want %q", gotFP, srv.fingerprint())
	}
	if srv.command() != "show running-config" {
		t.Errorf("device ran %q", srv.command())
	}
}

// TestSSHGatewayRefusesHostKeyMismatch is the MITM refusal: a recorded
// fingerprint that differs stops the capture dead, with no output.
func TestSSHGatewayRefusesHostKeyMismatch(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return false, false })

	out, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes)
	if err == nil {
		t.Fatal("a host-key mismatch must refuse the capture")
	}
	if out != "" {
		t.Fatal("a refused capture must return no configuration")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("the refusal must name the reason: %v", err)
	}
}

// TestSSHGatewayFailsClosedWithoutHostKeyPolicy: no policy is NOT "trust
// everything".
func TestSSHGatewayFailsClosedWithoutHostKeyPolicy(t *testing.T) {
	srv := newTestSSHServer(t, "pw", "x")
	gw := newGatewayFor(srv, nil)
	if _, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("a missing host-key policy must refuse the connection")
	}
}

// TestSSHGatewayEnforcesTheByteCap (§9): a device that streams more than the cap
// fails loudly rather than filling memory.
func TestSSHGatewayEnforcesTheByteCap(t *testing.T) {
	srv := newTestSSHServer(t, "pw", strings.Repeat("a", 4096))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	_, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", 512)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// TestSSHGatewayRefusesBadCredentials.
func TestSSHGatewayRefusesBadCredentials(t *testing.T) {
	srv := newTestSSHServer(t, "correct", "x")
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	gw.Credentials = func(context.Context, Device) (Credential, error) {
		return Credential{Username: "capture-ro", Password: "wrong"}, nil
	}
	if _, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("a bad credential must fail the capture")
	}
	// An incomplete credential is refused before any dial.
	gw.Credentials = func(context.Context, Device) (Credential, error) { return Credential{}, nil }
	if _, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("an incomplete credential must be refused")
	}
}

// TestSSHGatewayRespectsContextCancellation (§9 all IO has a timeout).
func TestSSHGatewayRespectsContextCancellation(t *testing.T) {
	srv := newTestSSHServer(t, "pw", "x")
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gw.Run(ctx, deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("a cancelled context must abort the capture")
	}
}

// TestSSHGatewayRefusesDeviceWithoutAddress.
func TestSSHGatewayRefusesDeviceWithoutAddress(t *testing.T) {
	gw := &SSHGateway{
		Credentials: func(context.Context, Device) (Credential, error) {
			return Credential{Username: "u", Password: "p"}, nil
		},
		HostKeyCheck: func(string, string) (bool, bool) { return true, true },
	}
	if _, err := gw.Run(context.Background(), Device{ID: "d1"}, "show running-config", 1024); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("err = %v, want ErrNoAddress", err)
	}
}

// ── the bounded retry (§9), and what it must never retry ────────────────────

// countingDial wraps the real dialer, failing the first failures attempts and
// counting every call.
type countingDial struct {
	mu       sync.Mutex
	calls    int
	failures int
}

func (c *countingDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	c.calls++
	fail := c.calls <= c.failures
	c.mu.Unlock()
	if fail {
		return nil, errors.New("connect: connection reset by peer")
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func (c *countingDial) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// TestSSHGatewayRetriesATransientDial: a reset that costs the whole capture
// interval was the defect. Two failures then a success must still capture.
func TestSSHGatewayRetriesATransientDial(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	gw.retryBackoff = 5 * time.Millisecond
	cd := &countingDial{failures: 2}
	gw.Dial = cd.dial

	out, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "hostname edge-01") {
		t.Fatalf("unexpected capture: %q", out)
	}
	if got := cd.count(); got != 3 {
		t.Errorf("dialed %d times, want 3 (two resets then the capture)", got)
	}
}

// TestSSHGatewayStopsRetryingAtTheAttemptBound: the retry is BOUNDED. A device
// that is simply unreachable must not be dialled forever.
func TestSSHGatewayStopsRetryingAtTheAttemptBound(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	gw.retryBackoff = 5 * time.Millisecond
	cd := &countingDial{failures: 1 << 30}
	gw.Dial = cd.dial

	out, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes)
	if err == nil {
		t.Fatal("an unreachable device must fail the capture")
	}
	if out != "" {
		t.Fatal("a failed capture must return no configuration")
	}
	if got := cd.count(); got != maxCaptureAttempts {
		t.Errorf("dialed %d times, want exactly maxCaptureAttempts (%d)", got, maxCaptureAttempts)
	}
}

// TestSSHGatewayNeverRetriesAHostKeyMismatch is the whole point of the
// classification: a device whose key changed is refused ONCE. Re-dialling it
// would re-offer the capture credential to whatever is answering for it.
func TestSSHGatewayNeverRetriesAHostKeyMismatch(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	checks := 0
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { checks++; return false, false })
	gw.retryBackoff = 5 * time.Millisecond
	cd := &countingDial{}
	gw.Dial = cd.dial

	out, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes)
	if err == nil {
		t.Fatal("a host-key mismatch must refuse the capture")
	}
	if out != "" {
		t.Fatal("a refused capture must return no configuration")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("the refusal must name the reason: %v", err)
	}
	if got := cd.count(); got != 1 {
		t.Errorf("dialed %d times, want exactly 1 — a mismatch is permanent", got)
	}
	if checks != 1 {
		t.Errorf("host-key check consulted %d times, want exactly 1", checks)
	}
}

// TestSSHGatewayNeverRetriesAnAuthFailure: repeated attempts with a bad
// credential are how a capture account gets locked out of a whole fleet.
func TestSSHGatewayNeverRetriesAnAuthFailure(t *testing.T) {
	srv := newTestSSHServer(t, "correct", sampleConfig("edge-01"))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	gw.retryBackoff = 5 * time.Millisecond
	gw.Credentials = func(context.Context, Device) (Credential, error) {
		return Credential{Username: "capture-ro", Password: "wrong"}, nil
	}
	cd := &countingDial{}
	gw.Dial = cd.dial

	if _, err := gw.Run(context.Background(), deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("a bad credential must fail the capture")
	}
	if got := cd.count(); got != 1 {
		t.Errorf("dialed %d times with a bad credential, want exactly 1", got)
	}
}

// TestSSHGatewayRetryStaysInsideTheCallerDeadline: the retry must never push the
// capture past the budget the caller set. With less time left than one backoff
// plus one dial, there is no second attempt.
func TestSSHGatewayRetryStaysInsideTheCallerDeadline(t *testing.T) {
	srv := newTestSSHServer(t, "pw", sampleConfig("edge-01"))
	gw := newGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	// The backoff itself would fit inside the deadline; one more DIAL would not
	// (DialTimeout is 5 s). It is that sum the guard has to weigh, so this is the
	// case that tells a real deadline check from a bare context wait.
	gw.retryBackoff = time.Millisecond
	cd := &countingDial{failures: 1 << 30}
	gw.Dial = cd.dial

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := gw.Run(ctx, deviceFor(srv), "show running-config", MaxCaptureBytes); err == nil {
		t.Fatal("an unreachable device must fail the capture")
	}
	if elapsed := time.Since(start); elapsed > 120*time.Millisecond {
		t.Errorf("the capture ran %v, past the caller's 120ms deadline", elapsed)
	}
	if got := cd.count(); got != 1 {
		t.Errorf("dialed %d times, want 1 — no backoff fits inside the deadline", got)
	}
}

// TestSSHGatewayRetryDelayIsBoundedAndJittered: every step stays inside
// [step/2, step) and never exceeds the ceiling.
func TestSSHGatewayRetryDelayIsBoundedAndJittered(t *testing.T) {
	gw := &SSHGateway{}
	seen := map[time.Duration]bool{}
	for i := 0; i < 40; i++ {
		d := gw.retryDelay(1)
		if d < captureRetryBase/2 || d >= captureRetryBase {
			t.Fatalf("attempt-1 delay %v outside [%v,%v)", d, captureRetryBase/2, captureRetryBase)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Error("the backoff carries no jitter — replicas would re-dial in lockstep")
	}
	for attempt := 1; attempt <= 12; attempt++ {
		if d := gw.retryDelay(attempt); d >= captureRetryCeiling {
			t.Errorf("attempt %d delay %v reached the ceiling %v", attempt, d, captureRetryCeiling)
		}
	}
}
