// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// sshgw_test.go — the LIVE diagnostics transport, proven against a REAL
// in-process SSH server (x/crypto/ssh's server side).
//
// This file exists because the rest of the package proves everything ABOVE the
// gateway against an injected fake, which is exactly the right design and proves
// nothing at all about the gateway itself. The three properties that only a real
// handshake can establish are all here: the host-key pin is consulted with the
// platform's fingerprint format and a MISMATCH refuses the command with no
// output; an ABSENT pin store is a refusal rather than a bypass; and the
// streaming path delivers bytes straight through and stops at its ceiling.
//
// The server is the same shape as internal/configstore/sshgw_test.go's — one
// ed25519 host key, password auth, one exec request — deliberately, so the two
// transports stay comparable.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// diagSSHServer answers ONE exec request with a fixed payload. It is the
// "device" in these tests.
type diagSSHServer struct {
	ln       net.Listener
	signer   ssh.Signer
	password string
	payload  string

	mu      sync.Mutex
	execCmd string
	wg      sync.WaitGroup
}

func newDiagSSHServer(t *testing.T, password, payload string) *diagSSHServer {
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
	s := &diagSSHServer{ln: ln, signer: signer, password: password, payload: payload}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *diagSSHServer) addr() (host string, port int) {
	a, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		return "", 0
	}
	return a.IP.String(), a.Port
}

func (s *diagSSHServer) fingerprint() string { return Fingerprint(s.signer.PublicKey()) }

func (s *diagSSHServer) command() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execCmd
}

func (s *diagSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *diagSSHServer) handle(conn net.Conn) {
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

func diagGatewayFor(srv *diagSSHServer, check func(string, string) (bool, bool)) *SSHGateway {
	return &SSHGateway{
		Credentials: func(context.Context, Device) (Credential, error) {
			return Credential{Username: "diag-ro", Password: srv.password}, nil
		},
		HostKeyCheck: check,
		DialTimeout:  5 * time.Second,
	}
}

func diagDeviceFor(srv *diagSSHServer) Device {
	host, port := srv.addr()
	return Device{ID: "d1", Hostname: "core-01", Address: host, Port: port,
		Platform: "Cisco IOS-XE 17.9", TenantID: "acme"}
}

const diagShowOutput = "Interface              IP-Address      OK? Method Status\n" +
	"GigabitEthernet0/0     10.0.0.1        YES NVRAM  up\n"

// ── host-key custody ────────────────────────────────────────────────────────

// TestSSHGateway_RunsThroughHostKeyVerification is the happy path — and the
// proof that the pin store is consulted with the address and the platform's
// SHA256 fingerprint spelling, once.
func TestSSHGateway_RunsThroughHostKeyVerification(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", diagShowOutput)
	var (
		gotAddr   string
		gotFP     string
		calls     int
		hookFP    string
		hookFirst bool
	)
	gw := diagGatewayFor(srv, func(addr, fp string) (bool, bool) {
		calls++
		gotAddr, gotFP = addr, fp
		return true, true
	})
	gw.OnHostKey = func(_ Device, fp string, first bool) { hookFP, hookFirst = fp, first }
	dev := diagDeviceFor(srv)

	out, err := gw.Run(context.Background(), dev, "show ip interface brief", MaxOutputBytes)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != diagShowOutput {
		t.Fatalf("capture = %q, want the device's own output", out)
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
	if hookFP != gotFP || !hookFirst {
		t.Errorf("OnHostKey observed (%q,%v), want (%q,true)", hookFP, hookFirst, gotFP)
	}
	if srv.command() != "show ip interface brief" {
		t.Errorf("device ran %q", srv.command())
	}
}

// TestSSHGateway_RefusesHostKeyMismatch is the MITM refusal: a RECORDED
// fingerprint that differs stops the command dead, names the reason, and returns
// no output at all.
func TestSSHGateway_RefusesHostKeyMismatch(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", diagShowOutput)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return false, false })
	dev := diagDeviceFor(srv)

	out, err := gw.Run(context.Background(), dev, "show ip interface brief", MaxOutputBytes)
	if err == nil {
		t.Fatal("a host-key mismatch must refuse the command")
	}
	if out != "" {
		t.Fatalf("a refused command must return no output, got %q", out)
	}
	if !strings.Contains(err.Error(), "host key mismatch") || !strings.Contains(err.Error(), "MITM") {
		t.Fatalf("the refusal must name the reason: %v", err)
	}
	if !strings.Contains(err.Error(), dev.Address) {
		t.Errorf("the refusal must name the device it refused: %v", err)
	}
	if srv.command() != "" {
		t.Fatalf("a command reached the device through a refused host key: %q", srv.command())
	}

	// The STREAMING path must refuse identically — same session, same custody.
	var buf bytes.Buffer
	n, err := gw.RunStream(context.Background(), dev, "show tech-support", MaxStreamOutputBytes, &buf)
	if err == nil {
		t.Fatal("RunStream must refuse a host-key mismatch too")
	}
	if n != 0 || buf.Len() != 0 {
		t.Fatalf("a refused stream wrote %d bytes", buf.Len())
	}
}

// TestSSHGateway_FailsClosedWithoutHostKeyPolicy: a nil HostKeyCheck is a
// REFUSAL, not a bypass — and the refusal happens before anything is dialed.
func TestSSHGateway_FailsClosedWithoutHostKeyPolicy(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", diagShowOutput)
	gw := diagGatewayFor(srv, nil)
	dialed := 0
	gw.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed++
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, addr)
	}

	out, err := gw.Run(context.Background(), diagDeviceFor(srv), "show ip interface brief", MaxOutputBytes)
	if err == nil {
		t.Fatal("a missing host-key policy must refuse the connection")
	}
	if out != "" {
		t.Fatalf("a refused command must return no output, got %q", out)
	}
	if !strings.Contains(err.Error(), "host-key verification") {
		t.Errorf("the refusal must say why: %v", err)
	}
	if dialed != 0 {
		t.Errorf("the gateway dialed %d times with no host-key policy — it must refuse first", dialed)
	}
	if srv.command() != "" {
		t.Fatalf("a command reached the device with no host-key policy: %q", srv.command())
	}

	var buf bytes.Buffer
	if _, err := gw.RunStream(context.Background(), diagDeviceFor(srv), "show tech-support", 1024, &buf); err == nil {
		t.Fatal("RunStream must fail closed without a host-key policy too")
	}
	if dialed != 0 {
		t.Errorf("RunStream dialed %d times with no host-key policy", dialed)
	}
}

// ── the streaming path ──────────────────────────────────────────────────────

// TestSSHGateway_RunStreamDeliversTheStream: bytes go straight through to the
// caller's writer, the byte count is honest, and the same host-key custody runs.
func TestSSHGateway_RunStreamDeliversTheStream(t *testing.T) {
	payload := strings.Repeat("show tech line\n", 500)
	srv := newDiagSSHServer(t, "pw", payload)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })

	var buf bytes.Buffer
	n, err := gw.RunStream(context.Background(), diagDeviceFor(srv), "show tech-support", MaxStreamOutputBytes, &buf)
	if err != nil {
		t.Fatalf("RunStream: %v", err)
	}
	if buf.String() != payload {
		t.Fatalf("streamed %d bytes, want the device's %d", buf.Len(), len(payload))
	}
	if n != int64(len(payload)) {
		t.Errorf("RunStream reported %d bytes, wrote %d", n, buf.Len())
	}
}

// TestSSHGateway_RunStreamCapsAtTheBound: the ceiling is honoured, the PREFIX
// already streamed is KEPT (a truncated support bundle beats no bundle), and the
// refusal is ErrTooLarge with an honest count.
//
// The bound is injectable — RunStream's maxBytes is used as given whenever it is
// positive and <= MaxStreamOutputBytes — so the cap logic is exercised at a small
// honest bound rather than by pushing 128 MiB through a test.
func TestSSHGateway_RunStreamCapsAtTheBound(t *testing.T) {
	payload := strings.Repeat("a", 4096)
	srv := newDiagSSHServer(t, "pw", payload)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })

	var buf bytes.Buffer
	const bound = 512
	n, err := gw.RunStream(context.Background(), diagDeviceFor(srv), "show tech-support", bound, &buf)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if n != bound {
		t.Errorf("RunStream reported %d bytes, want exactly the bound %d", n, bound)
	}
	if buf.Len() != bound {
		t.Fatalf("the writer holds %d bytes, want the %d-byte prefix kept", buf.Len(), bound)
	}
	if buf.String() != payload[:bound] {
		t.Error("the kept prefix must be the device's own leading bytes")
	}
}

// TestSSHGateway_RunStreamDefaultsToTheCeiling: a non-positive or over-ceiling
// bound is CLAMPED to MaxStreamOutputBytes rather than refused or taken as given.
func TestSSHGateway_RunStreamDefaultsToTheCeiling(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", diagShowOutput)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	for _, bound := range []int64{0, -1, MaxStreamOutputBytes + 1} {
		var buf bytes.Buffer
		n, err := gw.RunStream(context.Background(), diagDeviceFor(srv), "show tech-support", bound, &buf)
		if err != nil {
			t.Fatalf("RunStream(maxBytes=%d): %v", bound, err)
		}
		if n != int64(len(diagShowOutput)) || buf.String() != diagShowOutput {
			t.Errorf("RunStream(maxBytes=%d) streamed %d bytes: %q", bound, n, buf.String())
		}
	}
}

// TestSSHGateway_RunStreamNeedsAWriter.
func TestSSHGateway_RunStreamNeedsAWriter(t *testing.T) {
	gw := &SSHGateway{
		Credentials:  func(context.Context, Device) (Credential, error) { return Credential{}, nil },
		HostKeyCheck: func(string, string) (bool, bool) { return true, true },
	}
	if _, err := gw.RunStream(context.Background(), Device{ID: "d1", Address: "192.0.2.1"}, "show version", 1024, nil); err == nil {
		t.Fatal("RunStream must refuse a nil writer")
	}
}

// ── the buffered path's own cap, and the pre-dial refusals ──────────────────

// TestSSHGateway_RunCapsTheHeap (§9): the BUFFERED path holds everything in
// memory, so its cap refuses the whole capture rather than keeping a prefix.
func TestSSHGateway_RunCapsTheHeap(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", strings.Repeat("a", 4096))
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	out, err := gw.Run(context.Background(), diagDeviceFor(srv), "show ip interface brief", 512)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if out != "" {
		t.Errorf("an over-cap buffered capture must return nothing, got %d bytes", len(out))
	}
}

// TestSSHGateway_RefusesIncompleteCredentials — before any dial.
func TestSSHGateway_RefusesIncompleteCredentials(t *testing.T) {
	srv := newDiagSSHServer(t, "correct", diagShowOutput)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })

	gw.Credentials = func(context.Context, Device) (Credential, error) { return Credential{}, nil }
	if _, err := gw.Run(context.Background(), diagDeviceFor(srv), "show version", MaxOutputBytes); err == nil {
		t.Fatal("an incomplete credential must be refused")
	}
	gw.Credentials = func(context.Context, Device) (Credential, error) {
		return Credential{}, errors.New("vault down")
	}
	if _, err := gw.Run(context.Background(), diagDeviceFor(srv), "show version", MaxOutputBytes); err == nil {
		t.Fatal("an unavailable credential must be refused")
	}
	gw.Credentials = nil
	if _, err := gw.Run(context.Background(), diagDeviceFor(srv), "show version", MaxOutputBytes); err == nil {
		t.Fatal("a gateway with no credential source must be refused")
	}
	// A WRONG credential is a real auth failure at the device.
	gw.Credentials = func(context.Context, Device) (Credential, error) {
		return Credential{Username: "diag-ro", Password: "wrong"}, nil
	}
	if _, err := gw.Run(context.Background(), diagDeviceFor(srv), "show version", MaxOutputBytes); err == nil {
		t.Fatal("a bad credential must fail the command")
	}
}

// TestSSHGateway_RefusesDeviceWithoutAddress.
func TestSSHGateway_RefusesDeviceWithoutAddress(t *testing.T) {
	gw := &SSHGateway{
		Credentials: func(context.Context, Device) (Credential, error) {
			return Credential{Username: "u", Password: "p"}, nil
		},
		HostKeyCheck: func(string, string) (bool, bool) { return true, true },
	}
	if _, err := gw.Run(context.Background(), Device{ID: "d1"}, "show version", 1024); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("err = %v, want ErrNoAddress", err)
	}
	var buf bytes.Buffer
	if _, err := gw.RunStream(context.Background(), Device{ID: "d1"}, "show version", 1024, &buf); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("err = %v, want ErrNoAddress", err)
	}
}

// TestSSHGateway_RespectsContextCancellation (§9: all IO has a timeout).
func TestSSHGateway_RespectsContextCancellation(t *testing.T) {
	srv := newDiagSSHServer(t, "pw", diagShowOutput)
	gw := diagGatewayFor(srv, func(string, string) (bool, bool) { return true, true })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gw.Run(ctx, diagDeviceFor(srv), "show version", MaxOutputBytes); err == nil {
		t.Fatal("a cancelled context must abort the command")
	}
}

// ── capStream, at the real ceiling ──────────────────────────────────────────

// TestCapStream_StopsAtTheRealCeiling exercises the 128 MiB bound itself without
// moving 128 MiB: the writer is primed to just under MaxStreamOutputBytes and
// then asked to cross it. The constant, not a stand-in, is what is under test.
func TestCapStream_StopsAtTheRealCeiling(t *testing.T) {
	var sink bytes.Buffer
	cs := &capStream{w: &sink, max: MaxStreamOutputBytes, n: MaxStreamOutputBytes - 8}

	n, err := cs.Write([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The cap reports the bytes CONSUMED so ssh.Session.Run does not fail the
	// whole command with a short write — the refusal travels as ErrTooLarge.
	if n != 16 {
		t.Errorf("Write reported %d consumed, want 16", n)
	}
	if sink.String() != "01234567" {
		t.Errorf("wrote %q, want only the 8 bytes that still fit", sink.String())
	}
	if !cs.overflowed() {
		t.Fatal("crossing MaxStreamOutputBytes must set overflow")
	}
	if cs.written() != MaxStreamOutputBytes {
		t.Errorf("written() = %d, want exactly the ceiling %d", cs.written(), MaxStreamOutputBytes)
	}

	// Once over, further writes are swallowed (consumed, not forwarded) so the
	// session drains cleanly instead of dying mid-transfer.
	before := sink.Len()
	n, err = cs.Write([]byte("more"))
	if err != nil || n != 4 {
		t.Errorf("post-overflow Write = (%d,%v), want (4,nil)", n, err)
	}
	if sink.Len() != before {
		t.Error("bytes were forwarded after the cap was hit")
	}
	if cs.written() != MaxStreamOutputBytes {
		t.Errorf("written() moved past the ceiling to %d", cs.written())
	}
}

// TestCapStream_PropagatesWriterFailure: a failing sink is reported, never
// silently counted as delivered (§10).
func TestCapStream_PropagatesWriterFailure(t *testing.T) {
	cs := &capStream{w: failingWriter{}, max: 1024}
	if _, err := cs.Write([]byte("hello")); err == nil {
		t.Fatal("a writer failure must be reported")
	}
	if cs.written() != 0 {
		t.Errorf("written() = %d after a failed write, want 0", cs.written())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
