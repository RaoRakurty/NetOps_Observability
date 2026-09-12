// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshgw_test.go — the capture TRANSPORT, which until now had no test at all.
//
// Two layers, and both matter:
//
//  1. The SCP source-mode reader and the remote-path grammar are pure functions
//     fed a HOSTILE peer: a declared size far beyond the cap (which must be
//     REFUSED before anything is allocated, never truncated — a truncated pcap
//     reads as a valid short capture), malformed and error headers, a non-zero
//     trailing status, and control bytes that must never reach a log.
//  2. The host-key custody decision is proven against a REAL in-process SSH
//     server (x/crypto/ssh's server side), because a fake transport would prove
//     nothing about the property that matters: a device whose key does not match
//     the platform's pin does not get captured from, and an ABSENT policy is a
//     refusal rather than a bypass.

// ── the SCP reader, against a scripted hostile peer ─────────────────────────

// scpHeader renders a well-formed SCP source-mode file header.
func scpHeader(size int, name string) string { return fmt.Sprintf("C0644 %d %s\n", size, name) }

// runReadSCP drives readSCP over a scripted server stream and returns what the
// client wrote back (its acks) alongside the result.
func runReadSCP(t *testing.T, script []byte, maxBytes int64) ([]byte, *bytes.Buffer, error) {
	t.Helper()
	acks := &bytes.Buffer{}
	got, err := readSCP(bufio.NewReader(bytes.NewReader(script)), acks, maxBytes)
	return got, acks, err
}

func TestReadSCPReturnsExactlyTheDeclaredBytes(t *testing.T) {
	payload := samplePCAP(3)
	script := append([]byte(scpHeader(len(payload), "correlix-cap.pcap")), payload...)
	script = append(script, 0) // per-file status: OK

	got, acks, err := runReadSCP(t, script, MaxBytes)
	if err != nil {
		t.Fatalf("readSCP = %v, want the happy path", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("readSCP returned %d bytes, want the %d declared", len(got), len(payload))
	}
	// Three acks: the opening one, the one that accepts the header, and the one
	// that closes the transfer.
	if acks.Len() != 3 || !bytes.Equal(acks.Bytes(), []byte{0, 0, 0}) {
		t.Fatalf("acks = %v, want three zero bytes", acks.Bytes())
	}
}

// TestReadSCPRefusesAnOversizeDeclarationWithoutAllocating: the bound is checked
// against the DECLARED size BEFORE make([]byte, size). If it were not, this test
// would try to allocate a terabyte and die — which is precisely the point.
func TestReadSCPRefusesAnOversizeDeclarationWithoutAllocating(t *testing.T) {
	const declared = 1 << 40 // 1 TiB
	script := []byte(scpHeader(declared, "correlix-cap.pcap"))

	got, acks, err := runReadSCP(t, script, MaxBytes)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("readSCP = %v, want ErrTooLarge for a %d-byte declaration", err, int64(declared))
	}
	if got != nil {
		t.Fatalf("a refused transfer returned %d bytes — it must refuse, never truncate", len(got))
	}
	// Exactly ONE ack: the opening one. The second ack is what precedes the
	// allocation, so its absence is the observable proof that the size gate fired
	// before any buffer was made.
	if acks.Len() != 1 {
		t.Fatalf("readSCP wrote %d acks, want 1 — it proceeded past the size gate", acks.Len())
	}
	// And the boundary is exact: one byte over the cap is refused.
	if _, _, err := runReadSCP(t, []byte(scpHeader(65, "x.pcap")), 64); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("65 bytes against a 64-byte cap = %v, want ErrTooLarge", err)
	}
	body := append([]byte(scpHeader(64, "x.pcap")), bytes.Repeat([]byte{0xab}, 64)...)
	if _, _, err := runReadSCP(t, append(body, 0), 64); err != nil {
		t.Fatalf("64 bytes against a 64-byte cap = %v, want it accepted", err)
	}
}

func TestReadSCPRefusesMalformedAndRemoteErrorHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []byte
		want   string
	}{
		{"bare newline", []byte("\n"), "empty response"},
		{"peer hung up before the header", []byte{}, "scp header"},
		{"no file header", []byte("D0755 0 adir\n"), "unexpected response"},
		{"too few fields", []byte("C0644 12\n"), "malformed file header"},
		{"non-numeric size", []byte("C0644 many x.pcap\n"), "malformed file size"},
		{"negative size", []byte("C0644 -1 x.pcap\n"), "malformed file size"},
		{"remote error byte 1", append([]byte{1}, []byte("scp: /var/tmp/x.pcap: No such file\n")...), "remote error"},
		{"remote error byte 2", append([]byte{2}, []byte("scp: protocol error\n")...), "remote error"},
	} {
		got, _, err := runReadSCP(t, tc.script, MaxBytes)
		if err == nil {
			t.Errorf("%s: readSCP accepted it and returned %d bytes", tc.name, len(got))
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
		if got != nil {
			t.Errorf("%s: a refused transfer returned %d bytes", tc.name, len(got))
		}
	}
}

// TestReadSCPSanitizesRemoteText: the peer's error text is UNTRUSTED input that
// lands in an error string and then in a log (§8). Control bytes — a terminal
// escape, a newline that would forge a second log line — must not survive.
func TestReadSCPSanitizesRemoteText(t *testing.T) {
	hostile := "\x1b[2Jscp: \x07evil\x00\rforged-log-line: everything is fine"
	script := append([]byte{1}, []byte(hostile+"\n")...)
	_, _, err := runReadSCP(t, script, MaxBytes)
	if err == nil {
		t.Fatal("a remote-error header was accepted")
	}
	for _, b := range []byte(err.Error()) {
		if b < 0x20 || b == 0x7f {
			t.Fatalf("a control byte (%#x) survived into the error text: %q", b, err.Error())
		}
	}
	if !strings.Contains(err.Error(), "evil") {
		t.Fatalf("sanitizing must keep the printable reason: %q", err.Error())
	}
}

func TestReadSCPRefusesANonZeroTrailingStatus(t *testing.T) {
	payload := []byte("not really a pcap")
	script := append([]byte(scpHeader(len(payload), "x.pcap")), payload...)
	script = append(script, 1)                                  // per-file status: failed
	script = append(script, []byte("disk read error\x07\n")...) // the peer's reason
	got, _, err := runReadSCP(t, script, MaxBytes)
	if err == nil {
		t.Fatal("a transfer whose trailing status was non-zero was accepted as a capture")
	}
	if !strings.Contains(err.Error(), "transfer failed") || !strings.Contains(err.Error(), "disk read error") {
		t.Fatalf("err = %v, want it to say the transfer failed and why", err)
	}
	if got != nil {
		t.Fatalf("a failed transfer returned %d bytes", len(got))
	}
}

// TestReadSCPRefusesATruncatedBody: the declared size is the contract. A peer
// that declares more than it sends must fail, not hand back a short pcap.
func TestReadSCPRefusesATruncatedBody(t *testing.T) {
	script := append([]byte(scpHeader(64, "x.pcap")), bytes.Repeat([]byte{0xcd}, 16)...)
	got, _, err := runReadSCP(t, script, MaxBytes)
	if err == nil {
		t.Fatalf("a body 48 bytes short of its declaration was accepted as %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), "scp body") {
		t.Fatalf("err = %v, want it to name the body read", err)
	}
}

// TestReadLineBoundedRefusesAnUnterminatedLine: a peer that never sends a newline
// must produce an ERROR, not a silently truncated line that the header parser
// then treats as gospel.
func TestReadLineBoundedRefusesAnUnterminatedLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(strings.Repeat("A", 4096)))
	got, err := readLineBounded(r, 512)
	if err == nil {
		t.Fatalf("readLineBounded silently truncated an unterminated line to %q", got)
	}
	if len(got) != 512 {
		t.Fatalf("readLineBounded read %d bytes, want it to stop at the 512-byte bound", len(got))
	}
	// The bounded read is used for the SCP header, so an unterminated header is a
	// refusal all the way out.
	if _, _, err := runReadSCP(t, []byte(strings.Repeat("C", 4096)), MaxBytes); err == nil {
		t.Fatal("an unterminated SCP header was accepted")
	}
}

// ── the remote-path grammar ─────────────────────────────────────────────────

func TestSafeRemotePathAcceptsMintedPathsAndRefusesEverythingElse(t *testing.T) {
	// The shapes the command table actually mints, per vendor.
	for _, ok := range []string{
		"bootflash:correlix-0123456789abcdef0123456789abcdef.pcap",
		"/var/tmp/correlix-0123456789abcdef0123456789abcdef.pcap",
		"/mnt/flash/correlix-0123456789abcdef0123456789abcdef.pcap",
		"flash:/correlix-0123456789abcdef0123456789abcdef.pcap",
		"/var/tmp/correlix-0123456789abcdef0123456789abcdef.pcap",
	} {
		if err := safeRemotePath(ok); err != nil {
			t.Errorf("safeRemotePath(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"/var/tmp/x.pcap; reboot",
		"/var/tmp/x.pcap && reboot",
		"/var/tmp/x.pcap | sh",
		"/var/tmp/$(reboot).pcap",
		"/var/tmp/`reboot`.pcap",
		"/var/tmp/x.pcap\nconfigure terminal",
		"/var/tmp/x.pcap\rreload",
		"/var/tmp/x.pcap > /etc/passwd",
		"/var/tmp/x.pcap*",
		`/var/tmp/"x".pcap`,
		"/var/tmp/'x'.pcap",
		"/var/tmp/x.pcap #",
		"../../etc/shadow",
		"/var/tmp/../../etc/shadow",
		"/var/tmp/..",
		"/var/tmp/" + strings.Repeat("a", 256) + ".pcap",
	} {
		if err := safeRemotePath(bad); err == nil {
			t.Errorf("INJECTION ACCEPTED: safeRemotePath(%q) = nil", bad)
		}
	}
}

// ── the host-key custody decision, against a REAL SSH server ────────────────

// pcapTestSSHServer is a minimal SSH "device": it answers ONE exec request, and
// speaks SCP source mode when the command is `scp -f …`.
type pcapTestSSHServer struct {
	ln       net.Listener
	signer   ssh.Signer
	password string
	payload  []byte

	mu      sync.Mutex
	execCmd string
	wg      sync.WaitGroup
}

func newPcapTestSSHServer(t *testing.T, password string, payload []byte) *pcapTestSSHServer {
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
	s := &pcapTestSSHServer{ln: ln, signer: signer, password: password, payload: payload}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *pcapTestSSHServer) addr() (string, int) {
	a, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		panic("test listener is not TCP")
	}
	return a.IP.String(), a.Port
}

func (s *pcapTestSSHServer) fingerprint() string { return Fingerprint(s.signer.PublicKey()) }

func (s *pcapTestSSHServer) command() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execCmd
}

func (s *pcapTestSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *pcapTestSSHServer) handle(conn net.Conn) {
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
		go s.session(ch, creqs)
	}
}

func (s *pcapTestSSHServer) session(ch ssh.Channel, creqs <-chan *ssh.Request) {
	for req := range creqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
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
		if strings.HasPrefix(cmd, "scp -f ") {
			s.sourceMode(ch)
		} else {
			_, _ = ch.Write(s.payload)
		}
		_, _ = ch.SendRequest("exit-status", false, make([]byte, 4)) // exit 0
		_ = ch.Close()
	}
}

// sourceMode speaks the four-message SCP source protocol readSCP implements.
func (s *pcapTestSSHServer) sourceMode(ch ssh.Channel) {
	br := bufio.NewReader(ch)
	if _, err := br.ReadByte(); err != nil { // the client's opening ack
		return
	}
	if _, err := fmt.Fprintf(ch, "C0644 %d correlix-capture.pcap\n", len(s.payload)); err != nil {
		return
	}
	if _, err := br.ReadByte(); err != nil { // the ack that accepts the header
		return
	}
	if _, err := ch.Write(s.payload); err != nil {
		return
	}
	if _, err := ch.Write([]byte{0}); err != nil { // per-file status: OK
		return
	}
	_, _ = br.ReadByte() // the closing ack; the exit status follows either way
}

// pcapGatewayFor wires a gateway at the test server with an injectable host-key
// policy — the ONE decision these tests exist to pin.
func pcapGatewayFor(srv *pcapTestSSHServer, check func(addr, fp string) (bool, bool)) *SSHGateway {
	return &SSHGateway{
		Credentials: func(context.Context, Device) (Credential, error) {
			return Credential{Username: "capture-ro", Password: srv.password}, nil
		},
		HostKeyCheck: check,
		DialTimeout:  5 * time.Second,
	}
}

func pcapDeviceFor(srv *pcapTestSSHServer) Device {
	host, port := srv.addr()
	return Device{ID: "acme-core", Address: host, Port: port, Vendor: "cisco", OS: "NX-OS", TenantID: "acme"}
}

const testRemotePath = "/var/tmp/correlix-0123456789abcdef0123456789abcdef.pcap"

// TestPcapSSHGatewayExecVerifiesTheHostKey is the happy path: the pin is
// consulted with the platform's fingerprint spelling, the observability hook
// sees what was pinned, and the device runs exactly the command it was given.
func TestPcapSSHGatewayExecVerifiesTheHostKey(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", []byte("Capturing on Ethernet1/1\n"))
	var (
		gotAddr, gotFP string
		calls          int
		hookFP         string
		hookFirst      bool
		hookDev        Device
		hookCalls      int
	)
	gw := pcapGatewayFor(srv, func(addr, fp string) (bool, bool) {
		calls++
		gotAddr, gotFP = addr, fp
		return true, true // first seen, and accepted
	})
	gw.OnHostKey = func(dev Device, fp string, first bool) {
		hookCalls++
		hookDev, hookFP, hookFirst = dev, fp, first
	}
	dev := pcapDeviceFor(srv)

	out, err := gw.Exec(context.Background(), dev, "monitor capture CORRELIX start", MaxControlOutputBytes)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out, "Capturing on Ethernet1/1") {
		t.Fatalf("Exec returned %q", out)
	}
	if calls != 1 {
		t.Fatalf("host-key check called %d times, want exactly 1", calls)
	}
	if gotAddr != dev.Address {
		t.Errorf("host-key check saw addr %q, want %q", gotAddr, dev.Address)
	}
	if gotFP != srv.fingerprint() || !strings.HasPrefix(gotFP, "SHA256:") {
		t.Errorf("fingerprint = %q, want %q", gotFP, srv.fingerprint())
	}
	if strings.HasSuffix(gotFP, "=") {
		t.Errorf("fingerprint %q is not OpenSSH's unpadded spelling", gotFP)
	}
	if hookCalls != 1 || hookFP != gotFP || !hookFirst || hookDev.ID != dev.ID {
		t.Errorf("OnHostKey = (%d calls, dev %q, %q, first=%v), want one call carrying the device, the "+
			"fingerprint and firstSeen", hookCalls, hookDev.ID, hookFP, hookFirst)
	}
	if srv.command() != "monitor capture CORRELIX start" {
		t.Errorf("the device ran %q", srv.command())
	}
}

// TestPcapSSHGatewayFetchesTheCaptureOverSCP proves the SCP source-mode client
// against a real channel, not a scripted buffer.
func TestPcapSSHGatewayFetchesTheCaptureOverSCP(t *testing.T) {
	payload := samplePCAP(5)
	srv := newPcapTestSSHServer(t, "pw", payload)
	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })

	got, err := gw.Fetch(context.Background(), pcapDeviceFor(srv), testRemotePath, MaxBytes)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Fetch returned %d bytes, want the %d the device sent", len(got), len(payload))
	}
	if srv.command() != "scp -f "+testRemotePath {
		t.Fatalf("the device ran %q, want the SCP source-mode command for the minted path", srv.command())
	}
}

// TestPcapSSHGatewayRefusesAHostKeyMismatch is the MITM refusal. BOTH verbs must
// stop dead, and neither may return anything the caller could mistake for a
// result.
func TestPcapSSHGatewayRefusesAHostKeyMismatch(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", samplePCAP(5))
	hookCalls := 0
	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, false })
	gw.OnHostKey = func(Device, string, bool) { hookCalls++ }
	dev := pcapDeviceFor(srv)

	out, err := gw.Exec(context.Background(), dev, "monitor capture CORRELIX start", MaxControlOutputBytes)
	if err == nil {
		t.Fatal("Exec ran a command on a device whose host key does not match the pin")
	}
	if out != "" {
		t.Fatalf("a refused Exec returned %q", out)
	}
	if !strings.Contains(err.Error(), "host key mismatch") || !strings.Contains(err.Error(), "possible MITM") {
		t.Fatalf("the refusal must name the reason an operator has to act on: %v", err)
	}

	data, err := gw.Fetch(context.Background(), dev, testRemotePath, MaxBytes)
	if err == nil {
		t.Fatal("Fetch pulled a capture off a device whose host key does not match the pin")
	}
	if data != nil {
		t.Fatalf("a refused Fetch returned %d bytes", len(data))
	}
	if !strings.Contains(err.Error(), "host key mismatch") || !strings.Contains(err.Error(), "possible MITM") {
		t.Fatalf("the Fetch refusal does not name the reason: %v", err)
	}
	if hookCalls != 0 {
		t.Fatalf("OnHostKey fired %d times on a MISMATCH — the hook must only see accepted keys", hookCalls)
	}
	if srv.command() != "" {
		t.Fatalf("the device ran %q despite the mismatch", srv.command())
	}
}

// TestPcapSSHGatewayFailsClosedWithoutAHostKeyPolicy: an ABSENT policy is not
// "trust everything". Both verbs refuse, and they refuse before the dial.
func TestPcapSSHGatewayFailsClosedWithoutAHostKeyPolicy(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", samplePCAP(2))
	dials := 0
	gw := pcapGatewayFor(srv, nil)
	gw.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		d := &net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, network, addr)
	}
	dev := pcapDeviceFor(srv)

	out, err := gw.Exec(context.Background(), dev, "monitor capture CORRELIX start", MaxControlOutputBytes)
	if err == nil {
		t.Fatal("a nil HostKeyCheck was treated as a BYPASS: Exec connected with no host-key policy at all")
	}
	if out != "" {
		t.Fatalf("a refused Exec returned %q", out)
	}
	if !strings.Contains(err.Error(), "host-key verification") {
		t.Fatalf("the refusal does not say the policy is missing: %v", err)
	}
	data, err := gw.Fetch(context.Background(), dev, testRemotePath, MaxBytes)
	if err == nil {
		t.Fatal("a nil HostKeyCheck was treated as a BYPASS: Fetch pulled a capture with no host-key policy")
	}
	if data != nil {
		t.Fatalf("a refused Fetch returned %d bytes", len(data))
	}
	if dials != 0 {
		t.Fatalf("the gateway dialled %d times without a host-key policy — the refusal must precede the dial", dials)
	}
	if srv.command() != "" {
		t.Fatalf("the device ran %q with no host-key policy configured", srv.command())
	}
}

// TestPcapSSHGatewayRefusesAnUnsafeRemotePathBeforeDialling: the remote path
// arrives through a STORE ROW, so it is untrusted the moment anything else can
// write to it. It never reaches `scp -f`, and the device is never dialled.
func TestPcapSSHGatewayRefusesAnUnsafeRemotePathBeforeDialling(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", samplePCAP(2))
	dials := 0
	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })
	gw.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		d := &net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, network, addr)
	}
	for _, bad := range []string{"", "/var/tmp/x.pcap; reboot", "/var/tmp/../../etc/shadow", "/var/tmp/$(reboot)"} {
		if _, err := gw.Fetch(context.Background(), pcapDeviceFor(srv), bad, MaxBytes); err == nil {
			t.Errorf("Fetch accepted the remote path %q", bad)
		}
	}
	if dials != 0 {
		t.Fatalf("the gateway dialled %d times for a refused path", dials)
	}
	if srv.command() != "" {
		t.Fatalf("the device ran %q for a refused path", srv.command())
	}
}

// TestPcapSSHGatewayBoundsControlOutput (§9): a device that streams more than the
// cap fails loudly rather than filling memory with device chatter.
func TestPcapSSHGatewayBoundsControlOutput(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", bytes.Repeat([]byte("a"), 8192))
	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })
	if _, err := gw.Exec(context.Background(), pcapDeviceFor(srv), "show capture", 512); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// TestPcapSSHGatewayRefusesIncompleteCredentialsAndDevices covers the remaining
// fail-closed preconditions on connect().
func TestPcapSSHGatewayRefusesIncompleteCredentialsAndDevices(t *testing.T) {
	srv := newPcapTestSSHServer(t, "correct", samplePCAP(1))
	dev := pcapDeviceFor(srv)

	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })
	gw.Credentials = func(context.Context, Device) (Credential, error) { return Credential{}, nil }
	if _, err := gw.Exec(context.Background(), dev, "show capture", MaxControlOutputBytes); err == nil {
		t.Error("an empty credential was accepted")
	}
	gw.Credentials = func(context.Context, Device) (Credential, error) {
		return Credential{Username: "capture-ro", Password: "wrong"}, nil
	}
	if _, err := gw.Exec(context.Background(), dev, "show capture", MaxControlOutputBytes); err == nil {
		t.Error("a bad password was accepted")
	}

	nocred := &SSHGateway{HostKeyCheck: func(string, string) (bool, bool) { return false, true }}
	if _, err := nocred.Exec(context.Background(), dev, "show capture", MaxControlOutputBytes); err == nil {
		t.Error("a gateway with no Credentials function connected anyway")
	}

	noaddr := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })
	if _, err := noaddr.Exec(context.Background(), Device{ID: "d1"}, "show capture", MaxControlOutputBytes); !errors.Is(err, ErrNoAddress) {
		t.Errorf("err = %v, want ErrNoAddress", err)
	}
}

// TestPcapSSHGatewayRespectsContextCancellation (§9: all IO has a timeout).
func TestPcapSSHGatewayRespectsContextCancellation(t *testing.T) {
	srv := newPcapTestSSHServer(t, "pw", samplePCAP(1))
	gw := pcapGatewayFor(srv, func(string, string) (bool, bool) { return false, true })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gw.Exec(ctx, pcapDeviceFor(srv), "show capture", MaxControlOutputBytes); err == nil {
		t.Fatal("a cancelled context must abort the command")
	}
	if _, err := gw.Fetch(ctx, pcapDeviceFor(srv), testRemotePath, MaxBytes); err == nil {
		t.Fatal("a cancelled context must abort the fetch")
	}
}
