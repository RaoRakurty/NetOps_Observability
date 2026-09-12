// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// sshgw.go — the LIVE command source: one read-only `show` over the platform's
// SSH gateway.
//
// This is NOT a second SSH implementation. It is the SAME vendored, audited
// client the operator terminal and the config-capture path use
// (golang.org/x/crypto/ssh, CLAUDE.md §6 allowlist), configured with the SAME
// host-key custody: HostKeyCheck is INJECTED and production binds it to
// device_ssh.go's trust-on-first-use pinned fingerprint store, so a device whose
// key changed is refused HERE for exactly the same reason, and with exactly the
// same evidence, as it would be refused in the terminal. There is no
// InsecureIgnoreHostKey anywhere in this file and no code path that proceeds on
// a mismatch.
//
// It mirrors internal/configstore/sshgw.go deliberately — the differences are
// only the ones diagnostics require, and every one of them NARROWS the surface:
//
//   - a single non-interactive `exec` of ONE command from the CLOSED per-vendor
//     table (commandtable.go), never a shell and never a caller-supplied string;
//   - no PTY and no stdin — the session cannot be typed into;
//   - a hard byte cap on the response (§9) enforced by the writer itself, so a
//     device that streams forever is cut off rather than filling memory;
//   - a context deadline pushed onto the socket, so it can break a stuck
//     handshake or read rather than only wrapping the call.
//
// The Gateway interface is what keeps CI offline: every test in this package
// injects a fake session and no test ever opens a socket.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// DefaultDialTimeout bounds the TCP dial + SSH handshake (§9).
	DefaultDialTimeout = 10 * time.Second
	// DefaultCommandTimeout bounds ONE command end to end. A `show` that has not
	// answered within this window is a failed probe, not a reason to hang the
	// operator's collection.
	DefaultCommandTimeout = 30 * time.Second
	// MaxOutputBytes is the hard ceiling on ONE command's captured output (§9).
	// A diagnostics `show` is kilobytes; this is generous headroom, not a target.
	MaxOutputBytes = 512 << 10
	// MaxStreamOutputBytes is the hard ceiling on ONE command's output when it
	// is STREAMED rather than buffered (RunStream).
	//
	// It is a different number from MaxOutputBytes because it bounds a different
	// risk. MaxOutputBytes protects the HEAP: everything under it is held in
	// memory at once, so it must stay small. A streamed command never lands in
	// memory — it goes to the caller's writer, which for the TAC escalation is a
	// spill file on the way into the bundle — so what needs bounding there is
	// the DISK and the wall clock, not the heap. The vendors' own first-ask
	// collection sets the size: Cisco documents `show tech-support` output in
	// the tens of megabytes on a loaded chassis, and a ceiling below that would
	// turn the one command TAC always asks for into a truncated file.
	MaxStreamOutputBytes = 128 << 20
	// DefaultStreamTimeout bounds ONE streamed command end to end. A support
	// bundle takes minutes on a busy box; 30 s (DefaultCommandTimeout) is the
	// right budget for a `show ip ospf neighbor` and the wrong one for this.
	DefaultStreamTimeout = 15 * time.Minute
)

var (
	// ErrNoAddress is a device with nothing to dial.
	ErrNoAddress = errors.New("protocoldiag: device has no address")
	// ErrTooLarge is the output-cap refusal.
	ErrTooLarge = errors.New("protocoldiag: command output exceeded the size cap")
	// ErrCommandNotInTable is the closed-table refusal: a command that the
	// catalog could not have rendered for this device's dialect is never run,
	// even when it is a perfectly valid read-only `show` (§8 least privilege).
	ErrCommandNotInTable = errors.New("protocoldiag: command is not in the closed per-vendor command table")
	// ErrDeviceBusy is the one-in-flight-per-device refusal.
	ErrDeviceBusy = errors.New("protocoldiag: a diagnostics command is already running on this device")
)

// Credential is the least-privilege diagnostics identity: a READ-ONLY account
// whose command set is the `show` class, never an enable/config-capable one.
//
// It is fetched per command through an injected function so the secret is held
// for the life of one session and never cached on a struct — and it is never
// logged, never audited and never returned by any handler (§8).
type Credential struct {
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

// Gateway runs ONE already-validated read-only command on one device. Injecting
// it is what lets the whole collect path be tested with no network, and what
// keeps this package from holding ambient authority to reach devices (§5).
type Gateway interface {
	Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error)
}

// StreamingGateway runs one already-validated command and STREAMS its output to
// w instead of returning it.
//
// It is a separate, OPTIONAL interface rather than a change to Gateway for two
// reasons. First, compatibility: every existing gateway and every test fake
// stays valid, and a caller that needs streaming asks for it with a type
// assertion and falls back honestly when the transport cannot. Second, honesty
// about the bound: a streamed command is allowed a far larger ceiling
// (MaxStreamOutputBytes) precisely because its bytes never accumulate in memory,
// and that budget must not be reachable through the buffered call by accident.
//
// It returns the number of bytes written to w. A gateway that hits the ceiling
// returns ErrTooLarge with the bytes written so far already in w — a truncated
// support bundle with an honest note beats no bundle at all, and the caller
// records the truncation on the command.
type StreamingGateway interface {
	RunStream(ctx context.Context, dev Device, command string, maxBytes int64, w io.Writer) (int64, error)
}

// SSHGateway is the production Gateway.
type SSHGateway struct {
	// Credentials yields the diagnostics identity for a device. Required.
	Credentials func(ctx context.Context, dev Device) (Credential, error)
	// HostKeyCheck implements trust-on-first-use against the PLATFORM's pinned
	// fingerprint store. It returns (firstSeen, ok); ok=false means a recorded
	// fingerprint exists and DIFFERS — a possible MITM, and the command is
	// refused. Required: a nil check is a fail-closed error, never a bypass.
	HostKeyCheck func(addr, fingerprint string) (firstSeen, ok bool)
	// Dial opens the TCP connection. Optional: nil uses a bounded net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTimeout bounds the dial + handshake; <= 0 uses DefaultDialTimeout.
	DialTimeout time.Duration
	// Port is the default SSH port when the device carries none.
	Port int
	// OnHostKey is an optional observability hook (first-seen pins are worth a
	// log line). It never decides anything.
	OnHostKey func(dev Device, fingerprint string, firstSeen bool)
}

// Run implements Gateway. Output is BUFFERED and bounded by MaxOutputBytes; use
// RunStream for a command whose output belongs on disk rather than on the heap.
func (g *SSHGateway) Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error) {
	if maxBytes <= 0 || maxBytes > MaxOutputBytes {
		maxBytes = MaxOutputBytes
	}
	out := &capWriter{max: maxBytes}
	if _, err := g.exec(ctx, dev, command, out); err != nil {
		return "", err
	}
	return out.String(), nil
}

// RunStream implements StreamingGateway: the SAME session, the same host-key
// custody and the same bounds, with the output written straight through to w.
//
// The ceiling is MaxStreamOutputBytes rather than MaxOutputBytes because nothing
// here accumulates in memory — see the constant's own note. On overflow the
// bytes already written to w are KEPT and ErrTooLarge is returned with the count,
// so a caller can record an honest truncation instead of discarding minutes of a
// support bundle.
func (g *SSHGateway) RunStream(ctx context.Context, dev Device, command string, maxBytes int64, w io.Writer) (int64, error) {
	if w == nil {
		return 0, errors.New("protocoldiag: RunStream needs a writer")
	}
	if maxBytes <= 0 || maxBytes > MaxStreamOutputBytes {
		maxBytes = MaxStreamOutputBytes
	}
	cw := &capStream{w: w, max: maxBytes}
	n, err := g.exec(ctx, dev, command, cw)
	if cw.overflow {
		return n, ErrTooLarge
	}
	return n, err
}

// exec opens one session, runs one already-validated command and copies its
// stdout into sink. It is the single place the dial, the host-key custody, the
// deadline watchdog and the session hygiene live, so the buffered and streamed
// paths cannot drift apart on any of them.
func (g *SSHGateway) exec(ctx context.Context, dev Device, command string, sink interface {
	io.Writer
	written() int64
	overflowed() bool
}) (int64, error) {
	if g.Credentials == nil {
		return 0, errors.New("protocoldiag: no diagnostics credentials configured")
	}
	if g.HostKeyCheck == nil {
		// Fail CLOSED. An absent host-key policy is not "trust everything".
		return 0, errors.New("protocoldiag: no host-key verification configured — refusing to connect")
	}
	if dev.Address == "" {
		return 0, ErrNoAddress
	}
	timeout := g.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	port := dev.Port
	if port <= 0 {
		port = g.Port
	}
	if port <= 0 || port > 65535 {
		port = 22
	}
	addr := net.JoinHostPort(dev.Address, strconv.Itoa(port))

	cred, err := g.Credentials(ctx, dev)
	if err != nil {
		return 0, fmt.Errorf("diagnostics credentials unavailable: %w", err)
	}
	if cred.Username == "" || (cred.Password == "" && cred.PrivateKey == "") {
		return 0, errors.New("protocoldiag: diagnostics credentials are incomplete")
	}
	auth, err := sshAuthMethods(cred)
	if err != nil {
		return 0, err
	}

	cfg := &ssh.ClientConfig{
		User: cred.Username,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := Fingerprint(key)
			first, ok := g.HostKeyCheck(dev.Address, fp)
			if !ok {
				return fmt.Errorf("host key mismatch for %s (possible MITM) — recorded fingerprint differs", dev.Address)
			}
			if g.OnHostKey != nil {
				g.OnHostKey(dev, fp, first)
			}
			return nil
		},
		Timeout: timeout,
	}

	dial := g.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	// A context deadline must be able to break a stuck handshake or read, so it
	// is pushed onto the socket rather than only wrapping the call (§9).
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl) // best-effort: an unsupported deadline still leaves the ctx watchdog below
	}
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks any in-flight read/write
		case <-closed:
		}
	}()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close() // best-effort: the handshake already failed
		return 0, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	// No PTY and no stdin: this session can be read from, never typed into.
	session.Stdout = sink
	session.Stderr = io.Discard // device chatter is not diagnostic output
	if err := session.Run(command); err != nil {
		if sink.overflowed() {
			return sink.written(), ErrTooLarge
		}
		// A non-zero exit is an honest per-command failure. The collector records
		// it on that command and continues — it never invents output.
		return sink.written(), fmt.Errorf("command %q failed: %w", command, err)
	}
	if sink.overflowed() {
		return sink.written(), ErrTooLarge
	}
	return sink.written(), nil
}

// sshAuthMethods builds the offered SSH auth methods. Password is ALSO offered
// as keyboard-interactive because many network operating systems advertise only
// that method — the same reasoning (and the same fix) as the operator gateway.
func sshAuthMethods(cred Credential) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if cred.PrivateKey != "" {
		signer, err := parseSSHKey(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("invalid diagnostics private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cred.Password != "" {
		pw := cred.Password
		auth = append(auth, ssh.Password(pw))
		auth = append(auth, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(auth) == 0 {
		return nil, errors.New("protocoldiag: no usable diagnostics credential")
	}
	return auth, nil
}

func parseSSHKey(pem, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pem))
}

// Fingerprint renders a host key the way the operator gateway records it, so all
// three paths compare the SAME string against the SAME pin.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// capWriter is the byte cap (§9): it accepts up to max bytes and then refuses,
// so an endlessly-streaming device cannot grow the process's heap.
type capWriter struct {
	max      int64
	n        int64
	buf      []byte
	overflow bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return 0, ErrTooLarge
	}
	if c.n+int64(len(p)) > c.max {
		c.overflow = true
		return 0, ErrTooLarge
	}
	c.buf = append(c.buf, p...)
	c.n += int64(len(p))
	return len(p), nil
}

func (c *capWriter) String() string   { return string(c.buf) }
func (c *capWriter) written() int64   { return c.n }
func (c *capWriter) overflowed() bool { return c.overflow }

// capStream is the STREAMING byte cap: it passes bytes straight through to the
// underlying writer and stops at max.
//
// It differs from capWriter in the one way that matters. capWriter refuses the
// whole write that would cross the cap, because its caller is going to discard
// the buffer anyway. capStream writes the PREFIX that still fits and then stops:
// its caller has a file on disk with minutes of a support bundle in it, and
// throwing that away to return a rounder number would be worse for the TAC
// engineer who has to read it. The truncation is recorded on the command, so
// nothing is silently short.
type capStream struct {
	w        io.Writer
	max      int64
	n        int64
	overflow bool
}

func (c *capStream) Write(p []byte) (int, error) {
	if c.overflow {
		// Report the bytes as consumed so ssh.Session.Run does not fail the
		// whole command with a short-write error: the cap is OUR decision, and
		// it is reported through ErrTooLarge, not through a broken session.
		return len(p), nil
	}
	room := c.max - c.n
	if room <= 0 {
		c.overflow = true
		return len(p), nil
	}
	chunk := p
	if int64(len(chunk)) > room {
		chunk = chunk[:room]
		c.overflow = true
	}
	written, err := c.w.Write(chunk)
	c.n += int64(written)
	if err != nil {
		return written, err
	}
	if written != len(chunk) {
		return written, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *capStream) written() int64   { return c.n }
func (c *capStream) overflowed() bool { return c.overflow }

var (
	_ Gateway          = (*SSHGateway)(nil)
	_ StreamingGateway = (*SSHGateway)(nil)
)
