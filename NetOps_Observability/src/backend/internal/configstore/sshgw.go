// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

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

// sshgw.go — capture over the platform's SSH gateway.
//
// This is NOT a second SSH implementation. It is the SAME vendored, audited
// client the operator terminal uses (golang.org/x/crypto/ssh, CLAUDE.md §6
// allowlist), configured with the SAME host-key custody: HostKeyCheck is
// INJECTED and production binds it to device_ssh.go's trust-on-first-use pinned
// fingerprint store, so a device whose key changed is refused HERE for exactly
// the same reason and with exactly the same evidence as it would be refused in
// the terminal. There is no InsecureIgnoreHostKey anywhere in this file and no
// code path that proceeds on a mismatch.
//
// The differences from the interactive gateway are the ones capture requires and
// they all narrow the surface:
//
//   - a single non-interactive `exec` of ONE command from the closed per-vendor
//     table, never a shell and never a caller-supplied string;
//   - no PTY, no stdin — the session cannot be typed into;
//   - a hard byte cap on the response (§9) enforced by the writer itself, so a
//     device that streams forever is cut off rather than filling memory;
//   - a context deadline that closes the connection from underneath a stuck
//     read.

// Gateway runs ONE read-only command on a device. Injecting it is what lets the
// whole capture path be tested with no network (and what keeps this package from
// holding ambient authority to reach devices, §5).
type Gateway interface {
	Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error)
}

// Credential is the least-privilege capture identity. The design's rule stands:
// the platform authenticates with a READ-ONLY account whose command set is the
// `show running-config` class, never an enable/config-capable one.
//
// It is fetched per capture through an injected function so the secret is held
// for the life of one session and never cached on this struct — and it is never
// logged, never audited and never returned by any handler (§8).
type Credential struct {
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

// SSHGateway is the production Gateway.
type SSHGateway struct {
	// Credentials yields the capture identity for a device. Required.
	Credentials func(ctx context.Context, dev Device) (Credential, error)
	// HostKeyCheck implements trust-on-first-use against the PLATFORM's pinned
	// fingerprint store. It returns (firstSeen, ok); ok=false means a recorded
	// fingerprint exists and DIFFERS — a possible MITM, and the capture is
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

// Run implements Gateway.
func (g *SSHGateway) Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error) {
	if g.Credentials == nil {
		return "", errors.New("configstore: no capture credentials configured")
	}
	if g.HostKeyCheck == nil {
		// Fail CLOSED. An absent host-key policy is not "trust everything".
		return "", errors.New("configstore: no host-key verification configured — refusing to connect")
	}
	if dev.Address == "" {
		return "", ErrNoAddress
	}
	if maxBytes <= 0 || maxBytes > MaxCaptureBytes {
		maxBytes = MaxCaptureBytes
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
		return "", fmt.Errorf("capture credentials unavailable: %w", err)
	}
	if cred.Username == "" || (cred.Password == "" && cred.PrivateKey == "") {
		return "", errors.New("configstore: capture credentials are incomplete")
	}

	auth, err := authMethods(cred)
	if err != nil {
		return "", err
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
		return "", fmt.Errorf("connect: %w", err)
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
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	out := &capWriter{max: maxBytes}
	session.Stdout = out
	session.Stderr = io.Discard // device chatter is not configuration
	if err := session.Run(command); err != nil {
		if out.overflow {
			return "", ErrTooLarge
		}
		// A non-zero exit with output is still a failed capture: a truncated or
		// error-prefixed config must never be stored as a version.
		return "", fmt.Errorf("command %q failed: %w", command, err)
	}
	if out.overflow {
		return "", ErrTooLarge
	}
	return out.String(), nil
}

// authMethods builds the offered SSH auth methods. Password is ALSO offered as
// keyboard-interactive because many network operating systems advertise only
// that method — the same reasoning (and the same fix) as the operator gateway.
func authMethods(cred Credential) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if cred.PrivateKey != "" {
		signer, err := parseKey(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("invalid capture private key: %w", err)
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
		return nil, errors.New("configstore: no usable capture credential")
	}
	return auth, nil
}

func parseKey(pem, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pem))
}

// Fingerprint renders a host key the way the operator gateway records it, so the
// two paths compare the SAME string against the SAME pin.
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

func (c *capWriter) String() string { return string(c.buf) }

var _ Gateway = (*SSHGateway)(nil)
