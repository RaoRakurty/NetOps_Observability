// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshgw.go — capture orchestration over the platform's SSH gateway.
//
// This is NOT a second SSH implementation. It is the SAME vendored, audited
// client the operator terminal and the config-capture path use
// (golang.org/x/crypto/ssh, CLAUDE.md §6 allowlist), configured with the SAME
// host-key custody: HostKeyCheck is INJECTED and production binds it to
// device_ssh.go's trust-on-first-use pinned fingerprint store, so a device whose
// key changed is refused here for exactly the same reason and with exactly the
// same evidence as it would be refused in the terminal. There is no
// InsecureIgnoreHostKey in this file and no path that proceeds on a mismatch.
//
// Everything about this gateway narrows the surface relative to the interactive
// one: a single non-interactive `exec` of ONE command from the closed table,
// never a shell and never a caller-supplied string; no PTY and no stdin, so the
// session cannot be typed into; a hard byte cap enforced by the writer itself;
// and a context deadline pushed onto the socket so a stuck read is broken rather
// than waited on (§9).
//
// FETCH uses SCP source mode (`scp -f <path>`) over the same exec channel. That
// is deliberate: the stdlib has no SFTP client, adding one would need a new
// module (§6), and the vendors' own "print the file" commands mangle binary. SCP
// source mode is a four-message protocol we can implement exactly, bounded, over
// the module we already have.

// Credential is the least-privilege capture identity. It is fetched per capture
// through an injected function so the secret is held for the life of one session
// and never cached on this struct — and it is never logged, never audited and
// never returned by any handler (§8).
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
	// OnHostKey is an optional observability hook (a first-seen pin is worth a
	// log line). It never decides anything.
	OnHostKey func(dev Device, fingerprint string, firstSeen bool)
}

// Fingerprint renders the SHA256 host-key fingerprint in OpenSSH's spelling.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// Exec implements Gateway.
func (g *SSHGateway) Exec(ctx context.Context, dev Device, command string, maxBytes int64) (string, error) {
	client, closeFn, err := g.connect(ctx, dev)
	if err != nil {
		return "", err
	}
	defer closeFn()
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	out := &capWriter{max: boundBytes(maxBytes, MaxControlOutputBytes)}
	session.Stdout = out
	session.Stderr = io.Discard // device chatter is not capture output
	if err := session.Run(command); err != nil {
		if out.overflow {
			return "", ErrTooLarge
		}
		return "", fmt.Errorf("command %q failed: %w", command, err)
	}
	if out.overflow {
		return "", ErrTooLarge
	}
	return out.String(), nil
}

// Fetch implements Gateway using SCP source mode.
func (g *SSHGateway) Fetch(ctx context.Context, dev Device, remotePath string, maxBytes int64) ([]byte, error) {
	if remotePath == "" {
		return nil, errors.New("pcap: no remote capture path")
	}
	// The path is built by this package from a minted capture id and a constant
	// template, but it arrives here through a store row — untrusted the moment
	// anything else can write to it (§3). A path with a shell-meaningful byte is
	// refused rather than passed to `scp -f`.
	if err := safeRemotePath(remotePath); err != nil {
		return nil, err
	}
	client, closeFn, err := g.connect(ctx, dev)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	session.Stderr = io.Discard
	if err := session.Start("scp -f " + remotePath); err != nil {
		return nil, fmt.Errorf("scp start: %w", err)
	}
	data, rerr := readSCP(bufio.NewReader(stdout), stdin, boundBytes(maxBytes, MaxBytes))
	_ = stdin.Close() // best-effort: the transfer is over either way
	if rerr != nil {
		_ = session.Wait() // best-effort: drain the remote exit
		return nil, rerr
	}
	if err := session.Wait(); err != nil {
		return nil, fmt.Errorf("scp: %w", err)
	}
	return data, nil
}

// safeRemotePath refuses any path that is not a plain absolute-or-vendor-prefixed
// file name. It is the last line before a string reaches `scp -f`.
func safeRemotePath(p string) error {
	if len(p) > 256 {
		return errors.New("pcap: remote capture path is too long")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '.' || c == '-' || c == '_' || c == ':':
		default:
			return fmt.Errorf("pcap: remote capture path contains a forbidden character %q", string(rune(c)))
		}
	}
	if strings.Contains(p, "..") {
		return errors.New("pcap: remote capture path may not traverse")
	}
	return nil
}

// readSCP runs the SCP source-mode protocol: ack, read the `C<mode> <size>
// <name>` header, ack, read exactly size bytes, read the trailing status, ack.
// It is bounded at every step — a header line, a size and a body all have caps,
// so a hostile or broken peer cannot make this allocate without limit (§9).
func readSCP(r *bufio.Reader, w io.Writer, maxBytes int64) ([]byte, error) {
	ack := func() error {
		_, err := w.Write([]byte{0})
		return err
	}
	if err := ack(); err != nil {
		return nil, fmt.Errorf("scp: %w", err)
	}
	// The header line is tiny; bound the read so a peer that never sends a
	// newline cannot stream forever.
	header, err := readLineBounded(r, 512)
	if err != nil {
		return nil, fmt.Errorf("scp header: %w", err)
	}
	if len(header) == 0 {
		return nil, errors.New("scp: empty response")
	}
	switch header[0] {
	case 'C':
		// C0644 <size> <name>
	case 1, 2:
		return nil, fmt.Errorf("scp: remote error: %s", sanitizeSCPError(header[1:]))
	default:
		return nil, fmt.Errorf("scp: unexpected response %q", sanitizeSCPError(header))
	}
	fields := strings.SplitN(strings.TrimSpace(header[1:]), " ", 3)
	if len(fields) < 3 {
		return nil, errors.New("scp: malformed file header")
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 {
		return nil, errors.New("scp: malformed file size")
	}
	if size > maxBytes {
		// REFUSE rather than truncate: a truncated pcap looks like a valid short
		// capture, which is worse than no capture at all.
		return nil, ErrTooLarge
	}
	if err := ack(); err != nil {
		return nil, fmt.Errorf("scp: %w", err)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("scp body: %w", err)
	}
	// Trailing per-file status byte.
	if status, err := r.ReadByte(); err != nil {
		return nil, fmt.Errorf("scp trailer: %w", err)
	} else if status != 0 {
		// We are ALREADY failing here and are only trying to attach the peer's
		// reason. If that read also fails we report the transfer failure with an
		// empty reason rather than replacing a real error with an I/O error
		// about reading the explanation.
		msg, _ := readLineBounded(r, 512) // best-effort: an unreadable reason yields an empty one, never a swapped error
		return nil, fmt.Errorf("scp: transfer failed: %s", sanitizeSCPError(msg))
	}
	if err := ack(); err != nil {
		return nil, fmt.Errorf("scp: %w", err)
	}
	return buf, nil
}

// readLineBounded reads up to max bytes or a newline, whichever comes first.
func readLineBounded(r *bufio.Reader, max int) (string, error) {
	var b strings.Builder
	for i := 0; i < max; i++ {
		c, err := r.ReadByte()
		if err != nil {
			if b.Len() > 0 && errors.Is(err, io.EOF) {
				return b.String(), nil
			}
			return b.String(), err
		}
		if c == '\n' {
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return b.String(), errors.New("line exceeded its bound")
}

// sanitizeSCPError strips control bytes from remote error text before it can
// reach a log or an error string (§8 log hygiene: remote output is untrusted).
func sanitizeSCPError(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 200 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// connect dials, verifies the host key and returns a client plus its closer.
func (g *SSHGateway) connect(ctx context.Context, dev Device) (*ssh.Client, func(), error) {
	if g.Credentials == nil {
		return nil, nil, errors.New("pcap: no capture credentials configured")
	}
	if g.HostKeyCheck == nil {
		// Fail CLOSED. An absent host-key policy is not "trust everything".
		return nil, nil, errors.New("pcap: no host-key verification configured — refusing to connect")
	}
	if dev.Address == "" {
		return nil, nil, ErrNoAddress
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
		return nil, nil, fmt.Errorf("capture credentials unavailable: %w", err)
	}
	if cred.Username == "" || (cred.Password == "" && cred.PrivateKey == "") {
		return nil, nil, errors.New("pcap: capture credentials are incomplete")
	}
	auth, err := authMethods(cred)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	// A context deadline must be able to break a stuck handshake or read, so it
	// is pushed onto the socket rather than only wrapping the call (§9).
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl) // best-effort: the watchdog below still applies
	}
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks any in-flight read/write
		case <-closed:
		}
	}()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		close(closed)
		_ = conn.Close() // best-effort: the handshake already failed
		return nil, nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	return client, func() {
		_ = client.Close() // best-effort: nothing actionable on close failure
		close(closed)
	}, nil
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
		return nil, errors.New("pcap: no usable capture credential")
	}
	return auth, nil
}

func parseKey(pem, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pem))
}

func boundBytes(want, hard int64) int64 {
	if want <= 0 || want > hard {
		return hard
	}
	return want
}

// capWriter accumulates output up to a hard cap and then STOPS, recording the
// overflow. The bound lives in the writer (not in a caller's discipline) so
// every path that streams device output is bounded by construction (§9).
type capWriter struct {
	b        strings.Builder
	max      int64
	n        int64
	overflow bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return len(p), nil // absorb and drop: the caller checks overflow
	}
	room := c.max - c.n
	if int64(len(p)) > room {
		if room > 0 {
			c.b.Write(p[:room])
			c.n += room
		}
		c.overflow = true
		return len(p), nil
	}
	c.b.Write(p)
	c.n += int64(len(p))
	return len(p), nil
}

func (c *capWriter) String() string { return c.b.String() }
