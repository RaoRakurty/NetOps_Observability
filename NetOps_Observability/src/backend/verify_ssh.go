package main

// verify_ssh.go — production executors for the Active Verification engine
// (verify_engine.go). The SSH runner reuses the device-SSH gateway's host-key
// posture (TOFU via s.sshHosts — a changed key is refused, never accepted) and
// its auth shape (password offered as both password and keyboard-interactive,
// since many network OSes advertise only the latter).
//
// READ-ONLY defense in depth: every command is re-validated against the closed
// allowlist table HERE, immediately before execution — a non-allowlisted
// command cannot run even if a caller composed one.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"

	"golang.org/x/crypto/ssh"
)

// newVerifyDialers wires the engine's executor seams to the real network.
func (s *server) newVerifyDialers() verifyDialers {
	return verifyDialers{
		TCPReach: func(ctx context.Context, addr string) error {
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return err
			}
			return conn.Close()
		},
		SNMPReach:  collectors.ProbeSNMP,
		SNMPUptime: collectors.SysUpTimeSeconds,
		SSHRun:     s.verifySSHRun,
	}
}

// verifySSHOutputCap bounds how much device output one command may return.
const verifySSHOutputCap = 256 << 10 // 256 KiB

// verifySSHRun opens ONE SSH connection to the device and executes the given
// allowlisted commands, each in its own exec session under its own timeout.
// Session content beyond the bounded command output is never logged.
func (s *server) verifySSHRun(ctx context.Context, dev models.Device, cred verifySSHCred, cmds map[string]string) map[string]verifySSHOut {
	out := map[string]verifySSHOut{}
	ids := make([]string, 0, len(cmds))
	for id, cmd := range cmds {
		if !verifyCommandAllowed(cmd) {
			// Impossible via the engine (commands come from the table), kept as
			// a hard runtime guarantee regardless of caller.
			out[id] = verifySSHOut{Err: errors.New("command not in read-only allowlist — refused")}
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return out
	}

	var auth []ssh.AuthMethod
	if cred.PrivateKey != "" {
		signer, err := parsePrivateKey(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			for _, id := range ids {
				out[id] = verifySSHOut{Err: fmt.Errorf("invalid verification ssh key: %w", err)}
			}
			return out
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
		for _, id := range ids {
			out[id] = verifySSHOut{Err: errors.New("no verification ssh credential material")}
		}
		return out
	}

	port := cred.Port
	if port <= 0 || port > 65535 {
		port = 22
	}
	addr := net.JoinHostPort(hostOnly(dev.Address), fmt.Sprintf("%d", port))

	// Host-key TOFU shared with the device-SSH gateway: first key recorded, a
	// later mismatch refused (possible MITM).
	hostKeyCB := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := sshFingerprint(key)
		if _, okHost := s.sshHosts.check(hostOnly(dev.Address), fp); !okHost {
			return fmt.Errorf("host key mismatch for %s (possible MITM) — recorded fingerprint differs", dev.Address)
		}
		return nil
	}
	cfg := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         sshDialTimeout(),
	}

	d := net.Dialer{Timeout: sshDialTimeout()}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		for _, id := range ids {
			out[id] = verifySSHOut{Err: fmt.Errorf("connect failed: %w", err)}
		}
		return out
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		for _, id := range ids {
			out[id] = verifySSHOut{Err: fmt.Errorf("ssh handshake failed: %w", err)}
		}
		return out
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// ctx watchdog: a cancelled/expired run tears the connection down, which
	// unblocks any in-flight session.
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-watchdogDone:
		}
	}()

	perCmd := verifyCheckTimeout()
	for _, id := range ids {
		if ctx.Err() != nil {
			// remaining commands stay absent — the engine reports them skipped
			return out
		}
		out[id] = runOneSSHCommand(client, cmds[id], perCmd)
	}
	return out
}

// runOneSSHCommand executes a single allowlisted command in a fresh exec
// session with a hard timeout and a bounded output buffer.
func runOneSSHCommand(client *ssh.Client, cmd string, timeout time.Duration) verifySSHOut {
	session, err := client.NewSession()
	if err != nil {
		return verifySSHOut{Err: fmt.Errorf("session open failed: %w", err)}
	}
	defer session.Close()

	buf := &boundedBuf{cap: verifySSHOutputCap}
	session.Stdout = buf
	session.Stderr = buf

	timer := time.AfterFunc(timeout, func() { _ = session.Close() })
	defer timer.Stop()

	if err := session.Run(cmd); err != nil {
		if buf.Len() > 0 {
			// Some network OSes report a nonzero/aborted status on exec even
			// after emitting the full listing — the output is still evidence;
			// the parser decides (unparseable ⇒ skipped, never guessed).
			return verifySSHOut{Output: buf.String()}
		}
		return verifySSHOut{Err: fmt.Errorf("exec failed: %w", err)}
	}
	return verifySSHOut{Output: buf.String()}
}

// boundedBuf keeps at most cap bytes and silently drops the rest (bounded IO —
// a chatty device cannot balloon memory).
type boundedBuf struct {
	cap int
	b   []byte
}

func (w *boundedBuf) Write(p []byte) (int, error) {
	if room := w.cap - len(w.b); room > 0 {
		if len(p) > room {
			w.b = append(w.b, p[:room]...)
		} else {
			w.b = append(w.b, p...)
		}
	}
	return len(p), nil // report full write: dropping excess is intentional
}
func (w *boundedBuf) Len() int       { return len(w.b) }
func (w *boundedBuf) String() string { return string(w.b) }
