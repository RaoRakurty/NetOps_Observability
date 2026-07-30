package backend

// verify_ssh_test.go — the SSH runner's defense-in-depth refusal: even when a
// caller hands it an arbitrary command, a non-allowlisted command is refused
// before any network IO. Lives with the runner (the engine and its allowlist
// moved to internal/verify).

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/ssh"
	"net"
	"netops/backend/collectors"
	"netops/backend/internal/verify"
	"netops/backend/models"
)

func TestVerifySSHRunRefusesNonAllowlistedCommand(t *testing.T) {
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	// Even when a caller hands the runner an arbitrary command, it must be
	// refused before any network IO for that command.
	out := s.verifySSHRun(context.Background(), models.Device{ID: "d1", Address: "127.0.0.1"},
		verify.SSHCred{User: "u", Password: "p", Port: 1}, // port 1: nothing listens
		map[string]string{"evil": "reload"})
	res, ok := out["evil"]
	if !ok || res.Err == nil || !strings.Contains(res.Err.Error(), "allowlist") {
		t.Fatalf("non-allowlisted command must be refused, got %+v", res)
	}
}

func resultsByCheck(rs []verify.CheckResult) map[string]verify.CheckResult {
	m := map[string]verify.CheckResult{}
	for _, r := range rs {
		m[r.Check] = r
	}
	return m
}

func newTestHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startFakeSSHServer serves password-auth SSH sessions answering exec requests
// from the canned outputs map. Returns the listen port.
func startFakeSSHServer(t *testing.T, signer ssh.Signer, outputs map[string]string) int {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "verify" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sconn, chans, reqs, herr := ssh.NewServerConn(c, cfg)
				if herr != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, cerr := newChan.Accept()
					if cerr != nil {
						continue
					}
					go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
						defer ch.Close()
						for req := range chReqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							if ssh.Unmarshal(req.Payload, &payload) != nil {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							if out, ok := outputs[payload.Command]; ok {
								_, _ = ch.Write([]byte(out))
							}
							_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							return // one exec per session, like real network OSes
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestVerifySSHRunAgainstFakeServer(t *testing.T) {
	signer := newTestHostSigner(t)
	port := startFakeSSHServer(t, signer, map[string]string{
		"show ip interface brief": "Interface Status Protocol\nGi0/0 up up\nGi0/1 up down\n",
		"show ip bgp summary":     "Neighbor V AS State\n10.0.0.2 4 65001 never Idle\n",
	})
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	dev := models.Device{ID: "dev-1", Name: "edge-1", Address: "127.0.0.1", Vendor: "cisco"}
	cred := verify.SSHCred{User: "verify", Password: "pw", Port: port}

	out := s.verifySSHRun(context.Background(), dev, cred, map[string]string{
		"ssh_interfaces": "show ip interface brief",
		"ssh_routing":    "show ip bgp summary",
	})
	if len(out) != 2 {
		t.Fatalf("want 2 outputs, got %+v", out)
	}
	if out["ssh_interfaces"].Err != nil || !strings.Contains(out["ssh_interfaces"].Output, "Gi0/1") {
		t.Fatalf("ssh_interfaces: %+v", out["ssh_interfaces"])
	}
	// TOFU: a NEW host key on the same address must be refused (possible MITM).
	otherSigner := newTestHostSigner(t)
	port2 := startFakeSSHServer(t, otherSigner, nil)
	cred.Port = port2
	out2 := s.verifySSHRun(context.Background(), dev, cred, map[string]string{
		"ssh_routing": "show ip bgp summary",
	})
	if out2["ssh_routing"].Err == nil || !strings.Contains(out2["ssh_routing"].Err.Error(), "host key mismatch") {
		t.Fatalf("changed host key must be refused, got %+v", out2["ssh_routing"])
	}
}

func TestVerifyEngineEndToEndWithFakeSSH(t *testing.T) {
	signer := newTestHostSigner(t)
	port := startFakeSSHServer(t, signer, map[string]string{
		"show ip interface brief": "Interface Status Protocol\nGi0/0 up up\n",
		"show ip bgp summary":     "Neighbor V AS Up/Down State/PfxRcd\n10.0.0.2 4 65001 01:02:03 12\n",
	})
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	d := s.newVerifyDialers()
	// no SNMP daemon in tests: keep snmp faked, exercise tcp + ssh for real
	d.SNMPReach = func(ctx context.Context, tgt collectors.Target) error { return nil }
	d.SNMPUptime = func(ctx context.Context, tgt collectors.Target) (int64, error) { return 4000, nil }
	e := verify.NewEngine(d)
	tgt := verify.Target{
		Device: models.Device{ID: "dev-1", Name: "edge-1", Address: "127.0.0.1", Vendor: "cisco"},
		SNMP:   &collectors.Target{ID: "dev-1", Address: "127.0.0.1"},
		SSH:    &verify.SSHCred{User: "verify", Password: "pw", Port: port},
	}
	m := resultsByCheck(e.Run(context.Background(), []verify.Target{tgt}))
	if m["reach_tcp"].Status != verify.StatusPass {
		t.Fatalf("reach_tcp against live listener: %+v", m["reach_tcp"])
	}
	if m["snmp_uptime"].Status != verify.StatusPass || len(m["snmp_uptime"].RefutesKinds) != 1 {
		t.Fatalf("snmp_uptime: %+v", m["snmp_uptime"])
	}
	if m["ssh_interfaces"].Status != verify.StatusPass {
		t.Fatalf("ssh_interfaces: %+v", m["ssh_interfaces"])
	}
	if m["ssh_routing"].Status != verify.StatusPass || len(m["ssh_routing"].RefutesKinds) != 2 {
		t.Fatalf("ssh_routing: %+v", m["ssh_routing"])
	}
}
