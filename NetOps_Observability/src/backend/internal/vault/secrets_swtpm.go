package vault

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// secrets_swtpm.go — the swtpm SealingProvider (#17 phase 1a, client side). The
// TPM interaction itself lives in a separate sidecar container that shells out to
// tpm2-tools (so go.mod stays dependency-free, no CLAUDE.md §6 amendment). This
// is a thin Unix-socket client speaking a tiny line protocol to that sidecar:
//
//	UNSEAL\n            → OK <base64-kek>\n   | ERR <reason>\n
//	SEAL <base64-kek>\n → OK\n               | ERR <reason>\n
//
// The socket is the only channel — the KEK (never a secret) crosses it; tenant
// secrets never do. Path from SEAL_SOCKET (default /run/secrets-seal/seal.sock).
// Fail-closed: a missing/erroring sidecar surfaces an error so the Vault refuses
// to activate rather than silently degrading to plaintext.

type swtpmSidecarProvider struct {
	socket  string
	timeout time.Duration
}

func newSwtpmSidecarProvider() *swtpmSidecarProvider {
	sock := strings.TrimSpace(os.Getenv("SEAL_SOCKET"))
	if sock == "" {
		sock = "/run/secrets-seal/seal.sock"
	}
	return &swtpmSidecarProvider{socket: sock, timeout: 10 * time.Second}
}

func (p *swtpmSidecarProvider) Unseal(ctx context.Context) ([]byte, error) {
	resp, err := p.roundtrip(ctx, "UNSEAL")
	if err != nil {
		return nil, err
	}
	// "OK <b64>" on success; a first-run sidecar with no sealed KEK replies
	// "ERR no-kek", which the Vault treats as first-run (generate + Seal).
	if !strings.HasPrefix(resp, "OK ") {
		return nil, fmt.Errorf("swtpm unseal: %s", resp)
	}
	kek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(resp, "OK ")))
	if err != nil {
		return nil, fmt.Errorf("swtpm unseal: malformed KEK: %w", err)
	}
	return kek, nil
}

func (p *swtpmSidecarProvider) Seal(ctx context.Context, kek []byte) error {
	resp, err := p.roundtrip(ctx, "SEAL "+base64.StdEncoding.EncodeToString(kek))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("swtpm seal: %s", resp)
	}
	return nil
}

func (p *swtpmSidecarProvider) roundtrip(ctx context.Context, req string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p.socket)
	if err != nil {
		return "", fmt.Errorf("swtpm sidecar unreachable at %s: %w", p.socket, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte(req + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("swtpm sidecar: empty response")
	}
	return line, nil
}
