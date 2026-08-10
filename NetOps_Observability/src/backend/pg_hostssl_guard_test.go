package backend

// pg_hostssl_guard_test.go — F-4 regression pin (TLS assurance run 2026-08-09).
//
// The image-default pg_hba row `host all all all scram-sha-256` matches SSL
// AND non-SSL TCP, so a credentialed client could connect with sslmode=disable
// and put the password + rows on the wire: TLS on this store was client-side
// convention only. On a TLS deployment the tls-entrypoint wrapper now stages a
// pg_hba whose network row is `hostssl` — a non-TLS connection must be refused
// BEFORE any authentication exchange.
//
// Deliberately NOT build-tagged. The tagged `pgintegration` suite in this
// package has been non-compiling since the platformdb extraction (2026-07-28)
// and nobody noticed, because nothing in the default build ever touches it — a
// tagged guard is a guard that can rot. This file compiles on every
// `go test ./...` and SKIPS unless pointed at a TLS-wrapped postgres:
//
//	PG_HOSTSSL_TEST_DSN='postgres://netops_app:<pw>@postgres:5432/netops' \
//	  go test -count=1 -run TestPostgresRefusesPlaintextTCP ./...
//
// The DSN's sslmode is irrelevant — the test strips TLS from the parsed config
// (and from every fallback) so the attempt is unambiguously plaintext. It is
// env-gated rather than always-on because the CI pg-integration job runs a
// plaintext throwaway Postgres where this property is deliberately absent; the
// always-running half of the F-4 pin is the static contract test
// test_postgres_tls_entrypoint_requires_hostssl (tests/test_assurance_contracts.py).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgresRefusesPlaintextTCP(t *testing.T) {
	dsn := os.Getenv("PG_HOSTSSL_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_HOSTSSL_TEST_DSN not set — the hostssl guard runs only against a TLS-wrapped postgres")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	// Force plaintext. pgx keeps a fallback chain (sslmode=prefer is "TLS
	// first, then plaintext"), so clearing only the primary TLSConfig can still
	// let a fallback negotiate TLS and turn this negative test green for the
	// wrong reason.
	cfg.TLSConfig = nil
	for _, fb := range cfg.Fallbacks {
		fb.TLSConfig = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
		t.Fatalf("plaintext TCP connection SUCCEEDED — pg_hba still carries a `host` (not `hostssl`) network row (F-4)")
	}
	// The refusal must be the pg_hba gate, not a credential failure: a password
	// error would mean the plaintext connection reached the auth exchange —
	// exactly what hostssl exists to prevent.
	msg := err.Error()
	if !strings.Contains(msg, "pg_hba.conf") {
		t.Fatalf("plaintext TCP refused, but not by the pg_hba gate (want a no-pg_hba-entry error, got: %v)", err)
	}
	if strings.Contains(strings.ToLower(msg), "password") {
		t.Fatalf("plaintext TCP reached password authentication — the connection was not refused at the pg_hba gate (F-4): %v", err)
	}
}
