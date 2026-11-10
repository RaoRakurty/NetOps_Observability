// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"netops/backend/internal/credfile"
)

// passfile.go — the app-state role's password comes from a mounted file, not
// DATABASE_URL (tracker 384; the same pattern as tracker 367 layer 1).
//
// The file is the driver's own format: scripts/install.py renders one wildcard
// line into data/secrets/postgres/api/pgpass and compose sets PGPASSFILE. pgx
// reads that variable by itself, but in pgconn.ParseConfig, which runs ONCE, and
// it swallows every read error. On its own that gives neither of the two things
// this package needs:
//
//   - a connection opened after a rotation would present the password from boot,
//     so a pool recycling onto a rotated role would fail until a restart;
//   - an unreadable file would silently become an empty password.
//
// So BeforeConnect resolves the password for EVERY new connection through
// internal/credfile: re-read on change, last good value on a transient error, and
// a connection refused outright if the file never loaded.
//
// Leaving the variable to the driver as well is deliberate. A rollback to an image
// from before this change, under the same compose file and the same migrated
// .env, still authenticates through pgx's own passfile support.

// passwordRecheck stats the file on every new connection. Connects are rare (pool
// of 25, 30 min lifetime), and a rotation must reach the very next one rather than
// whichever comes after a second of grace.
const passwordRecheck = time.Nanosecond

// errPassfileNoMatch: the file holds a line, but not for this connection.
var errPassfileNoMatch = errors.New("password file holds no line for this connection")

// errPassfileFormat is what a line that is not the five pgpass fields gets. The
// message describes the shape only; it never quotes the line.
var errPassfileFormat = errors.New("password file is not one host:port:database:user:password line")

// parsePgpassLine splits one pgpass line on unescaped colons, the same format
// github.com/jackc/pgpassfile reads ("\:" and "\\" are the escapes). The value
// is never quoted back in an error.
func parsePgpassLine(line string) ([5]string, error) {
	var out [5]string
	field := 0
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line) && (line[i+1] == ':' || line[i+1] == '\\'):
			i++
			b.WriteByte(line[i])
		case c == ':':
			if field == len(out)-1 {
				return out, errPassfileFormat
			}
			out[field] = b.String()
			b.Reset()
			field++
		default:
			b.WriteByte(c)
		}
	}
	if field != len(out)-1 {
		return out, errPassfileFormat
	}
	out[field] = b.String()
	return out, nil
}

// connCredential is the file-backed password of one pool.
type connCredential struct {
	file *credfile.File
	// fallback is what DATABASE_URL (or PGPASSWORD) carried. Only an install that
	// has not been migrated yet has one; it is used only while the file cannot
	// be loaded, so a stale URL can never beat a good file.
	fallback string
}

// passwordFor resolves the password for a new connection. An error means the
// connection must not be attempted.
func (c *connCredential) passwordFor(host, port, database, user string) (string, error) {
	line, err := c.file.Value()
	if err != nil {
		if c.fallback != "" {
			return c.fallback, nil
		}
		return "", err
	}
	f, err := parsePgpassLine(line)
	if err != nil {
		return "", fmt.Errorf("%s: %w", c.file.Path(), err)
	}
	for i, want := range []string{host, port, database, user} {
		if f[i] != "*" && f[i] != want {
			return "", fmt.Errorf("%s: %w", c.file.Path(), errPassfileNoMatch)
		}
	}
	if f[4] == "" {
		return "", fmt.Errorf("%s: %w", c.file.Path(), credfile.ErrEmpty)
	}
	return f[4], nil
}

// attachPasswordFile wires PGPASSFILE into the pool config. It returns nil when
// the variable is not set: that deployment keeps whatever DATABASE_URL says.
func attachPasswordFile(cfg *pgxpool.Config, path string) (*connCredential, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	file, err := credfile.New(path, credfile.Options{
		Recheck: passwordRecheck,
		OnStateChange: func(e error) {
			if e != nil {
				logError("db", "Postgres password file cannot be used — keeping the last good value if there is one", map[string]any{"error": e.Error()})
				return
			}
			logInfo("db", "Postgres password file readable again", nil)
		},
	})
	if err != nil {
		return nil, err
	}
	c := &connCredential{file: file, fallback: cfg.ConnConfig.Password}
	cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
		host := cc.Host
		if network, _ := pgconn.NetworkAddress(cc.Host, cc.Port); network == "unix" {
			host = "localhost" // libpq's rule for a socket, and pgx's own
		}
		pw, err := c.passwordFor(host, strconv.Itoa(int(cc.Port)), cc.Database, cc.User)
		if err != nil {
			return fmt.Errorf("postgres password: %w", err)
		}
		cc.Password = pw
		return nil
	}
	return c, nil
}

// ResolveDSN returns the app-state DSN. DATABASE_URL_FILE names a file holding the
// whole DSN; the Helm chart uses it, mounting the existing Secret key, so an
// operator's Secret keeps working and the password stays out of the pod's
// environment with nothing to change. It is read once, at boot: after changing
// that Secret, restart the pods, as the environment form always needed. Compose
// uses a credential-free DATABASE_URL plus PGPASSFILE, which rotate live.
// An unreadable file is an error: the caller must not fall back to another DSN.
func ResolveDSN(getenv func(string) string) (string, error) {
	path := strings.TrimSpace(getenv("DATABASE_URL_FILE"))
	if path == "" {
		return getenv("DATABASE_URL"), nil
	}
	file, err := credfile.New(path, credfile.Options{})
	if err != nil {
		return "", err
	}
	dsn, err := file.Value()
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL_FILE: %w", err)
	}
	return dsn, nil
}

// WriteCredentialMetrics renders the file-backed Postgres credential's state for
// /metrics. It prints nothing unless a Postgres store with a password file is
// active. A loaded value of 0 means no new connection can open.
func WriteCredentialMetrics(w io.Writer) {
	pg, ok := ActivePG()
	if !ok || pg.DB() == nil || pg.DB().cred == nil {
		return
	}
	loaded, failures, _ := pg.DB().cred.file.Status()
	n := 0
	if loaded {
		n = 1
	}
	fmt.Fprintf(w, "# HELP netops_postgres_credential_loaded Whether the Postgres password file holds a valid value (0 = no new connection can open).\n")
	fmt.Fprintf(w, "# TYPE netops_postgres_credential_loaded gauge\n")
	fmt.Fprintf(w, "netops_postgres_credential_loaded %d\n", n)
	fmt.Fprintf(w, "# HELP netops_postgres_credential_reload_errors_total Failed re-reads of the Postgres password file (the last good value is kept).\n")
	fmt.Fprintf(w, "# TYPE netops_postgres_credential_reload_errors_total counter\n")
	fmt.Fprintf(w, "netops_postgres_credential_reload_errors_total %d\n", failures)
}
