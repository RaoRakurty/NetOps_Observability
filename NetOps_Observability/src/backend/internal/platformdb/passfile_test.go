// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"netops/backend/internal/credfile"
)

// passfile_test.go — the file-backed Postgres password, without a database. The
// rotation behaviour against a real server is passfile_pg_test.go.

func writePassfile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pgpass")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// replaceFile is what the installer does: rename over the path, a new inode.
func replaceFile(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func poolCfg(t *testing.T, dsn string) *pgxpool.Config {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// connect runs the pool's hook the way pgxpool does, on a copy of the config.
func connect(cfg *pgxpool.Config) (string, error) {
	cc := cfg.ConnConfig.Copy()
	if err := cfg.BeforeConnect(context.Background(), cc); err != nil {
		return "", err
	}
	return cc.Password, nil
}

const cleanDSN = "postgres://netops_app@postgres:5432/netops?sslmode=disable"

func TestPasswordFileUnsetLeavesTheDSNAlone(t *testing.T) {
	cfg := poolCfg(t, "postgres://u:from-url@postgres:5432/netops?sslmode=disable")
	c, err := attachPasswordFile(cfg, "  ")
	if err != nil || c != nil {
		t.Fatalf("c=%v err=%v, want nil, nil", c, err)
	}
	if cfg.BeforeConnect != nil {
		t.Fatal("no PGPASSFILE must install no hook")
	}
	if cfg.ConnConfig.Password != "from-url" {
		t.Fatal("the DSN's password must stay")
	}
}

func TestPasswordFileIsReadAtEveryNewConnection(t *testing.T) {
	p := writePassfile(t, "*:*:*:*:one\n")
	cfg := poolCfg(t, cleanDSN)
	if _, err := attachPasswordFile(cfg, p); err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "one" {
		t.Fatalf("first connect: %q, %v", got, err)
	}
	replaceFile(t, p, "*:*:*:*:two\n")
	if got, err := connect(cfg); err != nil || got != "two" {
		t.Fatalf("the connection after a rotation must present the new password: %q, %v", got, err)
	}
}

func TestPasswordFileNeverLoadedRefusesTheConnection(t *testing.T) {
	cfg := poolCfg(t, cleanDSN)
	if _, err := attachPasswordFile(cfg, filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(cfg); !errors.Is(err, credfile.ErrNotLoaded) {
		t.Fatalf("err = %v, want refusal: never an empty password", err)
	}
}

func TestPasswordFileKeepsLastGoodOnATransientFailure(t *testing.T) {
	p := writePassfile(t, "*:*:*:*:good\n")
	cfg := poolCfg(t, cleanDSN)
	c, err := attachPasswordFile(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "good" {
		t.Fatalf("%q, %v", got, err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "good" {
		t.Fatalf("a missing file must keep the last good value: %q, %v", got, err)
	}
	if _, failures, _ := c.file.Status(); failures == 0 {
		t.Fatal("the failure must be counted")
	}
}

// A .env not migrated yet: the URL's password still works while the file is
// absent, and the file wins as soon as it exists.
func TestLegacyDSNPasswordIsOnlyAFallback(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pgpass")
	cfg := poolCfg(t, "postgres://u:from-url@postgres:5432/netops?sslmode=disable")
	if _, err := attachPasswordFile(cfg, p); err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "from-url" {
		t.Fatalf("no file yet: %q, %v", got, err)
	}
	replaceFile(t, p, "*:*:*:*:from-file\n")
	if got, err := connect(cfg); err != nil || got != "from-file" {
		t.Fatalf("the file must win over userinfo: %q, %v", got, err)
	}
}

func TestPasswordFileRefusesAFileNotForThisConnection(t *testing.T) {
	for name, content := range map[string]string{
		"other user":     "*:*:*:someone_else:pw\n",
		"other host":     "elsewhere:*:*:*:pw\n",
		"other port":     "*:6543:*:*:pw\n",
		"other database": "*:*:other:*:pw\n",
		"too few fields": "*:*:*:pw\n",
		"too many":       "*:*:*:*:pw:extra\n",
		"no password":    "*:*:*:*:\n",
		"two lines":      "*:*:*:*:a\n*:*:*:*:b\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := poolCfg(t, cleanDSN)
			if _, err := attachPasswordFile(cfg, writePassfile(t, content)); err != nil {
				t.Fatal(err)
			}
			_, err := connect(cfg)
			if err == nil {
				t.Fatal("a file for another connection must refuse")
			}
			if strings.Contains(err.Error(), "pw") {
				t.Fatalf("the error quotes the file: %v", err)
			}
		})
	}
}

func TestPasswordFileMatchesExplicitFields(t *testing.T) {
	cfg := poolCfg(t, cleanDSN)
	if _, err := attachPasswordFile(cfg, writePassfile(t, "postgres:5432:netops:netops_app:pw\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "pw" {
		t.Fatalf("%q, %v", got, err)
	}
}

// The renderer writes the driver's format, and a rollback depends on the driver
// reading it: pin this parser to pgx's own on the same bytes, including escapes.
func TestPasswordLineAgreesWithTheDriversParser(t *testing.T) {
	for _, line := range []string{
		`*:*:*:*:plain`,
		`*:*:*:*:with\:colon`,
		`*:*:*:*:back\\slash`,
		`*:*:*:*:both\\\:mixed`,
		`*:*:*:*:!@#%^&*-_=+`,
	} {
		t.Run(line, func(t *testing.T) {
			p := writePassfile(t, line+"\n")
			cfg := poolCfg(t, cleanDSN)
			if _, err := attachPasswordFile(cfg, p); err != nil {
				t.Fatal(err)
			}
			got, err := connect(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("PGPASSFILE", p)
			driver, err := pgconn.ParseConfig(cleanDSN)
			if err != nil {
				t.Fatal(err)
			}
			if driver.Password == "" {
				t.Fatal("the driver read no password from the file")
			}
			if got != driver.Password {
				t.Fatalf("this parser %q, pgx %q", got, driver.Password)
			}
		})
	}
}

func TestSocketHostMatchesLikeLocalhost(t *testing.T) {
	cfg := poolCfg(t, "postgres://netops_app@/netops?host=/var/run/postgresql")
	if _, err := attachPasswordFile(cfg, writePassfile(t, "localhost:*:*:*:pw\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := connect(cfg); err != nil || got != "pw" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestResolveDSN(t *testing.T) {
	getenv := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	if got, err := ResolveDSN(getenv(map[string]string{"DATABASE_URL": "from-env"})); err != nil || got != "from-env" {
		t.Fatalf("env form: %q, %v", got, err)
	}
	f := writePassfile(t, "postgres://u:p@db/x\n")
	got, err := ResolveDSN(getenv(map[string]string{"DATABASE_URL_FILE": f, "DATABASE_URL": "ignored"}))
	if err != nil || got != "postgres://u:p@db/x" {
		t.Fatalf("file form: %q, %v", got, err)
	}
	// Never a silent fall back to the environment form.
	_, err = ResolveDSN(getenv(map[string]string{"DATABASE_URL_FILE": filepath.Join(t.TempDir(), "absent"), "DATABASE_URL": "must-not-be-used"}))
	if !errors.Is(err, credfile.ErrNotLoaded) {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestParsePgpassLineErrorsCarryNoValue(t *testing.T) {
	_, err := parsePgpassLine("not-a-pgpass-line-with-s3cret")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error quotes the line: %v", err)
	}
}

func TestWriteCredentialMetricsIsSilentWithoutAPostgresStore(t *testing.T) {
	prevActive, prevKind := active, kind
	t.Cleanup(func() { active, kind = prevActive, prevKind })
	UseMemory()
	var buf bytes.Buffer
	WriteCredentialMetrics(&buf)
	if buf.Len() != 0 {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}
