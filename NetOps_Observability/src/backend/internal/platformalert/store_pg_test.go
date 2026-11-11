// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package platformalert

// store_pg_test.go — the record against a REAL Postgres through the platform
// kv (app_kv), as the Postgres backend runs it in production: written as the
// NOBYPASSRLS app role, sealed at rest, read back by a second store (a second
// api replica). Runs in CI's pg-integration leg (PG_TEST_DSN).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
)

func TestStoreRoundTripOnPostgres(t *testing.T) {
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // a fresh database runs every migration first
	defer cancel()
	pg, err := platformdb.NewPGStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	key := "/data/platform_alert_route.pgtest-" + time.Now().UTC().Format("150405.000000000") + ".json"
	deps := StoreDeps{Key: key, Load: pg.Load, Save: pg.Save, Seal: fakeSeal, Open: fakeOpen}

	s := NewStore(deps)
	if ok, everRead := s.Health(); !ok || !everRead || s.Current().PageRouted() {
		t.Fatal("an absent row must read as the empty default, not a failure")
	}
	c := validNtfyOnly()
	c.Ntfy.Token = fakeSecret("pg-ntfy")
	c.SMS = validSMSOnly().SMS
	if err := s.Save(c, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := pg.Load(key)
	if err != nil {
		t.Fatalf("raw Load: %v", err)
	}
	for _, secret := range []string{c.Ntfy.Token, c.SMS.AuthToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("a secret is stored in the clear in app_kv: %s", raw)
		}
	}
	replica := NewStore(deps)
	got := replica.Current()
	if got.Ntfy.Token != c.Ntfy.Token || got.SMS.AuthToken != c.SMS.AuthToken || !got.PageRouted() {
		t.Fatalf("second replica read back: %+v", got)
	}
}
