// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// chatops_pg_isolation_test.go — storage-layer RLS proof for Iris in Slack /
// Teams (migration 0074), mirroring rca_resolution_pg_isolation_test.go: the
// FORCE-RLS tenant_iso policies on chatops_connections, chatops_links and
// chatops_link_codes are the backstop even if every handler check were
// bypassed (§3a rule 4), secrets reach a row only sealed, and the inbound
// token lookup is the single cross-tenant read. Gated on DATABASE_URL_TEST like
// every pg-integration test in this package.

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/chatops"
	"netops/backend/internal/platformdb"
)

// sealTestCrypter is a reversible stand-in for the vault, bound to tenant and
// field so a value sealed for one tenant never opens for another.
type sealTestCrypter struct{}

func (sealTestCrypter) Encrypt(tenant, field, plain string) (string, error) {
	return "sealed:" + base64.StdEncoding.EncodeToString([]byte(tenant+"|"+field+"|"+plain)), nil
}

func (sealTestCrypter) Decrypt(tenant, field, stored string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "sealed:"))
	if err != nil {
		return "", err
	}
	prefix := tenant + "|" + field + "|"
	if !strings.HasPrefix(string(raw), prefix) {
		return "", errors.New("sealed for another tenant or field")
	}
	return strings.TrimPrefix(string(raw), prefix), nil
}

func TestChatopsRLSIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := chatops.NewPGStore(ps.DB(), sealTestCrypter{})
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(tenant string) chatops.Connection {
		t.Helper()
		c, applyErr := chatops.Apply(chatops.Slack, chatops.Connection{}, false, chatops.Input{
			WorkspaceID: "T0SHARED", SigningSecret: strings.Repeat("ab", 16), BotToken: "xoxb-1111-PLAINTEXTBOT", Enabled: true,
		})
		if applyErr != nil {
			t.Fatal(applyErr)
		}
		c.TenantID, c.UpdatedBy, c.UpdatedAt = tenant, "admin@"+tenant, now
		if putErr := st.PutConnection(ctx, tenant, c); putErr != nil {
			t.Fatalf("put %s: %v", tenant, putErr)
		}
		return c
	}
	acme, globex := mk("acme"), mk("globex")

	// Own-only reads; the token lookup resolves each token to its own tenant.
	if l, listErr := st.Connections(ctx, "acme"); listErr != nil || len(l) != 1 || l[0].TenantID != "acme" {
		t.Fatalf("RLS LEAK in Connections: %+v (%v)", l, listErr)
	}
	if got, ok, lookErr := st.ConnectionByToken(ctx, globex.WebhookToken); lookErr != nil || !ok || got.TenantID != "globex" || got.BotToken != "xoxb-1111-PLAINTEXTBOT" {
		t.Fatalf("token lookup: %+v %v %v", got, ok, lookErr)
	}
	if _, ok, _ := st.GetConnection(ctx, "initech", chatops.Slack); ok {
		t.Fatal("RLS LEAK: a tenant with no connection saw one")
	}
	if gone, delErr := st.DeleteConnection(ctx, "initech", chatops.Slack); delErr != nil || gone {
		t.Fatalf("another tenant deleted a connection: %v %v", gone, delErr)
	}

	// Secrets reach the row only sealed.
	var rawSign, rawBot string
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT signing_secret, bot_token FROM chatops_connections WHERE tenant_id='acme'`).Scan(&rawSign, &rawBot)
	})
	if err != nil || strings.Contains(rawSign, strings.Repeat("ab", 16)) || strings.Contains(rawBot, "xoxb-") || !strings.HasPrefix(rawBot, "sealed:") {
		t.Fatalf("a secret reached the row unsealed: %q %q (%v)", rawSign, rawBot, err)
	}
	_ = acme // its token is exercised through Connections above

	// Codes and links: a code put in acme redeems in acme only.
	code := chatops.HashCode("acme", "ABCD-EFGH")
	if putErr := st.PutCode(ctx, "acme", chatops.LinkCode{CodeHash: code, Platform: chatops.Slack, WorkspaceID: "T0SHARED",
		ChatUserID: "U1", ChatName: "alice", ExpiresAt: now.Add(10 * time.Minute)}); putErr != nil {
		t.Fatal(putErr)
	}
	if _, redeemErr := st.RedeemCode(ctx, "globex", code, "bob", now); !errors.Is(redeemErr, chatops.ErrNotFound) {
		t.Fatalf("RLS LEAK: acme's code redeemed in globex: %v", redeemErr)
	}
	link, err := st.RedeemCode(ctx, "acme", code, "alice", now)
	if err != nil || link.Status != chatops.LinkPending || link.TenantID != "acme" {
		t.Fatalf("redeem: %+v %v", link, err)
	}
	if _, decErr := st.DecideLink(ctx, "globex", link.ID, "root-globex", true, now); !errors.Is(decErr, chatops.ErrNotFound) {
		t.Fatalf("RLS LEAK: globex decided acme's link: %v", decErr)
	}
	if _, decErr := st.DecideLink(ctx, "acme", link.ID, "alice", true, now); !errors.Is(decErr, chatops.ErrSelf) {
		t.Fatalf("self-approval must be refused: %v", decErr)
	}
	approved, err := st.DecideLink(ctx, "acme", link.ID, "carol", true, now)
	if err != nil || approved.Status != chatops.LinkApproved || approved.DecidedBy != "carol" {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	if l, _, lookErr := st.ActiveLink(ctx, "acme", chatops.Slack, "T0SHARED", "U1"); lookErr != nil || l.UserID != "alice" {
		t.Fatalf("active link: %+v %v", l, lookErr)
	}
	if _, ok, _ := st.ActiveLink(ctx, "globex", chatops.Slack, "T0SHARED", "U1"); ok {
		t.Fatal("RLS LEAK: the same chat account in another tenant resolved acme's link")
	}
	if l, listErr := st.Links(ctx, "globex"); listErr != nil || len(l) != 0 {
		t.Fatalf("RLS LEAK in Links: %+v (%v)", l, listErr)
	}

	// The policy refuses a forged owner inside a scoped transaction (42501),
	// and the CHECK constraints hold below the API (23514).
	var pgErr *pgconn.PgError
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO chatops_links (tenant_id, id, platform, workspace_id, chat_user_id, user_id, status)
		    VALUES ('globex', '99999999-9999-4999-8999-999999999999', 'slack', 'T0SHARED', 'U9', 'x', 'approved')`)
		return execErr
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO chatops_links (tenant_id, id, platform, workspace_id, chat_user_id, user_id, status)
		    VALUES ('acme', '88888888-8888-4888-8888-888888888888', 'slack', 'T0SHARED', 'U8', 'x', 'superuser')`)
		return execErr
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("an unknown link status must be refused by the CHECK, got %v", err)
	}
	// One live link per chat account, below the API (23505).
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO chatops_links (tenant_id, id, platform, workspace_id, chat_user_id, user_id, status)
		    VALUES ('acme', '77777777-7777-4777-8777-777777777777', 'slack', 'T0SHARED', 'U1', 'mallory', 'pending')`)
		return execErr
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("a second live link for one chat account must be refused, got %v", err)
	}
}
