// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenderEscapesAndLinksOnlyIntoCorrelix(t *testing.T) {
	a := Answer{
		Title: "BGP <down> & out",
		Text:  "Peer 10.0.0.1 is <script>alert(1)</script> down.",
		Next:  []string{"Check the provider ticket"},
		Citations: []Citation{
			{Label: "Incident | 7", Href: "/app/incidents/7"},
			{Label: "Elsewhere", Href: "https://evil.example.com/x"},
			{Label: "Protocol-relative", Href: "//evil.example.com/x"},
		},
		Disclaimers: []string{"Similar is not the same cause."},
	}
	s := Render(Slack, a, "https://correlix.example.com")
	if strings.Contains(s, "<script>") || !strings.Contains(s, "&lt;script&gt;") {
		t.Errorf("Slack control characters must be escaped: %q", s)
	}
	if !strings.Contains(s, "<https://correlix.example.com/app/incidents/7|Incident / 7>") {
		t.Errorf("a relative UI path links into Correlix: %q", s)
	}
	if strings.Contains(s, "evil.example.com") {
		t.Errorf("an absolute or protocol-relative href must never become a link: %q", s)
	}
	if !strings.Contains(s, "nothing has been run") {
		t.Error("next steps say nothing was run")
	}
	tm := Render(Teams, a, "https://correlix.example.com")
	if !strings.Contains(tm, "[Incident | 7](https://correlix.example.com/app/incidents/7)") || strings.Contains(tm, "evil.example.com") {
		t.Errorf("Teams markdown link: %q", tm)
	}
	if noBase := Render(Slack, a, ""); strings.Contains(noBase, "<https://") {
		t.Errorf("without a Correlix address citations are labels only: %q", noBase)
	}
	long := Render(Slack, Answer{Text: strings.Repeat("y", 10000)}, "")
	if len([]rune(long)) > slackMaxChars {
		t.Errorf("a reply must fit the platform: %d", len([]rune(long)))
	}
	if Render(Slack, Answer{}, "") == "" {
		t.Error("an empty answer still says something")
	}
}

func TestCodesAndHashes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NewCode()
		if err != nil || len(c) != 9 || c[4] != '-' || strings.ContainsAny(c, "01OIL") {
			t.Fatalf("code %q %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Error("codes repeat too often")
	}
	if HashCode(tenantA, "ABCD-EFGH") != HashCode(tenantA, " abcd efgh ") {
		t.Error("a typed code is normalised (case, spaces, dash)")
	}
	if HashCode(tenantA, "ABCD-EFGH") == HashCode(tenantB, "ABCD-EFGH") {
		t.Error("the hash is bound to the tenant")
	}
}

func TestStoreCodeLifecycle(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	put := func(code, user string, exp time.Time) {
		if err := m.PutCode(ctx, tenantA, LinkCode{CodeHash: HashCode(tenantA, code), Platform: Slack, WorkspaceID: "T0", ChatUserID: user, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	put("AAAA-AAAA", "U1", now.Add(time.Minute))
	put("BBBB-BBBB", "U1", now.Add(time.Minute)) // replaces the first
	if _, err := m.RedeemCode(ctx, tenantA, HashCode(tenantA, "AAAA-AAAA"), "alice", now); !errors.Is(err, ErrNotFound) {
		t.Error("a replaced code must not redeem")
	}
	put("CCCC-CCCC", "U2", now.Add(-time.Second))
	if _, err := m.RedeemCode(ctx, tenantA, HashCode(tenantA, "CCCC-CCCC"), "alice", now); !errors.Is(err, ErrNotFound) {
		t.Error("an expired code must not redeem")
	}
	l, err := m.RedeemCode(ctx, tenantA, HashCode(tenantA, "BBBB-BBBB"), "alice", now)
	if err != nil || l.Status != LinkPending || l.UserID != "alice" {
		t.Fatalf("redeem: %+v %v", l, err)
	}
	if _, err := m.RedeemCode(ctx, tenantA, HashCode(tenantA, "BBBB-BBBB"), "alice", now); !errors.Is(err, ErrNotFound) {
		t.Error("a code is spent once")
	}
	put("DDDD-DDDD", "U1", now.Add(time.Minute))
	if _, err := m.RedeemCode(ctx, tenantA, HashCode(tenantA, "DDDD-DDDD"), "mallory", now); !errors.Is(err, ErrLinked) {
		t.Error("a chat account with a live link cannot be linked again")
	}
	if _, err := m.DecideLink(ctx, tenantB, l.ID, "root-b", true, now); !errors.Is(err, ErrNotFound) {
		t.Error("another tenant cannot decide the link")
	}
	if _, err := m.DecideLink(ctx, tenantA, l.ID, "alice", true, now); !errors.Is(err, ErrSelf) {
		t.Error("the linked user cannot approve their own link")
	}
	if l2, err := m.DecideLink(ctx, tenantA, l.ID, "carol", false, now); err != nil || l2.Status != LinkRevoked {
		t.Fatalf("revoke: %+v %v", l2, err)
	}
	if _, active, _ := m.ActiveLink(ctx, tenantA, Slack, "T0", "U1"); active {
		t.Error("a revoked link is not live")
	}
}

func TestApplyTeamsValidation(t *testing.T) {
	good := Input{WorkspaceID: "72f988bf-86f1-41af-91ab-2d7cd011db47", AppID: "11111111-2222-3333-4444-555555555555", AppPassword: "longenough"}
	c, err := Apply(Teams, Connection{}, false, good)
	if err != nil || c.WebhookToken == "" || c.ChannelReplies != RepliesPrivate {
		t.Fatalf("apply: %+v %v", c, err)
	}
	tok := c.WebhookToken
	again, err := Apply(Teams, c, true, Input{WorkspaceID: good.WorkspaceID, AppID: good.AppID})
	if err != nil || again.WebhookToken != tok || again.AppPassword != "longenough" {
		t.Errorf("an update keeps the token and the stored password: %+v %v", again, err)
	}
	rot, _ := Apply(Teams, c, true, Input{WorkspaceID: good.WorkspaceID, AppID: good.AppID, RotateToken: true})
	if rot.WebhookToken == tok {
		t.Error("rotate_token mints a new inbound address")
	}
	for _, in := range []Input{
		{WorkspaceID: "not-a-guid", AppID: good.AppID, AppPassword: "longenough"},
		{WorkspaceID: good.WorkspaceID, AppID: "x", AppPassword: "longenough"},
		{WorkspaceID: good.WorkspaceID, AppID: good.AppID, AppPassword: "short"},
		{WorkspaceID: good.WorkspaceID, AppID: good.AppID, AppPassword: "longenough", BotToken: "xoxb-1111-AAAAAAAAAA"},
		{WorkspaceID: good.WorkspaceID, AppID: good.AppID, AppPassword: "longenough", ChannelReplies: "everyone"},
	} {
		if _, err := Apply(Teams, Connection{}, false, in); err == nil {
			t.Errorf("want a validation error for %+v", in)
		}
	}
}
