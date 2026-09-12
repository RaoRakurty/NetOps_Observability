// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// notify_g10_test.go — G10 (Project 2 integrations residue): Microsoft Teams and
// Amazon SNS were the last two notification destinations wired straight from env
// in main.go. They had no admin surface, no severity gate (every alert at every
// severity went out) and no way to change them without a restart. This file is
// the proof that they now behave exactly like the other managed channels:
//
//   - config round-trip with the webhook masked (write-only, boolean-only read)
//   - validation refuses an http:// webhook and a malformed topic ARN with 400
//   - the AWS credential never enters the stored config or any response
//   - the legacy env wiring migrates ONCE and is then latched
//   - the admin endpoints are platform-OWNER only (CLAUDE.md §3a rule 3):
//     notification channels are platform-GLOBAL plumbing, so a tenant/org admin
//     — who holds administration:admin inside its own scope — gets 403.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netops/backend/internal/session"
	"netops/backend/internal/users"
	"netops/backend/notify"
	"time"
)

// newG10NotifyServer is newNotifyCfgServer over the real router.
//
// The four Teams/SNS admin routes are registered by main.go's routes() as of
// the P3-EMIT wiring pass (2026-09-02); the local shim that mounted them while
// main.go was owned by another change is GONE — leaving it would have
// double-registered the patterns, which Go's ServeMux panics on.
func newG10NotifyServer(t *testing.T) (*httptest.Server, *server) {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	us, err := users.NewFileStore(dir+"/users.json", userDeps())
	must(err)
	rs, err := newRoleStore(dir + "/roles.json")
	must(err)
	ts, err := newTenantStore(dir + "/tenants.json")
	must(err)
	rf, err := session.NewRefreshStore(dir+"/refresh.json", time.Hour, platformKV{})
	must(err)
	must(us.SeedAdmin("admin", "Passw0rd!2345"))
	s := &server{users: us, roles: rs, tenants: ts, refresh: rf, startedAt: time.Now().UTC()}
	s.notifyCfg = newNotifyConfigStore(dir+"/notify.json", s)
	mux := http.NewServeMux()
	s.routes(mux)
	srv := httptest.NewServer(s.withAuth(mux))
	t.Cleanup(srv.Close)
	return srv, s
}

// TestNotifyTeamsConfigRoundTripMasksTheWebhook: the Teams Incoming Webhook URL
// embeds a bearer token, so the WHOLE URL is the secret — same treatment Slack
// gets. It is write-only: stored, never echoed, preserved when omitted.
func TestNotifyTeamsConfigRoundTripMasksTheWebhook(t *testing.T) {
	srv, s := newG10NotifyServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token
	const secret = "https://example.webhook.office.com/webhookb2/TEAMS-BEARER-SECRET/IncomingWebhook/x/y"

	st, b := do(t, srv, "PUT", "/api/notify/teams", tok, map[string]any{"enabled": true, "webhook_url": secret})
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	if strings.Contains(string(b), "TEAMS-BEARER-SECRET") {
		t.Fatalf("PUT response leaked the webhook: %s", b)
	}
	if !strings.Contains(string(b), `"webhook_set":true`) || !strings.Contains(string(b), `"min_severity":"warning"`) {
		t.Fatalf("unexpected public view: %s", b)
	}
	if s.notifyCfg.cfg.Teams.WebhookURL != secret {
		t.Fatalf("webhook not stored: %q", s.notifyCfg.cfg.Teams.WebhookURL)
	}

	// GET redacts identically.
	st, b = do(t, srv, "GET", "/api/notify/teams", tok, nil)
	if st != 200 || strings.Contains(string(b), "TEAMS-BEARER-SECRET") || !strings.Contains(string(b), `"webhook_set":true`) {
		t.Fatalf("GET redaction failed: %d %s", st, b)
	}

	// A PUT that omits the webhook preserves it (write-only semantics).
	if st, b := do(t, srv, "PUT", "/api/notify/teams", tok, map[string]any{"enabled": true, "min_severity": "error"}); st != 200 {
		t.Fatalf("re-PUT: %d %s", st, b)
	}
	if s.notifyCfg.cfg.Teams.WebhookURL != secret {
		t.Fatalf("write-only webhook not preserved on omitted PUT: %q", s.notifyCfg.cfg.Teams.WebhookURL)
	}
	if s.notifyCfg.cfg.Teams.MinSeverity != "error" {
		t.Fatalf("min_severity not updated: %q", s.notifyCfg.cfg.Teams.MinSeverity)
	}

	// It survives a reload from disk (encrypted at rest via mapNotify).
	reloaded := newNotifyConfigStore(s.notifyCfg.path, nil)
	if reloaded.cfg.Teams.WebhookURL != secret || !reloaded.cfg.Teams.Enabled {
		t.Fatalf("teams config did not round-trip through the store: %+v", reloaded.cfg.Teams)
	}

	// Method posture matches the other channels.
	if st, _ := do(t, srv, "DELETE", "/api/notify/teams", tok, nil); st != 405 {
		t.Fatalf("DELETE = %d, want 405", st)
	}
}

// TestNotifyTeamsRejectsAPlaintextWebhook: http:// would put the bearer token
// and every alert body on the wire in clear text — 400 at the boundary.
func TestNotifyTeamsRejectsAPlaintextWebhook(t *testing.T) {
	srv, s := newG10NotifyServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "PUT", "/api/notify/teams", tok, map[string]any{"enabled": true, "webhook_url": "http://example.webhook.office.com/hook"})
	if st != 400 {
		t.Fatalf("http:// webhook = %d, want 400 (%s)", st, b)
	}
	if !strings.Contains(string(b), "https") {
		t.Errorf("400 body should say why: %s", b)
	}
	if s.notifyCfg.cfg.Teams.WebhookURL != "" {
		t.Fatalf("a rejected PUT must store nothing, got %q", s.notifyCfg.cfg.Teams.WebhookURL)
	}
	// Enabling with no webhook anywhere is equally refused — a channel that can
	// never fire must not report itself as enabled.
	if st, _ := do(t, srv, "PUT", "/api/notify/teams", tok, map[string]any{"enabled": true}); st != 400 {
		t.Fatalf("enable-with-no-webhook = %d, want 400", st)
	}
	// Invalid severity is still refused by the shared handler.
	if st, _ := do(t, srv, "PUT", "/api/notify/teams", tok, map[string]any{"min_severity": "shrug"}); st != 400 {
		t.Fatalf("invalid min_severity = %d, want 400", st)
	}
}

// TestNotifySNSConfigRoundTripKeepsCredentialsOutOfTheConfig: the AWS keys are
// deployment environment, never config. The API may say whether they are
// present; it must never carry a value.
func TestNotifySNSConfigRoundTripKeepsCredentialsOutOfTheConfig(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "AWS-SECRET-VALUE")
	srv, s := newG10NotifyServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "PUT", "/api/notify/sns", tok, map[string]any{
		"enabled": true, "topic_arn": "arn:aws:sns:us-east-1:123456789012:correlix-alerts",
		"phone_numbers": "+14155550123",
	})
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	for _, leak := range []string{"AWS-SECRET-VALUE", "AKIDEXAMPLE"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("SNS response leaked the AWS credential (%s): %s", leak, b)
		}
	}
	var view map[string]any
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatal(err)
	}
	if view["credentials_set"] != true {
		t.Errorf("credentials_set should report the env credential is present: %s", b)
	}
	if view["min_severity"] != "critical" {
		t.Errorf("sns default floor should be critical: %s", b)
	}
	if view["scope"] != "all" {
		t.Errorf("sns scope should normalize to all: %s", b)
	}
	// Region is derived from the ARN when omitted.
	if view["region"] != "us-east-1" {
		t.Errorf("region should be derived from the topic ARN: %s", b)
	}

	// The stored config must not contain a credential field at all — check the
	// serialized form, which is what lands on disk.
	raw, err := json.Marshal(s.notifyCfg.cfg.SNS)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"secret", "access_key", "AKIDEXAMPLE", "AWS-SECRET-VALUE"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(banned)) {
			t.Fatalf("SNS config JSON must never carry credentials (%q): %s", banned, raw)
		}
	}
}

func TestNotifySNSRejectsAMalformedTopicARN(t *testing.T) {
	srv, s := newG10NotifyServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token

	bad := []map[string]any{
		{"enabled": true, "topic_arn": "not-an-arn"},
		{"enabled": true, "topic_arn": "arn:aws:sqs:us-east-1:123456789012:t"},
		{"enabled": true, "topic_arn": "arn:aws:sns:us-east-1:12345:t"},
		// The region is interpolated into the SNS endpoint host — a region that
		// smuggles a host must never be stored.
		{"enabled": true, "region": "us-east-1/@evil.example.com", "phone_numbers": "+14155550123"},
		{"enabled": true, "region": "us-west-2", "topic_arn": "arn:aws:sns:us-east-1:123456789012:t"},
		{"enabled": true, "region": "us-east-1", "phone_numbers": "555-0123"},
		{"enabled": true, "region": "us-east-1"}, // enabled with nowhere to send
	}
	for _, in := range bad {
		st, b := do(t, srv, "PUT", "/api/notify/sns", tok, in)
		if st != 400 {
			t.Errorf("PUT %v = %d, want 400 (%s)", in, st, b)
		}
	}
	if s.notifyCfg.cfg.SNS.Enabled || s.notifyCfg.cfg.SNS.TopicARN != "" {
		t.Fatalf("rejected PUTs must store nothing: %+v", s.notifyCfg.cfg.SNS)
	}
}

// TestNotifyG10TestHooksRequireConfiguration: the delivery-test hook exists for
// both new channels and refuses clearly when the channel is not usable yet.
func TestNotifyG10TestHooksRequireConfiguration(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	srv, _ := newG10NotifyServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token

	if st, b := do(t, srv, "POST", "/api/notify/teams/test", tok, nil); st != 400 || !strings.Contains(string(b), "webhook") {
		t.Errorf("teams test with no webhook = %d %s, want 400", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/notify/sns/test", tok, nil); st != 400 || !strings.Contains(string(b), "topic ARN") {
		t.Errorf("sns test with no destination = %d %s, want 400", st, b)
	}

	// Configure SNS but leave the AWS credential absent: the hook must say the
	// credential is missing rather than attempt an unsigned call.
	if st, b := do(t, srv, "PUT", "/api/notify/sns", tok, map[string]any{
		"topic_arn": "arn:aws:sns:us-east-1:123456789012:t"}); st != 200 {
		t.Fatalf("PUT sns: %d %s", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/notify/sns/test", tok, nil); st != 400 || !strings.Contains(string(b), "AWS_ACCESS_KEY_ID") {
		t.Errorf("sns test with no credential = %d %s, want 400 naming the env var", st, b)
	}
}

// ---- env migration ----------------------------------------------------------

// TestMigrateTeamsFromEnvOnceAndOnlyOnce is the migration contract: an existing
// TEAMS_WEBHOOK_URL deployment is carried across exactly once, and the latch
// then keeps the deprecated env from overruling a later admin decision.
func TestMigrateTeamsFromEnvOnceAndOnlyOnce(t *testing.T) {
	t.Setenv("FEATURE_TEAMS_NOTIFICATIONS", "true")
	t.Setenv("TEAMS_WEBHOOK_URL", "https://example.webhook.office.com/webhookb2/ENVSEED/IncomingWebhook/x/y")
	s := newTestNotifyStore(t, t.TempDir()+"/notify.json")

	if !s.migrateEnvChannels() {
		t.Fatal("first migration must report a change")
	}
	if !s.cfg.Teams.Enabled || !strings.Contains(s.cfg.Teams.WebhookURL, "ENVSEED") {
		t.Fatalf("teams not migrated: %+v", s.cfg.Teams)
	}
	if s.cfg.Teams.MinSeverity != "warning" {
		t.Errorf("migrated teams floor = %q, want warning", s.cfg.Teams.MinSeverity)
	}
	if !s.cfg.IsEnvSeeded("teams") {
		t.Fatal("migration must latch")
	}

	// Second call: nothing to do.
	if s.migrateEnvChannels() {
		t.Fatal("migration must be idempotent — a second run must report no change")
	}

	// The operator then turns Teams off in the admin UI. The env var is still
	// in .env; it must NOT resurrect the channel at the next boot.
	s.cfg.Teams.Enabled = false
	if s.migrateEnvChannels() {
		t.Fatal("the latch must stop the env from re-seeding")
	}
	if s.cfg.Teams.Enabled {
		t.Fatal("a disabled channel must not be re-enabled by the deprecated env path")
	}
}

func TestMigrateTeamsFromEnvRefusesAPlaintextWebhook(t *testing.T) {
	t.Setenv("FEATURE_TEAMS_NOTIFICATIONS", "true")
	t.Setenv("TEAMS_WEBHOOK_URL", "http://example.webhook.office.com/hook")
	s := newTestNotifyStore(t, t.TempDir()+"/notify.json")

	if s.migrateEnvChannels() {
		t.Fatal("a plaintext env webhook must not be migrated")
	}
	if s.cfg.Teams.WebhookURL != "" {
		t.Fatalf("nothing should be stored: %q", s.cfg.Teams.WebhookURL)
	}
	// Deliberately NOT latched: the operator can fix the env and be migrated.
	if s.cfg.IsEnvSeeded("teams") {
		t.Fatal("a failed migration must stay loud, not latch")
	}
}

// TestMigrateSNSFromEnvPreservesLegacyReach: the env channel had no gate and no
// scope filter, so it received everything. The migration keeps the destination
// behavior operators actually have (scope=all) rather than silently narrowing
// their paging on upgrade, while adding the critical floor.
func TestMigrateSNSFromEnvPreservesLegacyReach(t *testing.T) {
	t.Setenv("FEATURE_SNS_NOTIFICATIONS", "true")
	t.Setenv("SNS_TOPIC_ARN", "arn:aws:sns:eu-west-2:123456789012:correlix")
	t.Setenv("SNS_PHONE_NUMBERS", "+442071838750")
	t.Setenv("AWS_REGION", "")
	s := newTestNotifyStore(t, t.TempDir()+"/notify.json")

	if !s.migrateEnvChannels() {
		t.Fatal("first migration must report a change")
	}
	got := s.cfg.SNS
	if !got.Enabled || got.TopicARN != "arn:aws:sns:eu-west-2:123456789012:correlix" || got.PhoneNumbers != "+442071838750" {
		t.Fatalf("sns not migrated: %+v", got)
	}
	if got.Region != "eu-west-2" {
		t.Errorf("region should be derived from the ARN, got %q", got.Region)
	}
	if got.MinSeverity != "critical" || notify.NormalizeSNSScope(got.Scope) != "all" {
		t.Errorf("migrated sns posture = floor %q scope %q, want critical/all", got.MinSeverity, got.Scope)
	}
	if s.migrateEnvChannels() {
		t.Fatal("migration must be idempotent")
	}
}

func TestMigrateSNSFromEnvRefusesAMalformedARN(t *testing.T) {
	t.Setenv("FEATURE_SNS_NOTIFICATIONS", "true")
	t.Setenv("SNS_TOPIC_ARN", "arn:aws:sqs:us-east-1:123456789012:t")
	t.Setenv("SNS_PHONE_NUMBERS", "")
	s := newTestNotifyStore(t, t.TempDir()+"/notify.json")
	if s.migrateEnvChannels() {
		t.Fatal("a malformed env ARN must not be migrated")
	}
	if s.cfg.SNS.Enabled {
		t.Fatalf("nothing should be enabled: %+v", s.cfg.SNS)
	}
}

// TestMigrateEnvChannelsPersistsTheLatch: the "once" guarantee has to survive a
// restart, which means the latch has to be written to disk with the config.
func TestMigrateEnvChannelsPersistsTheLatch(t *testing.T) {
	t.Setenv("FEATURE_TEAMS_NOTIFICATIONS", "true")
	t.Setenv("TEAMS_WEBHOOK_URL", "https://example.webhook.office.com/webhookb2/PERSIST/IncomingWebhook/x/y")
	path := t.TempDir() + "/notify.json"

	// First boot: no stored config → first-run seed path.
	first := newNotifyConfigStore(path, nil)
	if !first.cfg.Teams.Enabled || !first.cfg.IsEnvSeeded("teams") {
		t.Fatalf("first boot did not migrate: %+v", first.cfg.Teams)
	}

	// Operator disables Teams and it is saved.
	first.cfg.Teams.Enabled = false
	if err := first.save(); err != nil {
		t.Fatal(err)
	}

	// Second boot: stored config exists → upgrade path. The env is still set and
	// must be ignored.
	second := newNotifyConfigStore(path, nil)
	if second.cfg.Teams.Enabled {
		t.Fatal("the persisted latch must survive a restart — the env re-enabled a disabled channel")
	}
	if !second.cfg.IsEnvSeeded("teams") {
		t.Fatal("latch did not persist")
	}
}

// TestMigrateEnvChannelsRunsOnTheUpgradePath: a deployment that already has a
// stored config (so the first-run seed never fires) still gets its env-only
// Teams/SNS channels adopted.
func TestMigrateEnvChannelsRunsOnTheUpgradePath(t *testing.T) {
	path := t.TempDir() + "/notify.json"
	pre := newTestNotifyStore(t, path)
	pre.cfg.Slack.Enabled = true
	pre.cfg.Slack.WebhookURL = "https://hooks.slack.example/T/B/C"
	if err := pre.save(); err != nil {
		t.Fatal(err)
	}
	if pre.cfg.IsEnvSeeded("teams") {
		t.Fatal("precondition: nothing migrated yet")
	}

	t.Setenv("FEATURE_TEAMS_NOTIFICATIONS", "true")
	t.Setenv("TEAMS_WEBHOOK_URL", "https://example.webhook.office.com/webhookb2/UPGRADE/IncomingWebhook/x/y")
	upgraded := newNotifyConfigStore(path, nil)
	if !upgraded.cfg.Teams.Enabled || !strings.Contains(upgraded.cfg.Teams.WebhookURL, "UPGRADE") {
		t.Fatalf("upgrade path did not migrate teams: %+v", upgraded.cfg.Teams)
	}
	if !upgraded.cfg.Slack.Enabled {
		t.Fatal("migration must not disturb existing channels")
	}
}

// ---- §3a rule 3: platform-GLOBAL plumbing is owner-only ---------------------

// TestNotifyG10ChannelsArePlatformOwnerOnly is the CLAUDE.md §3a rule 3 test.
// Notification channels are platform-GLOBAL plumbing, so the gate must be
// requirePlatformAdmin, not a scope-blind requireAdmin: an org/tenant admin
// holds full administration:admin inside its own scope and would otherwise be
// able to read the operator's channel inventory and repoint the platform's
// paging destination.
func TestNotifyG10ChannelsArePlatformOwnerOnly(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token // platform owner

	if st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "orgboss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": "acme-prod"}); st != 201 {
		t.Fatal("create org-admin")
	}
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "tadmin", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod"}); st != 201 {
		t.Fatal("create tenant super-admin")
	}
	orgBoss := login(t, srv, "orgboss", "Passw0rd!2345").Token
	tenantAdmin := login(t, srv, "tadmin", "Passw0rd!2345").Token

	// The G10 endpoints are part of the real router now (main.go routes()).
	mux := http.NewServeMux()
	s.routes(mux)
	g10 := httptest.NewServer(s.withAuth(mux))
	defer g10.Close()

	for _, ep := range []string{"/api/notify/teams", "/api/notify/sns"} {
		for _, who := range []struct{ name, token string }{{"org-admin", orgBoss}, {"tenant-admin", tenantAdmin}} {
			if st, b := do(t, g10, "GET", ep, who.token, nil); st != 403 {
				t.Errorf("%s GET %s = %d, want 403 (platform-owner only): %s", who.name, ep, st, b)
			}
			if st, b := do(t, g10, "PUT", ep, who.token, map[string]any{"enabled": true}); st != 403 {
				t.Errorf("%s PUT %s = %d, want 403 (platform-owner only): %s", who.name, ep, st, b)
			}
		}
	}
	// The delivery-test hooks are the same platform surface — they SEND from the
	// operator's channel, so they must be gated identically.
	for _, ep := range []string{"/api/notify/teams/test", "/api/notify/sns/test"} {
		for _, who := range []struct{ name, token string }{{"org-admin", orgBoss}, {"tenant-admin", tenantAdmin}} {
			if st, b := do(t, g10, "POST", ep, who.token, nil); st != 403 {
				t.Errorf("%s POST %s = %d, want 403 (platform-owner only): %s", who.name, ep, st, b)
			}
		}
	}
	// An unauthenticated caller never gets in either.
	for _, ep := range []string{"/api/notify/teams", "/api/notify/sns"} {
		if st, _ := do(t, g10, "GET", ep, "", nil); st != 401 {
			t.Errorf("anonymous GET %s = %d, want 401", ep, st)
		}
	}
}

// TestSNSCredentialsComeOnlyFromTheEnvironment pins the credential source: the
// config store has no field for it, so the ONLY way a key reaches the signer is
// snsCredentials() reading the process environment.
func TestSNSCredentialsComeOnlyFromTheEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "  AKIDEXAMPLE  ")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sk")
	ak, sk, ok := snsCredentials()
	if !ok || ak != "AKIDEXAMPLE" || sk != "sk" {
		t.Fatalf("snsCredentials() = %q,%q,%v", ak, sk, ok)
	}
	// A half-present credential must fail closed rather than sign with a blank.
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, _, ok := snsCredentials(); ok {
		t.Fatal("a partial AWS credential must not be reported as usable")
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		t.Fatal("test env not applied")
	}
}
