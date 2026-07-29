package main

import (
	"context"
	"netops/backend/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/notify"
)

// TestConfigSecretsRoundTrip proves each config type's secret fields survive a
// seal→open round-trip and that sealing actually transforms them (active Vault).
func TestConfigSecretsRoundTrip(t *testing.T) {
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	notif := notify.ChannelConfig{}
	notif.SMTP.Pass = "smtp-pw"
	notif.Twilio.AuthToken = "twilio-tok"
	notif.Ntfy.Token = "ntfy-tok"
	notif.Slack.WebhookURL = "https://hooks.slack.com/services/SECRET"
	notif.PagerDuty.RoutingKey = "pd-routing"
	sealed, err := mapNotify(notif, sealFn(v))
	if err != nil {
		t.Fatalf("seal notify: %v", err)
	}
	if sealed.SMTP.Pass == notif.SMTP.Pass || !strings.HasPrefix(sealed.Slack.WebhookURL, vault.VersionPrefix) {
		t.Fatalf("notify secrets not encrypted: %+v", sealed)
	}
	opened, err := mapNotify(sealed, openFn(v))
	if err != nil || opened != notif {
		t.Fatalf("notify round-trip: %+v err=%v", opened, err)
	}

	// Single-field configs.
	oc, _ := mapOIDC(oidcConfig{ClientSecret: "oidc-sec"}, sealFn(v))
	if got, _ := mapOIDC(oc, openFn(v)); got.ClientSecret != "oidc-sec" || oc.ClientSecret == "oidc-sec" {
		t.Fatalf("oidc round-trip failed: sealed=%q opened=%q", oc.ClientSecret, got.ClientSecret)
	}
	lc, _ := mapLDAP(ldapConfig{BindPassword: "ldap-pw"}, sealFn(v))
	if got, _ := mapLDAP(lc, openFn(v)); got.BindPassword != "ldap-pw" || lc.BindPassword == "ldap-pw" {
		t.Fatalf("ldap round-trip failed")
	}
	tc, _ := mapTACACS(tacacsConfig{Secret: "tac-sec"}, sealFn(v))
	if got, _ := mapTACACS(tc, openFn(v)); got.Secret != "tac-sec" || tc.Secret == "tac-sec" {
		t.Fatalf("tacacs round-trip failed")
	}
}

// TestNotifyConfigEncryptedAtRest proves the notify store persists ciphertext and
// decrypts it on reopen (the full store wiring, not just the map helpers).
func TestNotifyConfigEncryptedAtRest(t *testing.T) {
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	path := filepath.Join(t.TempDir(), "notify.json")
	srv := &server{vault: v} // nil notifier → apply() is a no-op

	st := newNotifyConfigStore(path, srv)
	st.cfg.SMTP.Pass = "super-smtp-secret"
	st.cfg.Slack.WebhookURL = "https://hooks.slack.com/services/TOKEN123"
	st.save()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), "super-smtp-secret") || strings.Contains(string(raw), "TOKEN123") {
		t.Fatalf("notify secret stored in plaintext:\n%s", raw)
	}
	// Reopen → decrypts back to plaintext in memory.
	st2 := newNotifyConfigStore(path, srv)
	if st2.cfg.SMTP.Pass != "super-smtp-secret" || st2.cfg.Slack.WebhookURL != "https://hooks.slack.com/services/TOKEN123" {
		t.Fatalf("decrypt-on-reload mismatch: pass=%q url=%q", st2.cfg.SMTP.Pass, st2.cfg.Slack.WebhookURL)
	}
}
