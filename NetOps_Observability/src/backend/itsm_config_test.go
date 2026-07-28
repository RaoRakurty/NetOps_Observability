package main

import (
	"netops/backend/internal/platformdb"
	"path/filepath"
	"testing"

	"netops/backend/notify"
)

func newTestITSMStore(t *testing.T) (*itsmConfigStore, *server) {
	t.Helper()
	srv := &server{notifier: notify.NewDispatcher()}
	st := &itsmConfigStore{
		path: filepath.Join(t.TempDir(), "itsm.json"), srv: srv,
		cfgs: map[string]itsmConfig{}, live: map[string]*itsmLive{},
	}
	srv.itsmCfg = st
	return st, srv
}

func TestValidateITSM(t *testing.T) {
	cases := []struct {
		name string
		cfg  itsmConfig
		ok   bool
	}{
		{"sn enabled needs url", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true}}, false},
		{"sn url must be http", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "ftp://x"}}, false},
		{"sn ok", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com"}}, true},
		{"jira enabled needs base+project", itsmConfig{Jira: jiraConfig{Enabled: true, BaseURL: "https://x.atlassian.net"}}, false},
		{"jira ok", itsmConfig{Jira: jiraConfig{Enabled: true, BaseURL: "https://x.atlassian.net", ProjectKey: "NOC"}}, true},
		{"both disabled ok", itsmConfig{}, true},
	}
	for _, c := range cases {
		err := validateITSM(c.cfg)
		if (err == nil) != c.ok {
			t.Errorf("%s: validate ok=%v, got err=%v", c.name, c.ok, err)
		}
	}
}

func TestNormalizeJiraServiceNow(t *testing.T) {
	sn := normalizeServiceNow(serviceNowConfig{InstanceURL: " https://dev.service-now.com/ ", MinSeverity: ""})
	if sn.InstanceURL != "https://dev.service-now.com" {
		t.Errorf("instance url not trimmed: %q", sn.InstanceURL)
	}
	if sn.MinSeverity != "critical" {
		t.Errorf("min severity default = %q, want critical", sn.MinSeverity)
	}
	jr := normalizeJira(jiraConfig{BaseURL: "https://x.atlassian.net/", ProjectKey: "noc"})
	if jr.ProjectKey != "NOC" {
		t.Errorf("project key not upper: %q", jr.ProjectKey)
	}
}

func TestITSMApplyAndPublic(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	st, srv := newTestITSMStore(t)

	// Enable ServiceNow for the global tenant → live connector resolvable.
	if err := st.set("", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc", Password: "secret"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if srv.serviceNow() == nil {
		t.Fatal("servicenow connector not live after enable")
	}

	// public() must redact the password but advertise that one is stored.
	pub := st.public("")["servicenow"].(map[string]any)
	if _, leaked := pub["password"]; leaked {
		t.Error("public() leaked the password")
	}
	if pub["has_password"] != true || pub["configured"] != true {
		t.Errorf("public() flags wrong: %+v", pub)
	}

	// Blank password on update KEEPS the stored secret (write-only field).
	if err := st.set("", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc2", Password: ""}}); err != nil {
		t.Fatalf("set2: %v", err)
	}
	if st.cfgs[""].ServiceNow.Password != "secret" {
		t.Errorf("blanked password not preserved, got %q", st.cfgs[""].ServiceNow.Password)
	}

	// Disable → connector no longer resolvable.
	if err := st.set("", itsmConfig{ServiceNow: serviceNowConfig{Enabled: false}}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if srv.serviceNow() != nil {
		t.Error("servicenow still live after disable")
	}
}

// TestITSMPerTenantIsolation proves a tenant's connector resolves ONLY for that
// tenant — never another tenant, and never the global connector (and vice versa).
func TestITSMPerTenantIsolation(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	st, srv := newTestITSMStore(t)

	// Acme configures its own ServiceNow; Globex configures its own Jira.
	if err := st.set("acme", itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://acme.service-now.com", User: "a", Password: "pa"}}); err != nil {
		t.Fatalf("set acme: %v", err)
	}
	if err := st.set("globex", itsmConfig{Jira: jiraConfig{Enabled: true, BaseURL: "https://globex.atlassian.net", Email: "g@x", APIToken: "tg", ProjectKey: "OPS"}}); err != nil {
		t.Fatalf("set globex: %v", err)
	}

	if srv.serviceNowFor("acme") == nil {
		t.Error("acme ServiceNow not resolvable")
	}
	if srv.serviceNowFor("globex") != nil {
		t.Error("globex must NOT see a ServiceNow connector")
	}
	if srv.serviceNowFor("") != nil {
		t.Error("global must NOT see acme's connector")
	}
	if srv.jiraFor("globex") == nil {
		t.Error("globex Jira not resolvable")
	}
	if srv.jiraFor("acme") != nil {
		t.Error("acme must NOT see globex's Jira")
	}

	// public() is per-tenant: acme sees its own config, globex sees none for SN.
	if st.public("acme")["servicenow"].(map[string]any)["configured"] != true {
		t.Error("acme public servicenow should be configured")
	}
	if st.public("globex")["servicenow"].(map[string]any)["configured"] != false {
		t.Error("globex public servicenow should be unconfigured")
	}
}

// TestITSMLegacyMigration proves a pre-per-tenant single-object config file is
// migrated under the global "" key on load.
func TestITSMLegacyMigration(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	_, srv := newTestITSMStore(t)
	path := filepath.Join(t.TempDir(), "legacy.json")
	// Legacy format: a bare itsmConfig object (no version envelope).
	legacy := `{"servicenow":{"enabled":true,"instance_url":"https://legacy.service-now.com","user":"u","password":"p","min_severity":"critical"},"jira":{"enabled":false}}`
	if err := platformdb.Save(path, []byte(legacy)); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	st := newITSMConfigStore(srv, path)
	if st.serviceNowFor("") == nil {
		t.Fatal("legacy global ServiceNow not migrated/live")
	}
	if st.cfgs[""].ServiceNow.InstanceURL != "https://legacy.service-now.com" {
		t.Errorf("legacy instance url lost: %q", st.cfgs[""].ServiceNow.InstanceURL)
	}
}
