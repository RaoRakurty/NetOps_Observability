package ticketing

import (
	"netops/backend/internal/platformdb"
	"os"
	"path/filepath"
	"testing"
)

func newTestITSMStore(t *testing.T) *ITSMConfigStore {
	t.Helper()
	return &ITSMConfigStore{
		path: filepath.Join(t.TempDir(), "itsm.json"),
		cfgs: map[string]ITSMConfig{}, live: map[string]*itsmLive{},
		envDefault:      func() ITSMConfig { return ITSMConfig{} },
		stateFileFor:    func(system, tenant string) string { return filepath.Join(t.TempDir(), system+"_"+tenant+".json") },
		legacyAlertITSM: func() bool { return os.Getenv("FEATURE_LEGACY_ALERT_ITSM") == "true" },
	}
}

func TestValidateITSM(t *testing.T) {
	cases := []struct {
		name string
		cfg  ITSMConfig
		ok   bool
	}{
		{"sn enabled needs url", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true}}, false},
		{"sn url must be http", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "ftp://x"}}, false},
		{"sn ok", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com"}}, true},
		{"jira enabled needs base+project", ITSMConfig{Jira: JiraConfig{Enabled: true, BaseURL: "https://x.atlassian.net"}}, false},
		{"jira ok", ITSMConfig{Jira: JiraConfig{Enabled: true, BaseURL: "https://x.atlassian.net", ProjectKey: "NOC"}}, true},
		{"both disabled ok", ITSMConfig{}, true},
	}
	for _, c := range cases {
		err := ValidateITSM(c.cfg)
		if (err == nil) != c.ok {
			t.Errorf("%s: validate ok=%v, got err=%v", c.name, c.ok, err)
		}
	}
}

func TestNormalizeJiraServiceNow(t *testing.T) {
	sn := NormalizeServiceNow(ServiceNowConfig{InstanceURL: " https://dev.service-now.com/ ", MinSeverity: ""})
	if sn.InstanceURL != "https://dev.service-now.com" {
		t.Errorf("instance url not trimmed: %q", sn.InstanceURL)
	}
	if sn.MinSeverity != "critical" {
		t.Errorf("min severity default = %q, want critical", sn.MinSeverity)
	}
	jr := NormalizeJira(JiraConfig{BaseURL: "https://x.atlassian.net/", ProjectKey: "noc"})
	if jr.ProjectKey != "NOC" {
		t.Errorf("project key not upper: %q", jr.ProjectKey)
	}
}

func TestITSMApplyAndPublic(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	st := newTestITSMStore(t)

	// Enable ServiceNow for the global tenant → live connector resolvable.
	if err := st.Set("", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc", Password: "secret"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if st.ServiceNowFor("") == nil {
		t.Fatal("servicenow connector not live after enable")
	}

	// public() must redact the password but advertise that one is stored.
	pub := st.Public("")["servicenow"].(map[string]any)
	if _, leaked := pub["password"]; leaked {
		t.Error("public() leaked the password")
	}
	if pub["has_password"] != true || pub["configured"] != true {
		t.Errorf("public() flags wrong: %+v", pub)
	}

	// Blank password on update KEEPS the stored secret (write-only field).
	if err := st.Set("", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc2", Password: ""}}); err != nil {
		t.Fatalf("set2: %v", err)
	}
	if st.cfgs[""].ServiceNow.Password != "secret" {
		t.Errorf("blanked password not preserved, got %q", st.cfgs[""].ServiceNow.Password)
	}

	// Disable → connector no longer resolvable.
	if err := st.Set("", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: false}}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if st.ServiceNowFor("") != nil {
		t.Error("servicenow still live after disable")
	}
}

// TestITSMPerTenantIsolation proves a tenant's connector resolves ONLY for that
// tenant — never another tenant, and never the global connector (and vice versa).
func TestITSMPerTenantIsolation(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	st := newTestITSMStore(t)

	// Acme configures its own ServiceNow; Globex configures its own Jira.
	if err := st.Set("acme", ITSMConfig{ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "https://acme.service-now.com", User: "a", Password: "pa"}}); err != nil {
		t.Fatalf("set acme: %v", err)
	}
	if err := st.Set("globex", ITSMConfig{Jira: JiraConfig{Enabled: true, BaseURL: "https://globex.atlassian.net", Email: "g@x", APIToken: "tg", ProjectKey: "OPS"}}); err != nil {
		t.Fatalf("set globex: %v", err)
	}

	if st.ServiceNowFor("acme") == nil {
		t.Error("acme ServiceNow not resolvable")
	}
	if st.ServiceNowFor("globex") != nil {
		t.Error("globex must NOT see a ServiceNow connector")
	}
	if st.ServiceNowFor("") != nil {
		t.Error("global must NOT see acme's connector")
	}
	if st.JiraFor("globex") == nil {
		t.Error("globex Jira not resolvable")
	}
	if st.JiraFor("acme") != nil {
		t.Error("acme must NOT see globex's Jira")
	}

	// public() is per-tenant: acme sees its own config, globex sees none for SN.
	if st.Public("acme")["servicenow"].(map[string]any)["configured"] != true {
		t.Error("acme public servicenow should be configured")
	}
	if st.Public("globex")["servicenow"].(map[string]any)["configured"] != false {
		t.Error("globex public servicenow should be unconfigured")
	}
}

// TestITSMLegacyMigration proves a pre-per-tenant single-object config file is
// migrated under the global "" key on load.
func TestITSMLegacyMigration(t *testing.T) {
	t.Setenv("FEATURE_LEGACY_ALERT_ITSM", "true") // legacy lane coverage: deprecated path stays tested
	path := filepath.Join(t.TempDir(), "legacy.json")
	// Legacy format: a bare itsmConfig object (no version envelope).
	legacy := `{"servicenow":{"enabled":true,"instance_url":"https://legacy.service-now.com","user":"u","password":"p","min_severity":"critical"},"jira":{"enabled":false}}`
	if err := platformdb.Save(path, []byte(legacy)); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	st := NewITSMConfigStore(path,
		func() ITSMConfig { return ITSMConfig{} },
		func(system, tenant string) string { return filepath.Join(t.TempDir(), system+"_"+tenant+".json") },
		func() bool { return os.Getenv("FEATURE_LEGACY_ALERT_ITSM") == "true" })
	if st.ServiceNowFor("") == nil {
		t.Fatal("legacy global ServiceNow not migrated/live")
	}
	if st.cfgs[""].ServiceNow.InstanceURL != "https://legacy.service-now.com" {
		t.Errorf("legacy instance url lost: %q", st.cfgs[""].ServiceNow.InstanceURL)
	}
}
