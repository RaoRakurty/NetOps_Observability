package main

import (
	"path/filepath"
	"testing"

	"netops/backend/notify"
)

func newTestITSMStore(t *testing.T) (*itsmConfigStore, *server) {
	t.Helper()
	srv := &server{notifier: notify.NewDispatcher()}
	st := &itsmConfigStore{path: filepath.Join(t.TempDir(), "itsm.json"), srv: srv}
	return st, srv
}

func hasChannel(d *notify.Dispatcher, name string) bool {
	for _, n := range d.Names() {
		if n == name {
			return true
		}
	}
	return false
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
	st, srv := newTestITSMStore(t)

	// Enable ServiceNow → live connector + notifier channel present.
	if err := st.set(itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc", Password: "secret"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if srv.serviceNow() == nil {
		t.Fatal("servicenow connector not live after enable")
	}
	if !hasChannel(srv.notifier, "servicenow") {
		t.Error("servicenow not registered with the dispatcher")
	}

	// public() must redact the password but advertise that one is stored.
	pub := st.public()["servicenow"].(map[string]any)
	if _, leaked := pub["password"]; leaked {
		t.Error("public() leaked the password")
	}
	if pub["has_password"] != true || pub["configured"] != true {
		t.Errorf("public() flags wrong: %+v", pub)
	}

	// Blank password on update KEEPS the stored secret (write-only field).
	if err := st.set(itsmConfig{ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.service-now.com", User: "svc2", Password: ""}}); err != nil {
		t.Fatalf("set2: %v", err)
	}
	if st.cfg.ServiceNow.Password != "secret" {
		t.Errorf("blanked password not preserved, got %q", st.cfg.ServiceNow.Password)
	}

	// Disable → connector removed from server + dispatcher.
	if err := st.set(itsmConfig{ServiceNow: serviceNowConfig{Enabled: false}}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if srv.serviceNow() != nil {
		t.Error("servicenow still live after disable")
	}
	if hasChannel(srv.notifier, "servicenow") {
		t.Error("servicenow still registered after disable")
	}
}
