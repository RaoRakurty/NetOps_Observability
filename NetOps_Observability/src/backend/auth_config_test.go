package main

// auth_config_test.go — unit + HTTP tests for the runtime-configurable native
// LDAP/TACACS providers (auth_config.go): kv-backed config stores, write-only
// secret handling (redaction on GET, preservation on PUT), input validation,
// admin gating, and the public /api/auth/methods discovery endpoint.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newAuthCfgServer builds a server wired with the identity stores plus the
// LDAP/TACACS config stores and a (disabled) OIDC provider, exercised through
// the real router + auth middleware.
func newAuthCfgServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	us, err := newUserStore(dir + "/users.json")
	must(err)
	rs, err := newRoleStore(dir + "/roles.json")
	must(err)
	ts, err := newTenantStore(dir + "/tenants.json")
	must(err)
	rf, err := newRefreshStore(dir+"/refresh.json", time.Hour)
	must(err)
	must(us.SeedAdmin("admin", "password123"))
	s := &server{
		users:     us,
		roles:     rs,
		tenants:   ts,
		refresh:   rf,
		startedAt: time.Now().UTC(),
		oidc:      newOIDCProvider(), // disabled (no env) -> ready()==false
		ldap:      newLDAPConfigStore(dir + "/ldap_config.json"),
		tacacs:    newTACACSConfigStore(dir + "/tacacs_config.json"),
	}
	mux := http.NewServeMux()
	s.routes(mux)
	srv := httptest.NewServer(s.withAuth(mux))
	t.Cleanup(srv.Close)
	return srv
}

func adminToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return login(t, srv, "admin", "password123").Token
}

// ---------------------------------------------------------------------------
// LDAP config store (pure unit)
// ---------------------------------------------------------------------------

func TestLDAPConfigStoreSetEffectiveAndReload(t *testing.T) {
	path := t.TempDir() + "/ldap.json"
	st := newLDAPConfigStore(path)
	// Nothing saved yet -> falls back to env defaults (disabled).
	if st.effective().Enabled {
		t.Fatal("expected disabled effective config before any save")
	}
	in := ldapConfig{
		Enabled: true, Host: "ldap.example.com", BaseDN: "dc=example,dc=com",
		UserFilter: "(uid=%s)", BindDN: "cn=svc", BindPassword: "s3cret",
	}
	out, err := st.set(in)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !out.Enabled || out.Host != "ldap.example.com" {
		t.Fatalf("unexpected stored config: %+v", out)
	}
	// A fresh store over the same path must load the persisted config.
	st2 := newLDAPConfigStore(path)
	if got := st2.effective(); !got.Enabled || got.BindPassword != "s3cret" {
		t.Fatalf("reload lost data: %+v", got)
	}
}

func TestLDAPConfigSecretPreservedOnUpdate(t *testing.T) {
	st := newLDAPConfigStore(t.TempDir() + "/ldap.json")
	if _, err := st.set(ldapConfig{Enabled: true, Host: "h", BaseDN: "dc=x", UserFilter: "(uid=%s)", BindDN: "cn=svc", BindPassword: "orig"}); err != nil {
		t.Fatal(err)
	}
	// Update with an empty password (the redacted form round-trip) -> keep "orig".
	out, err := st.set(ldapConfig{Enabled: true, Host: "h2", BaseDN: "dc=x", UserFilter: "(uid=%s)", BindDN: "cn=svc"})
	if err != nil {
		t.Fatal(err)
	}
	if out.BindPassword != "orig" {
		t.Fatalf("password not preserved: %q", out.BindPassword)
	}
	if out.Host != "h2" {
		t.Fatalf("host not updated: %q", out.Host)
	}
	// Update with a new password -> replace.
	out, err = st.set(ldapConfig{Enabled: true, Host: "h2", BaseDN: "dc=x", UserFilter: "(uid=%s)", BindDN: "cn=svc", BindPassword: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if out.BindPassword != "new" {
		t.Fatalf("password not replaced: %q", out.BindPassword)
	}
}

func TestLDAPConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		c    ldapConfig
		ok   bool
	}{
		{"disabled is always valid", ldapConfig{Enabled: false}, true},
		{"enabled needs host", ldapConfig{Enabled: true, BaseDN: "dc=x", UserFilter: "(uid=%s)"}, false},
		{"enabled needs base_dn", ldapConfig{Enabled: true, Host: "h", UserFilter: "(uid=%s)"}, false},
		{"filter needs %s", ldapConfig{Enabled: true, Host: "h", BaseDN: "dc=x", UserFilter: "(uid=joe)"}, false},
		{"tls+starttls conflict", ldapConfig{Enabled: true, Host: "h", BaseDN: "dc=x", UserFilter: "(uid=%s)", UseTLS: true, StartTLS: true}, false},
		{"port range", ldapConfig{Enabled: true, Host: "h", BaseDN: "dc=x", UserFilter: "(uid=%s)", Port: 70000}, false},
		{"valid", ldapConfig{Enabled: true, Host: "h", BaseDN: "dc=x", UserFilter: "(uid=%s)"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			c.normalize()
			err := c.validate()
			if tc.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestLDAPConfigNormalizeDefaults(t *testing.T) {
	c := ldapConfig{Enabled: true, Host: "  h  ", BaseDN: " dc=x ", UserFilter: "  ",
		RoleMappings: []ldapRoleMapping{{Group: "cn=a", Role: "operator"}, {Group: " ", Role: "x"}, {Group: "cn=b", Role: ""}}}
	c.normalize()
	if c.Host != "h" || c.BaseDN != "dc=x" {
		t.Fatalf("trim failed: %+v", c)
	}
	if c.UserFilter != "(uid=%s)" {
		t.Fatalf("default filter not applied: %q", c.UserFilter)
	}
	if c.DefaultRole != RoleReadOnly || c.DefaultTenant != TenantGlobal {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if len(c.RoleMappings) != 1 || c.RoleMappings[0].Group != "cn=a" {
		t.Fatalf("role mappings not cleaned: %+v", c.RoleMappings)
	}
}

func TestLDAPPublicNeverLeaksPassword(t *testing.T) {
	c := ldapConfig{Enabled: true, Host: "h", BindPassword: "topsecret"}
	pub := c.public()
	if !pub.BindPasswordSet {
		t.Fatal("BindPasswordSet should be true")
	}
	b, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "topsecret") || strings.Contains(string(b), "bind_password\"") {
		t.Fatalf("public view leaked the password: %s", b)
	}
}

// ---------------------------------------------------------------------------
// TACACS config (pure unit)
// ---------------------------------------------------------------------------

func TestTACACSConfigClientBuild(t *testing.T) {
	c := tacacsConfig{Enabled: true, Host: "tac.example.com", Port: 49, Secret: "k", TimeoutSeconds: 3, DefaultRole: "operator"}
	cl := c.client()
	if !cl.Enabled() {
		t.Fatal("client should be enabled")
	}
	if cl.addr != "tac.example.com:49" {
		t.Fatalf("addr: %q", cl.addr)
	}
	if cl.timeout != 3*time.Second {
		t.Fatalf("timeout: %v", cl.timeout)
	}
	// Disabled when host empty even if Enabled flag set.
	if (tacacsConfig{Enabled: true, Host: ""}).client().Enabled() {
		t.Fatal("empty host must yield disabled client")
	}
}

func TestTACACSConfigSecretPreservedAndValidate(t *testing.T) {
	st := newTACACSConfigStore(t.TempDir() + "/tac.json")
	if _, err := st.set(tacacsConfig{Enabled: true, Host: "h", Secret: "orig"}); err != nil {
		t.Fatal(err)
	}
	out, err := st.set(tacacsConfig{Enabled: true, Host: "h2"}) // no secret -> preserve
	if err != nil {
		t.Fatal(err)
	}
	if out.Secret != "orig" || out.Host != "h2" {
		t.Fatalf("preserve/update failed: %+v", out)
	}
	if out.Port != 49 || out.TimeoutSeconds != 5 {
		t.Fatalf("normalize defaults not applied: %+v", out)
	}
	if _, err := st.set(tacacsConfig{Enabled: true, Host: ""}); err == nil {
		t.Fatal("enabled without host should fail validation")
	}
}

func TestTACACSPublicNeverLeaksSecret(t *testing.T) {
	pub := tacacsConfig{Enabled: true, Host: "h", Secret: "sharedkey"}.public()
	if !pub.SecretSet {
		t.Fatal("SecretSet should be true")
	}
	b, _ := json.Marshal(pub)
	if strings.Contains(string(b), "sharedkey") {
		t.Fatalf("public view leaked secret: %s", b)
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func TestAuthMethodsPublic(t *testing.T) {
	srv := newAuthCfgServer(t)
	st, b := do(t, srv, "GET", "/api/auth/methods", "", nil) // no token: must be public
	if st != 200 {
		t.Fatalf("methods status %d: %s", st, b)
	}
	var m struct {
		Local  bool `json:"local"`
		LDAP   struct{ Enabled bool } `json:"ldap"`
		TACACS struct{ Enabled bool } `json:"tacacs"`
		SSO    struct{ Enabled bool } `json:"sso"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if !m.Local || m.LDAP.Enabled || m.TACACS.Enabled || m.SSO.Enabled {
		t.Fatalf("unexpected methods: %s", b)
	}
}

func TestLDAPConfigAdminGatedAndRedacted(t *testing.T) {
	srv := newAuthCfgServer(t)
	// Unauthenticated -> 401.
	if st, _ := do(t, srv, "GET", "/api/auth/ldap/config", "", nil); st != 401 {
		t.Fatalf("unauth GET status %d, want 401", st)
	}
	tok := adminToken(t, srv)
	// PUT a config with a secret.
	put := map[string]any{
		"enabled": true, "host": "ldap.example.com", "base_dn": "dc=example,dc=com",
		"user_filter": "(uid=%s)", "bind_dn": "cn=svc", "bind_password": "supersecret",
	}
	st, b := do(t, srv, "PUT", "/api/auth/ldap/config", tok, put)
	if st != 200 {
		t.Fatalf("PUT status %d: %s", st, b)
	}
	if strings.Contains(string(b), "supersecret") {
		t.Fatalf("PUT response leaked secret: %s", b)
	}
	// GET must redact the password to a boolean.
	st, b = do(t, srv, "GET", "/api/auth/ldap/config", tok, nil)
	if st != 200 {
		t.Fatalf("GET status %d: %s", st, b)
	}
	if strings.Contains(string(b), "supersecret") {
		t.Fatalf("GET leaked secret: %s", b)
	}
	if !strings.Contains(string(b), `"bind_password_set":true`) {
		t.Fatalf("expected bind_password_set true: %s", b)
	}
	// /api/auth/methods should now report ldap enabled.
	_, mb := do(t, srv, "GET", "/api/auth/methods", "", nil)
	if !strings.Contains(string(mb), `"enabled":true`) {
		t.Fatalf("methods should reflect ldap enabled: %s", mb)
	}
}

func TestLDAPConfigRejectsInvalid(t *testing.T) {
	srv := newAuthCfgServer(t)
	tok := adminToken(t, srv)
	// enabled but no host -> 400.
	st, _ := do(t, srv, "PUT", "/api/auth/ldap/config", tok, map[string]any{"enabled": true, "base_dn": "dc=x", "user_filter": "(uid=%s)"})
	if st != 400 {
		t.Fatalf("invalid config status %d, want 400", st)
	}
}

func TestTACACSConfigAdminGatedAndRedacted(t *testing.T) {
	srv := newAuthCfgServer(t)
	if st, _ := do(t, srv, "GET", "/api/auth/tacacs/config", "", nil); st != 401 {
		t.Fatalf("unauth GET status %d, want 401", st)
	}
	tok := adminToken(t, srv)
	st, b := do(t, srv, "PUT", "/api/auth/tacacs/config", tok, map[string]any{
		"enabled": true, "host": "tac.example.com", "secret": "sharedkey", "default_role": "operator",
	})
	if st != 200 {
		t.Fatalf("PUT status %d: %s", st, b)
	}
	st, b = do(t, srv, "GET", "/api/auth/tacacs/config", tok, nil)
	if st != 200 || strings.Contains(string(b), "sharedkey") {
		t.Fatalf("GET leaked or failed: %d %s", st, b)
	}
	if !strings.Contains(string(b), `"secret_set":true`) {
		t.Fatalf("expected secret_set true: %s", b)
	}
}

func TestLDAPLoginNotConfiguredReturns404(t *testing.T) {
	srv := newAuthCfgServer(t)
	st, _ := do(t, srv, "POST", "/api/auth/ldap/login", "", map[string]string{"username": "x", "password": "y"})
	if st != 404 {
		t.Fatalf("ldap login when disabled: status %d, want 404", st)
	}
	st, _ = do(t, srv, "POST", "/api/auth/tacacs/login", "", map[string]string{"username": "x", "password": "y"})
	if st != 404 {
		t.Fatalf("tacacs login when disabled: status %d, want 404", st)
	}
}
