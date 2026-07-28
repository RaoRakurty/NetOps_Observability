package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/snmpcred"
	"strings"
	"testing"
)

func TestGenSecretSafeAndUnique(t *testing.T) {
	a, err := genSecret(20)
	if err != nil || len(a) != 20 {
		t.Fatalf("genSecret len/err: %q %v", a, err)
	}
	b, _ := genSecret(20)
	if a == b {
		t.Fatal("secrets must be random/unique")
	}
	// CLI-safe: lowercase alnum only (no quotes/spaces/specials to break a paste).
	for _, r := range a {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Fatalf("secret has unsafe char %q in %q", r, a)
		}
	}
}

func TestDeviceSNMPConfigPerVendor(t *testing.T) {
	// v3 block for each first-class vendor must contain the generated keys and
	// the vendor's signature CLI token.
	cases := []struct{ vendor, token string }{
		{"cisco", "snmp-server user"},
		{"arista", "snmp-server user"},
		{"juniper", "set snmp v3 usm"},
		{"fortinet", "config system snmp user"},
		{"paloalto", "snmp-setting access-setting version v3"},
		{"f5", "modify sys snmp users"},
		{"checkpoint", "add snmp usm user"},
		{"mikrotik", "/snmp community add"},
		{"huawei", "usm-user v3"},
		{"extreme", "configure snmpv3 add user"},
		{"ubiquiti", "set service snmp v3 user"},
	}
	for _, c := range cases {
		cfg := deviceSNMPConfig(c.vendor, "v3", "", "correlix", "AUTH123", "PRIV456", "", "")
		if !strings.Contains(cfg, c.token) {
			t.Errorf("%s v3 missing token %q:\n%s", c.vendor, c.token, cfg)
		}
		if !strings.Contains(cfg, "AUTH123") || !strings.Contains(cfg, "PRIV456") {
			t.Errorf("%s v3 must embed both keys:\n%s", c.vendor, cfg)
		}
	}
}

func TestDeviceSNMPConfigV2cAndFortinetHosts(t *testing.T) {
	c := deviceSNMPConfig("cisco", "v2c", "PUB123", "", "", "", "", "")
	if !strings.Contains(c, "snmp-server community PUB123 RO") {
		t.Fatalf("cisco v2c wrong: %s", c)
	}
	// FortiGate v2c defaults the host to the whole space when no subnet given.
	fg := deviceSNMPConfig("fortinet", "v2c", "PUB123", "", "", "", "", "")
	if !strings.Contains(fg, "set ip 0.0.0.0 0.0.0.0") || !strings.Contains(fg, `set name "PUB123"`) {
		t.Fatalf("fortinet v2c default host wrong: %s", fg)
	}
	// With a subnet it uses it.
	fg2 := deviceSNMPConfig("fortinet", "v2c", "PUB123", "", "", "", "10.0.0.0", "255.0.0.0")
	if !strings.Contains(fg2, "set ip 10.0.0.0 255.0.0.0") {
		t.Fatalf("fortinet v2c subnet wrong: %s", fg2)
	}
}

func TestDeviceSNMPConfigUnknownVendorFallback(t *testing.T) {
	cfg := deviceSNMPConfig("aruba", "v3", "", "correlix", "AK", "PK", "", "")
	if !strings.Contains(cfg, "SNMPv3 read-only user") || !strings.Contains(cfg, "AK") {
		t.Fatalf("unknown vendor should give generic guidance with the key: %s", cfg)
	}
}

func TestBuildSNMPCredential(t *testing.T) {
	v3 := buildSNMPCredential("fortinet", "v3", "", "correlix", "AK", "PK")
	if v3.Version != "v3" || v3.SecurityName != "correlix" || v3.AuthProtocol != "SHA" || v3.PrivProtocol != "AES128" || v3.AuthKey != "AK" || v3.PrivKey != "PK" {
		t.Fatalf("v3 cred wrong: %+v", v3)
	}
	v2 := buildSNMPCredential("cisco", "v2c", "PUB", "", "", "")
	if v2.Community != "PUB" || v2.SecurityName != "" {
		t.Fatalf("v2c cred wrong: %+v", v2)
	}
}

func genGenServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := snmpcred.NewStore(dir+"/creds.json", nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	au, _ := newAuditStore(dir + "/audit.json")
	return &server{roles: rs, snmpCreds: cs, audit: au}
}

func TestGenerateSNMPConfigHandler(t *testing.T) {
	s := genGenServer(t)
	body := `{"vendor":"fortinet","version":"v3"}`
	r := httptest.NewRequest(http.MethodPost, "/api/onboard/snmp-config", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}))
	w := httptest.NewRecorder()
	s.handleGenerateSNMPConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	var res snmpGenResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.AuthKey == "" || res.PrivKey == "" || res.ProfileID != "fortinet-v3-gen" || !res.Templated {
		t.Fatalf("result incomplete: %+v", res)
	}
	if !strings.Contains(res.DeviceConfig, res.AuthKey) {
		t.Fatal("device config must embed the generated auth key")
	}
	// The profile was provisioned (secrets write-only — Get never returns them).
	pub, ok := s.snmpCreds.Get("fortinet-v3-gen")
	if !ok || !pub.HasAuthKey || !pub.HasPrivKey {
		t.Fatalf("profile not provisioned write-only: %+v ok=%v", pub, ok)
	}
}

func TestGenerateSNMPConfigRequiresPlatformAdmin(t *testing.T) {
	s := genGenServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/onboard/snmp-config", strings.NewReader(`{"vendor":"cisco"}`))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, jwtClaims{Role: "admin", Tenant: "t-a", Sub: "u"}))
	w := httptest.NewRecorder()
	s.handleGenerateSNMPConfig(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin must be refused (platform-admin only), got %d", w.Code)
	}
}

func TestGenerateSNMPConfigSkipProfile(t *testing.T) {
	s := genGenServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/onboard/snmp-config", strings.NewReader(`{"vendor":"cisco","version":"v2c","skip_profile":true}`))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}))
	w := httptest.NewRecorder()
	s.handleGenerateSNMPConfig(w, r)
	var res snmpGenResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Community == "" || res.ProfileID != "" {
		t.Fatalf("skip_profile: config+secret returned, no profile: %+v", res)
	}
	if _, ok := s.snmpCreds.Get("cisco-v2c-gen"); ok {
		t.Fatal("skip_profile must not provision a profile")
	}
}
