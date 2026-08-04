package secprofile

import (
	"strings"
	"testing"
)

// A validator is only worth what its failure behaviour is worth. Every test
// below asserts a REFUSAL, not a success — the success path is the trivial one.

func envOf(m map[string]string) Env {
	return func(k string) string { return m[k] }
}

func noFiles(string) bool { return false }

// The full production-ready configuration: no fatal findings.
func secureEnv() map[string]string {
	return map[string]string{
		"TLS_CERT_FILE":           "/data/tls/api.crt",
		"TLS_KEY_FILE":            "/data/tls/api.key",
		"TLS_CLIENT_CA_FILE":      "/data/tls/ca.pem",
		"TLS_CLIENT_ALLOWED_URIS": "spiffe://netops/ns/default/sa/nginx",
		"SEAL_PROVIDER":           "swtpm",
		"JWT_SECRET":              "x",
		"OPENSEARCH_URL":          "https://opensearch:9200",
		"CLICKHOUSE_URL":          "https://clickhouse:8443",
		"VICTORIA_URL":            "https://vmauth:8427",
		"DATABASE_URL":            "postgres://u:p@postgres:5432/netops?sslmode=verify-full",
		"REDIS_HOST":              "redis",
		"REDIS_PASSWORD":          "x",
		"CORRELATION_URL":         "https://correlation:8000",
	}
}

func TestSecureConfigurationHasNoFatalFindings(t *testing.T) {
	rep := Evaluate(Production, envOf(secureEnv()), noFiles)
	if rep.Fatal != 0 {
		t.Fatalf("a fully secured configuration must produce no fatal findings, got %d:\n%s", rep.Fatal, rep.Error())
	}
	if rep.Blocking() {
		t.Fatal("secure configuration must not block boot")
	}
}

// Each prohibited configuration must be caught INDIVIDUALLY, and must name a
// variable the operator can act on. A validator that only fails in aggregate
// tells you that something is wrong, not what.
func TestEachProhibitedConfigurationIsCaught(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]string)
		wantSub string // must appear in the finding, so the message is actionable
	}{
		{"no TLS listener", func(m map[string]string) { delete(m, "TLS_CERT_FILE") }, "TLS_CERT_FILE"},
		{"no client CA (mTLS off)", func(m map[string]string) { delete(m, "TLS_CLIENT_CA_FILE") }, "TLS_CLIENT_CA_FILE"},
		{"mTLS without identity allowlist", func(m map[string]string) { delete(m, "TLS_CLIENT_ALLOWED_URIS") }, "TLS_CLIENT_ALLOWED_URIS"},
		{"unsealed secrets", func(m map[string]string) { delete(m, "SEAL_PROVIDER") }, "SEAL_PROVIDER"},
		{"dev secret fallback", func(m map[string]string) { m["ALLOW_DEV_SECRETS"] = "true" }, "ALLOW_DEV_SECRETS"},
		{"no JWT secret", func(m map[string]string) { delete(m, "JWT_SECRET") }, "JWT_SECRET"},
		{"plaintext OpenSearch", func(m map[string]string) { m["OPENSEARCH_URL"] = "http://opensearch:9200" }, "OPENSEARCH_URL"},
		{"plaintext ClickHouse", func(m map[string]string) { m["CLICKHOUSE_URL"] = "http://clickhouse:8123" }, "CLICKHOUSE_URL"},
		{"plaintext VictoriaMetrics", func(m map[string]string) { m["VICTORIA_URL"] = "http://victoria:8428" }, "VICTORIA_URL"},
		{"postgres sslmode=disable", func(m map[string]string) {
			m["DATABASE_URL"] = "postgres://u:p@postgres:5432/netops?sslmode=disable"
		}, "sslmode=disable"},
		{"anonymous Valkey", func(m map[string]string) { delete(m, "REDIS_PASSWORD") }, "REDIS_PASSWORD"},
		{"plaintext correlation", func(m map[string]string) { m["CORRELATION_URL"] = "http://correlation:8000" }, "CORRELATION_URL"},
		{"insecure gNMI", func(m map[string]string) { m["GNMI_ALLOW_INSECURE"] = "true" }, "GNMI_ALLOW_INSECURE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := secureEnv()
			tc.mutate(env)
			rep := Evaluate(Production, envOf(env), noFiles)
			if rep.Fatal == 0 {
				t.Fatalf("%s produced NO fatal finding — production would boot with it", tc.name)
			}
			if !rep.Blocking() {
				t.Fatalf("%s must block a production boot", tc.name)
			}
			msg := rep.Error()
			if !strings.Contains(msg, tc.wantSub) {
				t.Fatalf("the refusal must name %q so an operator can act on it; got:\n%s", tc.wantSub, msg)
			}
			// Actionability contract: every fatal finding carries a remedy.
			for _, f := range rep.Findings {
				if f.Severity == Fatal && strings.TrimSpace(f.Remedy) == "" {
					t.Errorf("fatal finding %s has no remedy — an unactionable error is barely better than silence", f.Rule)
				}
			}
		})
	}
}

// The escape hatch is the PROFILE, never a bypass flag. Lower profiles report
// the same findings; only production refuses.
func TestLowerProfilesReportButDoNotBlock(t *testing.T) {
	env := envOf(map[string]string{}) // nothing configured: maximum findings
	for _, p := range []Profile{Lab, Development, Staging} {
		rep := Evaluate(p, env, noFiles)
		if rep.Fatal == 0 {
			t.Fatalf("%s must still REPORT fatal-class findings so an operator sees what production would refuse", p)
		}
		if rep.Blocking() {
			t.Fatalf("%s must not block boot — the profile is the escape hatch", p)
		}
	}
	if prod := Evaluate(Production, env, noFiles); !prod.Blocking() {
		t.Fatal("production MUST block on the same findings")
	}
}

// A typo in the profile must not silently downgrade production to lab.
func TestUnknownProfileIsRejected(t *testing.T) {
	if _, err := ParseProfile("prod"); err == nil {
		t.Fatal(`"prod" must be rejected — silently treating it as lab would disable every production check`)
	}
	if p, err := ParseProfile(""); err != nil || p != Lab {
		t.Fatalf("empty profile must default to lab, got %v %v", p, err)
	}
	for _, v := range []string{"Production", " production ", "PRODUCTION"} {
		if p, err := ParseProfile(v); err != nil || p != Production {
			t.Fatalf("profile %q should normalize to production, got %v %v", v, p, err)
		}
	}
}

// There must be no global bypass. This test exists to fail if someone ever adds
// one — it asserts on the rule set's own behaviour rather than on documentation.
func TestNoGlobalBypassExists(t *testing.T) {
	env := secureEnv()
	delete(env, "SEAL_PROVIDER") // one real violation
	for _, bypass := range []string{
		"IGNORE_SECURITY_ERRORS", "SKIP_SECURITY_VALIDATION", "DISABLE_SECURITY_CHECKS",
		"SECURITY_VALIDATOR_OFF", "FORCE_INSECURE",
	} {
		e := map[string]string{}
		for k, v := range env {
			e[k] = v
		}
		e[bypass] = "true"
		if rep := Evaluate(Production, envOf(e), noFiles); !rep.Blocking() {
			t.Fatalf("%s disabled the validator — a global bypass must never exist", bypass)
		}
	}
}

// Backups: deferred out of v1, so the finding must be VISIBLE but not fatal —
// the product must not claim coverage it does not have, nor block on it.
func TestBackupEncryptionIsVisibleButNotFatal(t *testing.T) {
	rep := Evaluate(Production, envOf(secureEnv()), noFiles)
	var found bool
	for _, f := range rep.Findings {
		if f.Rule == "BKP-001" {
			found = true
			if f.Severity != Warn {
				t.Fatalf("backup encryption is deferred by owner decision — it must warn, not block; got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("backup encryption must produce a visible finding when unverified — silence would imply coverage we do not have")
	}
}
