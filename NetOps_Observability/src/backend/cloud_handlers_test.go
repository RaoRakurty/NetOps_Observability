package backend

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// isCloudAppToken bounds the app id embedded in the app-rca SQL literal (#81 P3G).
// It must accept real app/resource names (dots, dashes, slashes, colons, spaces)
// and REJECT anything that could break out of the literal — quotes, backslash,
// control chars, over-length. This is a SQL-injection guard, so the negative cases
// are the important ones.
func TestIsCloudAppToken(t *testing.T) {
	valid := []string{
		"billing", "checkout", "billing-db", "payments_api", "app/billing-alb/0a1b2c3d",
		"arn:aws:elb:tg", "Reports Worker", "a", "a.b.c-d_e:f/g",
	}
	for _, s := range valid {
		if !isCloudAppToken(s) {
			t.Errorf("expected valid app token: %q", s)
		}
	}

	invalid := []string{
		"",                                  // empty
		"a'b",                               // single quote — literal breakout
		"a\"b",                              // double quote
		"a\\b",                              // backslash
		"a;b",                               // statement separator
		"a b'; DROP TABLE netops.flows; --", // injection attempt
		"a\nb",                              // newline / control char
		"a\tb",                              // tab
		"app(name)",                         // parens
		"app=name",                          // equals
		"100%",                              // percent (LIKE wildcard)
	}
	for _, s := range invalid {
		if isCloudAppToken(s) {
			t.Errorf("expected REJECTED app token: %q", s)
		}
	}

	// over-length (>128) is rejected even with otherwise-valid chars.
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	if isCloudAppToken(string(long)) {
		t.Error("expected over-length app token to be rejected")
	}
}

// Wave 2 #5 scope bar: provider accepts a comma-separated OR set, every part
// enum-checked at the boundary — a typo in ANY part is a clean 400, never a
// silently-empty result.
func TestParseCloudResourceFilterMultiValue(t *testing.T) {
	ok := httptest.NewRequest(http.MethodGet,
		"/api/cloud/resources?provider=aws,azure&account=111,sub-9&region=us-east-1,eastus", nil)
	f, err := parseCloudResourceFilter(ok)
	if err != nil {
		t.Fatalf("multi-value filter rejected: %v", err)
	}
	if f.Provider != "aws,azure" || f.Account != "111,sub-9" || f.Region != "us-east-1,eastus" {
		t.Fatalf("filter fields not carried: %+v", f)
	}
	bad := httptest.NewRequest(http.MethodGet, "/api/cloud/resources?provider=aws,nonsense", nil)
	if _, err := parseCloudResourceFilter(bad); err == nil {
		t.Fatal("an unknown provider inside a multi-value list must be rejected")
	}
}

// Wave 5 #15: ?family= is a CLASS filter over the kinds.go vocabulary —
// validated at the boundary (typo = 400) and applied via ComponentFamily in
// both store backends (matchCloudResource here; buildCloudWhere mirrors it).
func TestParseCloudResourceFilterFamily(t *testing.T) {
	ok := httptest.NewRequest(http.MethodGet, "/api/cloud/resources?family=K8s", nil)
	f, err := parseCloudResourceFilter(ok)
	if err != nil {
		t.Fatalf("family filter rejected: %v", err)
	}
	if f.Family != "k8s" {
		t.Fatalf("family not normalized: %+v", f)
	}
	bad := httptest.NewRequest(http.MethodGet, "/api/cloud/resources?family=containers", nil)
	if _, err := parseCloudResourceFilter(bad); err == nil {
		t.Fatal("an unknown family must be rejected")
	}
}
