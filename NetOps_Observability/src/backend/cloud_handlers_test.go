package main

import "testing"

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
