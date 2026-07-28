package tenant

import "testing"

// Moved from the integrator with sanitizeLandingRoute (route sanitization is
// package contract; the setter/resolution tests stayed with the wrapper).
func TestSanitizeLandingRoute(t *testing.T) {
	ok := []string{"", "#/incident/overview", "#/dashboards/home", "#/infrastructure/topology-canvas"}
	for _, r := range ok {
		if _, err := sanitizeLandingRoute(r); err != nil {
			t.Errorf("sanitizeLandingRoute(%q) unexpected error: %v", r, err)
		}
	}
	bad := []string{
		"https://evil.com",               // open-redirect attempt
		"//evil.com",                     // scheme-relative
		"#/foo bar",                      // whitespace
		"javascript:alert(1)",            // no hash route
		"/incident/overview",             // missing hash
		"#/" + string(make([]byte, 200)), // too long / control bytes
	}
	for _, r := range bad {
		if _, err := sanitizeLandingRoute(r); err == nil {
			t.Errorf("sanitizeLandingRoute(%q) should have been rejected", r)
		}
	}
}
