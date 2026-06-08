package main

import "testing"

// mfaSatisfied honors the IdP's MFA: an amr second factor, or a configured acr.
func TestOIDCMFASatisfied(t *testing.T) {
	p := &oidcProvider{mfaAcr: splitSet("urn:okta:loa:2fa,gold")}

	cases := []struct {
		name string
		c    oidcClaims
		want bool
	}{
		{"password only", oidcClaims{Amr: []string{"pwd"}}, false},
		{"no amr/acr", oidcClaims{}, false},
		{"amr otp", oidcClaims{Amr: []string{"pwd", "otp"}}, true},
		{"amr mfa", oidcClaims{Amr: []string{"mfa"}}, true},
		{"amr webauthn", oidcClaims{Amr: []string{"webauthn"}}, true},
		{"acr match", oidcClaims{Amr: []string{"pwd"}, Acr: "urn:okta:loa:2fa"}, true},
		{"acr non-match", oidcClaims{Amr: []string{"pwd"}, Acr: "urn:okta:loa:1fa"}, false},
		{"amr case-insensitive", oidcClaims{Amr: []string{"OTP"}}, true},
	}
	for _, tc := range cases {
		if got := p.mfaSatisfied(tc.c); got != tc.want {
			t.Errorf("%s: mfaSatisfied = %v, want %v", tc.name, got, tc.want)
		}
	}
}
