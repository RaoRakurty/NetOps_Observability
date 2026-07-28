package main

import (
	"testing"

	"netops/backend/internal/jwks"
)

// mfaSatisfied honors the IdP's MFA: an amr second factor, or a configured acr.
func TestOIDCMFASatisfied(t *testing.T) {
	p := &oidcProvider{mfaAcr: splitSet("urn:okta:loa:2fa,gold")}

	cases := []struct {
		name string
		c    jwks.Claims
		want bool
	}{
		{"password only", jwks.Claims{Amr: []string{"pwd"}}, false},
		{"no amr/acr", jwks.Claims{}, false},
		{"amr otp", jwks.Claims{Amr: []string{"pwd", "otp"}}, true},
		{"amr mfa", jwks.Claims{Amr: []string{"mfa"}}, true},
		{"amr webauthn", jwks.Claims{Amr: []string{"webauthn"}}, true},
		{"acr match", jwks.Claims{Amr: []string{"pwd"}, Acr: "urn:okta:loa:2fa"}, true},
		{"acr non-match", jwks.Claims{Amr: []string{"pwd"}, Acr: "urn:okta:loa:1fa"}, false},
		{"amr case-insensitive", jwks.Claims{Amr: []string{"OTP"}}, true},
	}
	for _, tc := range cases {
		if got := p.mfaSatisfied(tc.c); got != tc.want {
			t.Errorf("%s: mfaSatisfied = %v, want %v", tc.name, got, tc.want)
		}
	}
}
