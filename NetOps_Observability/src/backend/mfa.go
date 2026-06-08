package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// mfa.go — TOTP multi-factor auth for LOCAL accounts. Federated users are managed
// by their IdP (we don't see their password), so MFA there is enforced at the IdP
// via the OIDC amr/acr claims — not here.
//
// Flow: setup (issue a pending secret) → activate (confirm a code) → enabled.
// At login, an MFA-enabled user gets a short-lived challenge token instead of a
// session; they complete it at /api/auth/mfa/login with a code.

// mfaChallengeScope marks the short-lived token issued between password success
// and code entry. withAuth REJECTS any token carrying it, so a challenge token can
// NEVER be used as a session/access token — it only works at /api/auth/mfa/login.
const mfaChallengeScope = "mfa-challenge"
const mfaChallengeTTL = 5 * time.Minute

// sealMFA / openMFA encrypt the per-user TOTP seed at rest with the platform DEK,
// bound to the username (AAD), mirroring the other config-secret seals. A dormant
// Vault passes through (plaintext) — same posture as every other stored secret.
func (s *server) sealMFA(username, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	return sealFn(s.vault)("", "user.mfa:"+strings.ToLower(username), secret) // #nosec G101 -- Vault AAD field-id, not a credential
}
func (s *server) openMFA(username, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	return openFn(s.vault)("", "user.mfa:"+strings.ToLower(username), sealed) // #nosec G101 -- Vault AAD field-id, not a credential
}

// handleMFASetup (POST, authed) issues a fresh PENDING secret for the caller and
// returns the otpauth URI + secret so the SPA can render a QR / manual key. Local
// accounts only. Does not enable MFA — the caller must confirm a code at /activate.
func (s *server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	u, ok := s.users.Get(claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("user not found"))
		return
	}
	if !isLocalAccount(u.AuthSource) {
		writeError(w, http.StatusBadRequest, errors.New("MFA for federated accounts is managed by your identity provider"))
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sealed, err := s.sealMFA(u.Username, secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("could not store MFA secret"))
		return
	}
	if err := s.users.SetMFA(u.Username, u.MFAEnabled, u.MFASecret, sealed); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret, // shown once for manual entry; pairs with the QR
		"uri":    totpURI(secret, mfaIssuer(), u.Username),
	})
}

// handleMFAActivate (POST {code}, authed) confirms the pending secret and enables MFA.
func (s *server) handleMFAActivate(w http.ResponseWriter, r *http.Request) {
	claims, code, u, ok := s.mfaCodeRequest(w, r)
	if !ok {
		return
	}
	if u.MFAPending == "" {
		writeError(w, http.StatusBadRequest, errors.New("no pending MFA setup — start enrollment first"))
		return
	}
	secret, err := s.openMFA(u.Username, u.MFAPending)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("could not read MFA secret"))
		return
	}
	if !verifyTOTP(secret, code) {
		writeError(w, http.StatusBadRequest, errors.New("that code didn't match — check your authenticator and try again"))
		return
	}
	if err := s.users.SetMFA(claims.Sub, true, u.MFAPending, ""); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	logInfo("mfa", "enabled", map[string]any{"user": claims.Sub})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true})
}

// handleMFADisable (POST {code}, authed) turns MFA off after re-verifying a code.
func (s *server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	claims, code, u, ok := s.mfaCodeRequest(w, r)
	if !ok {
		return
	}
	if !u.MFAEnabled {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	secret, err := s.openMFA(u.Username, u.MFASecret)
	if err != nil || !verifyTOTP(secret, code) {
		writeError(w, http.StatusBadRequest, errors.New("that code didn't match — MFA was not disabled"))
		return
	}
	if err := s.users.SetMFA(claims.Sub, false, "", ""); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	logInfo("mfa", "disabled", map[string]any{"user": claims.Sub})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

// handleMFAStatus (GET, authed) reports the caller's MFA state for the UI.
func (s *server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	u, _ := s.users.Get(claims.Sub)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": u.MFAEnabled,
		"pending": u.MFAPending != "",
		"local":   isLocalAccount(u.AuthSource),
	})
}

// handleMFALogin (POST {mfa_token, code}, PUBLIC) completes a login challenge: it
// verifies the short-lived challenge token + the TOTP code, then issues the real
// session — the same response shape as a password-only login.
func (s *server) handleMFALogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	claims, err := verifyJWT(req.MFAToken, jwtSecret())
	if err != nil || !claims.hasScope(mfaChallengeScope) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired MFA challenge — sign in again"))
		return
	}
	u, ok := s.users.Get(claims.Sub)
	if !ok || u.Status == "disabled" || !u.MFAEnabled {
		writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
		return
	}
	secret, err := s.openMFA(u.Username, u.MFASecret)
	if err != nil || !verifyTOTP(secret, req.Code) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid authentication code"))
		return
	}
	s.issueSession(w, r, u)
}

// mfaCodeRequest is the shared preamble for the authed code-bearing endpoints
// (activate/disable): resolve the caller, require a local account, decode {code}.
func (s *server) mfaCodeRequest(w http.ResponseWriter, r *http.Request) (jwtClaims, string, User, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return jwtClaims{}, "", User{}, false
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return jwtClaims{}, "", User{}, false
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return jwtClaims{}, "", User{}, false
	}
	u, ok := s.users.Get(claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("user not found"))
		return jwtClaims{}, "", User{}, false
	}
	return claims, strings.TrimSpace(req.Code), u, true
}

// handleMFAAdminReset (POST {username}, admin) clears a user's MFA — the recovery
// path when someone loses their device. Same-tenant unless platform owner.
func (s *server) handleMFAAdminReset(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target, ok := s.users.Get(req.Username)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("user not found"))
		return
	}
	tenant, cross := principalTenant(claims)
	if !cross && !strings.EqualFold(target.TenantID, tenant) {
		writeError(w, http.StatusForbidden, errors.New("cannot manage a user in another tenant"))
		return
	}
	if err := s.users.SetMFA(target.Username, false, "", ""); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	logInfo("mfa", "admin reset", map[string]any{"user": target.Username, "by": claims.Sub})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

func mfaIssuer() string {
	if v := strings.TrimSpace(envOr("MFA_ISSUER", "")); v != "" {
		return v
	}
	return "Opsis"
}
