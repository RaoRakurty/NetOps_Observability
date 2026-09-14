// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"netops/backend/internal/elevation"
	"netops/backend/internal/jwks"
	"netops/backend/internal/oidc"
	"netops/backend/internal/tenantlocator"
	"netops/backend/internal/users"
)

// oidc.go — Single Sign-On via Keycloak (broker-and-reissue model).
//
// Keycloak is the AUTHENTICATION plane: it speaks OIDC, SAML 2.0 and LDAP/AD and
// brokers external IdPs (Okta, Azure AD, Google). The Go API is the
// AUTHORIZATION plane and never parses SAML/LDAP itself. The flow:
//
//	1. /api/auth/sso/login         → 302 to Keycloak's authorize endpoint
//	                                  (optionally with kc_idp_hint=<idp> so a
//	                                  SAML/LDAP IdP is selected directly)
//	2. user authenticates at Keycloak (OIDC, SAML, LDAP, MFA — all Keycloak's job)
//	3. /api/auth/sso/callback?code → we exchange the code, verify the ID token
//	                                  against Keycloak's JWKS (jwks.go), JIT-
//	                                  provision a local user, then mint OUR OWN
//	                                  session (HS256 access + rotating refresh).
//
// Re-issuing our own session keeps the hot-path middleware on a single
// verification path and means SAML/LDAP "just work" as Keycloak IdPs without a
// line of SAML in Go. See docs/IDENTITY_ACCESS.md.

// ssoProviderInfo describes a sign-in button for the UI / login page.
//
// handleSSOConfig: GET /api/auth/sso/config (PUBLIC — publicPaths). The second
// unauthenticated door onto the button list, beside /api/auth/methods, and it is
// filtered by the SAME realm rule (review 3.7-06): the caller sees the
// connections its locator candidate reaches, and with no locator only the
// PLATFORM realm. The reasoning — why a tenant-bound button on the bare page is
// a dead end, and why its alias and display label are not an anonymous caller's
// to read — is written out once on handleAuthMethods; the two doors must not
// disagree, or narrowing one of them means nothing.
func (s *server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []ssoProviderInfo{}})
		return
	}
	var cand *tenantlocator.Candidate
	if c, ok := s.locatorCandidate(r); ok {
		cand = &c
	}
	all := p.Providers()
	shown := make([]ssoProviderInfo, 0, len(all))
	for _, pi := range all {
		if s.providerVisible(cand, pi.ID) {
			shown = append(shown, pi)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "providers": shown})
}

const ssoStateCookie = "netops_sso_state"

// ssoPendingCookie is the JS-readable, single-use fallback nonce set only on
// bookmark / IdP-initiated logins (no SPA-supplied fe_state). The SPA reads and
// clears it, requiring it to equal the `state` echoed in the callback fragment,
// so a token delivered to a browser that never hit /sso/login is still refused.
const ssoPendingCookie = "netops_sso_pending"

// handleSSOLogin (public) starts the Authorization Code flow: set a CSRF state
// cookie and 302 to Keycloak. ?idp=<id> selects a federated IdP via kc_idp_hint.
func (s *server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeError(w, http.StatusNotFound, errors.New("sso not configured"))
		return
	}
	// The idp alias is forwarded to Keycloak as kc_idp_hint. Only aliases the
	// operator configured (OIDC_PROVIDERS / saved config) are accepted — the
	// browser never selects an IdP the server did not offer ("Okta dashboard
	// launch" hardening; the bookmark URL carries one of these aliases).
	idpHint := strings.TrimSpace(r.URL.Query().Get("idp"))
	if !p.ValidIDP(idpHint) {
		logWarn("auth", "sso login refused — unknown idp alias", map[string]any{"idp": idpHint})
		writeError(w, http.StatusNotFound, errors.New("unknown identity provider"))
		return
	}
	// Per-tenant sign-in (tracker 276): when the browser arrived through a
	// tenant's own sign-in URL, it may only start a flow through a provider that
	// tenant's realm reaches. Same 404 as an unknown alias — a wrong-tenant
	// probe learns nothing an unknown-alias probe does not.
	if !s.ssoIDPAllowedForLocator(r, idpHint) {
		logWarn("auth", "sso login refused — provider not registered for this realm", map[string]any{"idp": idpHint})
		writeError(w, http.StatusNotFound, errors.New("unknown identity provider"))
		return
	}
	state, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	verifier, challenge, err := oidc.NewPKCEVerifier()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Server-side transaction: makes state single-use at the callback and keeps
	// the nonce + PKCE verifier out of the browser entirely. feState is the SPA's
	// own nonce (M20): carried through the flow and echoed in the callback
	// fragment so only the tab that began the login can consume the token.
	feState := strings.TrimSpace(r.URL.Query().Get("fe_state"))
	if len(feState) > 128 {
		feState = feState[:128] // opaque; bound it (never trust caller length)
	}
	// Bookmark / IdP-initiated entry (Okta dashboard tile → …/sso/login?idp=okta,
	// docs/runbooks/okta-sso-setup.md): the full-page navigation never runs the
	// SPA's ssoLoginUrl(), so no fe_state is supplied and the M20 sessionStorage
	// nonce is never armed — the returning token would be discarded. Synthesize
	// the nonce server-side instead: a random value carried through the flow as
	// feState (echoed as `state` in the callback fragment) AND mirrored into a
	// JS-readable, short-TTL cookie the SPA falls back to when it has no
	// sessionStorage nonce. This still binds the token to a browser that actually
	// hit /sso/login: an attacker who delivers a #token= fragment to a victim who
	// never started a flow has neither the sessionStorage nonce nor this cookie,
	// so the token is refused. SP-initiated logins (SPA supplies fe_state) are
	// untouched — no cookie is synthesized in that path.
	if feState == "" {
		syn, err := randomToken(24)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		feState = syn
		http.SetCookie(w, &http.Cookie{
			Name:     ssoPendingCookie,
			Value:    syn,
			Path:     "/",
			HttpOnly: false, // SPA must read it to match the echoed `state`
			Secure:   cookieSecure(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
	}
	// The alias travels in the SERVER-SIDE transaction, not the browser: the
	// callback must know which door was used to decide whether this sign-in
	// provisions an account or only elevates one, and that decision may not
	// depend on anything the browser can restate. It was validated against the
	// configured button list above, so it can only name a provider the operator
	// configured.
	if err := s.ssoTxns.CreateFlowIdP(state, nonce, verifier, feState, idpHint, time.Now()); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	// Secure is decided per request by the SAME helper the session cookies use
	// (cookieSecure: SECURE_COOKIES=true, direct TLS, or X-Forwarded-Proto=https
	// from the TLS edge). This cookie is the CSRF defence for the whole SSO
	// callback — without Secure it was emitted in the clear on an HTTPS
	// deployment and became stealable off any plaintext request to the same
	// host, which is exactly the login-CSRF the state parameter exists to stop.
	http.SetCookie(w, &http.Cookie{
		Name:  ssoStateCookie,
		Value: state,
		// Path "/" — NOT "/api/auth/sso". A tenant-bound connection returns to
		// /t/{slug}/sso/{alias}/callback (tracker 276), and a cookie scoped to
		// the api prefix would simply not be sent there, taking the CSRF defence
		// off exactly the flow that needs it most. HttpOnly + SameSite=Lax +
		// Secure are unchanged, and the value stays a single-use opaque nonce.
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL, err := p.AuthorizeURL(s.ssoLoginRedirectURI(r, p, idpHint), state, nonce, challenge, idpHint)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// #nosec G710 -- the redirect target is the IdP's DISCOVERED auth endpoint
	// (trusted operator config via oidc.Provider), never caller input; the only
	// caller-influenced parts (state, kc_idp_hint) are query-encoded parameters.
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSSOCallback (public) completes the flow: validate state, exchange the
// code, verify the ID token, JIT-provision the user and re-issue our session.
func (s *server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeError(w, http.StatusNotFound, errors.New("sso not configured"))
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, e+": "+r.URL.Query().Get("error_description"))
		return
	}
	state := r.URL.Query().Get("state")
	ck, err := r.Cookie(ssoStateCookie)
	if err != nil || ck.Value == "" || ck.Value != state {
		s.ssoFail(w, r, "invalid SSO state")
		return
	}
	// Clear the state cookie. Same attributes as the one that was set (a delete
	// is just a Set with MaxAge<0, and a browser will reject a Secure cookie
	// arriving over plain HTTP) so the expiry lands on exactly the cookie above.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    "",
		Path:     "/", // must match the Set above or the expiry lands on nothing
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Atomically consume the server-side transaction: state becomes single-use
	// (a replayed callback dies here even with a stolen cookie), and the nonce +
	// PKCE verifier come back from server memory, never from the browser. The
	// browser-facing message stays identical to the cookie failure on purpose —
	// an attacker learns nothing about WHICH binding failed.
	txn, ok := s.ssoTxns.Consume(state, time.Now())
	if !ok {
		s.ssoFail(w, r, "invalid SSO state")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.ssoFail(w, r, "missing authorization code")
		return
	}
	idToken, err := p.Exchange(code, s.ssoCallbackRedirectURI(r, p), txn.Verifier)
	if err != nil {
		s.ssoFail(w, r, "token exchange failed: "+err.Error())
		return
	}
	claims, err := p.VerifyIDToken(idToken)
	if err != nil {
		s.ssoFail(w, r, "id token rejected: "+err.Error())
		return
	}
	// OIDC Core §3.1.3.7 #11: the ID token must echo OUR nonce. A token without
	// it, or with someone else's, was not minted for this login. Values are
	// deliberately not logged.
	if claims.Nonce == "" || claims.Nonce != txn.Nonce {
		s.ssoFail(w, r, "id token rejected: nonce mismatch")
		return
	}
	// Honor the IdP's MFA: when required, the token must assert a second factor
	// (amr/acr). We don't run MFA for SSO users — we verify the IdP did.
	if p.RequireMFA() && !p.MFASatisfied(claims) {
		logWarn("auth", "sso login rejected — MFA required but not asserted by IdP", map[string]any{"sub": claims.Sub, "amr": claims.Amr, "acr": claims.Acr})
		s.ssoFail(w, r, "multi-factor authentication is required — your identity provider did not confirm a second factor")
		return
	}

	// THE SUBJECT IS `sub`, AND ONLY `sub` (tracker 300 §2.3). It used to be
	// firstNonEmpty(preferred_username, email, sub), which made the account key
	// a mutable profile attribute: two IdPs asserting one e-mail were ONE
	// account, and a person renamed at the IdP became a second one. `sub` is the
	// broker's stable per-realm principal id and is the only thing keyed on now;
	// the old derivation survives solely as Assertion.LegacyUsername, for the
	// bounded §2.6 adoption of accounts the pre-migration code created from it.
	if strings.TrimSpace(claims.Sub) == "" {
		s.ssoFail(w, r, "id token carried no usable subject")
		return
	}
	// ELEVATION DOOR. A provider configured as `kind: elevation` provisions
	// nothing: it reads the existing account by its canonical tuple and mints a
	// time-bound binding on it. No provisioning, and no profile the IdP could
	// rewrite, is on this path at all.
	if pol, isElev := s.elevationPolicy(txn.IdP); isElev {
		s.completeElevationSSO(w, r, p, pol, txn.IdP, txn.FEState, claims)
		return
	}
	// THE REALM TRAVELS WITH THE SIGN-IN. Until now only the CONNECTION was
	// checked against the URL's realm; the ACCOUNT the token names was not, so a
	// tenant that registers its own IdP could name any username in the platform
	// and be handed a session in that account's tenant (and rewrite its role and
	// auth source on the way through). The store applies this beside the merge,
	// which is where it has to be: the merge write is itself the damage.
	// The realm comes from ssoSignInRealm, never from the callback URL alone: a
	// URL that names no realm falls back to the CONNECTION's own registration,
	// so only a connection nobody bound to a tenant carries no constraint.
	assertion := oidcSSOAssertion(p, claims, s.ssoProvisionTenant(r, p), txn.IdP)
	// THE REALM DECIDES WHICH RESOLUTION FORM IS CORRECT, and the two are not
	// interchangeable.
	//
	// A tenant-BOUND connection is resolved inside its own realm: the exact tuple,
	// then (§2.5 Amendment) the same (issuer, subject) across the tenants that
	// realm reaches, and nothing wider.
	//
	// An UNBOUND connection is the shared platform front door. It has no realm
	// because it legitimately signs in users of EVERY tenant — that is the
	// pre-locator behaviour every existing deployment depends on — so it uses the
	// same unbound form the bearer, LDAP and TACACS+ doors use: find the account by
	// (issuer, subject) whatever tenant it lives in, refuse an ambiguous match, and
	// provision into the provider's default tenant on first sight. Handing the ZERO
	// realm to the bound form instead would make the front door resolve the exact
	// tuple only, and every existing per-tenant account would be re-provisioned as
	// a duplicate in the global tenant on its owner's next sign-in.
	realm := s.ssoSignInRealm(r, txn.IdP)
	var user User
	if realm.Reaches == nil {
		user, err = s.users.ResolveFederatedUnbound(assertion)
	} else {
		user, err = s.users.ResolveFederated(assertion, realm, true)
	}
	if err != nil {
		// The account exists, in a realm this URL does not reach. Say only what
		// a mis-registered provider is told — naming the real reason would be a
		// cross-tenant existence oracle. The subject is logged, never echoed.
		if errors.Is(err, users.ErrForeignTenant) {
			s.ssoRefuseForeignRealm(w, r, claims.Sub)
			return
		}
		// Everything else — H1's local-account refusal (the IdP's verdict must
		// never be accepted against a locally-managed record: that would bypass
		// its password AND its MFA enrolment), an identity ambiguous across the
		// realm's tenants, a lost race on the tuple — maps once, for every door.
		_, msg, reason := identityRefusal(err)
		logWarn("auth", "sso login refused", map[string]any{"sub": claims.Sub, "src": "oidc", "reason": reason})
		s.ssoFail(w, r, msg)
		return
	}
	s.logBindingSync(user, "oidc") // PBAC Phase A: mirror the provisioned identity
	if user.Status == "disabled" {
		s.ssoFail(w, r, "account disabled")
		return
	}
	// #146b parity: the account-state gates every login path owes (tenant
	// suspension + hard account-lifecycle denials) and the F-68 concurrent-
	// login policy — previously enforced only on the local paths, so an
	// expired account or a suspended tenant's users could still enter via SSO.
	if msg := s.federatedLoginBarrier(r, user); msg != "" {
		s.ssoFail(w, r, msg)
		return
	}
	if err := s.enforceConcurrentLoginDeny(r, user); err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}

	// Open a server-side session (same lifecycle as every other login path) and
	// hand the SPA a fresh access token (with sid) + refresh token.
	access, refresh, err := s.mintSession(r, user)
	if err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}
	s.users.TouchLogin(user.ID)
	logInfo("auth", "sso login ok", map[string]any{"user": user.ID, "role": user.Role, "src": "oidc"})

	// Hand the session to the SPA via the URL fragment (never logged, never sent
	// to the server). The SPA captures it on load (services/api.ts).
	frag := url.Values{}
	frag.Set("token", access)
	frag.Set("refresh", refresh)
	frag.Set("sso", "1")
	// Echo the SPA's own nonce (M20) so the SPA accepts this fragment only in the
	// tab that started the flow; an attacker-delivered #token= fragment carries
	// no matching state and is dropped client-side.
	if txn.FEState != "" {
		frag.Set("state", txn.FEState)
	}
	http.Redirect(w, r, s.ssoPostLoginPath(r, p)+"#"+frag.Encode(), http.StatusFound)
}

// completeElevationSSO finishes a sign-in through an ELEVATION provider.
//
// Everything the standing path does to the account store is deliberately
// absent. What remains is: prove the account exists and is usable, derive the
// elevated role under the SAME federation guard the standing path uses (SR-025
// — an elevation IdP must not be the back door to platform ownership either),
// mint the grant, and then open an ordinary session so the operator is simply
// signed in with elevated access held beside their standing rights.
func (s *server) completeElevationSSO(w http.ResponseWriter, r *http.Request, p *oidcProvider, pol elevation.Policy, alias, feState string, claims jwks.Claims) {
	// The realm this sign-in is confined to. An elevation provider registered by
	// one tenant must not reach another tenant's account any more than a
	// standing one may — and, like the standing path, the constraint is read
	// from the CONNECTION when the callback URL names no realm, so a connection
	// whose tenant the directory cannot resolve does not become unbound
	// (ssoSignInRealm).
	realm := s.ssoSignInRealm(r, alias)
	bound := realm.Reaches != nil
	// THE READ-ONLY DOOR (design §2.5, tracker 300). It resolves the CANONICAL
	// TUPLE with provision=false: a tuple miss is a refusal and nothing is
	// written. It never binds by username again — the old `users.Get(username)`
	// made an elevation IdP able to name any account whose login handle it could
	// guess.
	//
	// The assertion deliberately carries NO Email, NO DisplayName, NO Role and NO
	// LegacyUsername. That keeps the documented invariant of this door intact:
	// the account is READ, never re-profiled, never re-roled and never adopted.
	// (MergeFederated with every profile field empty is a no-op, and the mapped
	// role is applied to the GRANT below, never to the record.)
	probe := users.Assertion{Identity: users.Identity{
		TenantID: s.ssoProvisionTenant(r, p),
		Issuer:   p.Issuer(),
		Subject:  claims.Sub,
		Protocol: users.ProtocolOIDC,
		// The alias is recorded beside the key, never in it.
		ConnectionID: alias,
	}}
	// An UNBOUND elevation connection is the SHARED PLATFORM FRONT DOOR: it
	// legitimately serves every tenant, exactly as it did when this lookup was
	// `users.Get(username)`. So the find-only lookup is told to reach every
	// tenant explicitly rather than being handed the "no constraint" zero value,
	// which the store deliberately reads as "no cross-tenant reach" to keep the
	// PROVISIONING path narrow (realmScopedOwner). Nothing is provisioned here,
	// and an identity that resolves to more than one account is still refused
	// rather than guessed.
	lookupRealm := realm
	if !bound {
		lookupRealm = users.Realm{Reaches: func(string) bool { return true }}
	}
	user, err := s.users.ResolveFederated(probe, lookupRealm, false)
	if err != nil {
		if bound || errors.Is(err, users.ErrForeignTenant) {
			// In a tenant-bound flow "no such account" and "not your account"
			// must answer identically, or the pair is an existence oracle.
			s.ssoRefuseForeignRealm(w, r, claims.Sub)
			return
		}
		if errors.Is(err, users.ErrNoSuchUser) {
			logWarn("auth", "elevation login refused — no account holds this identity",
				map[string]any{"sub": claims.Sub, "provider": pol.Provider})
			s.ssoFail(w, r, elevation.UnknownAccountRefusal)
			return
		}
		_, msg, reason := identityRefusal(err)
		logWarn("auth", "elevation login refused", map[string]any{"sub": claims.Sub, "provider": pol.Provider, "reason": reason})
		s.ssoFail(w, r, msg)
		return
	}
	// H1 parity, defence in depth: the store already refuses a federated tuple
	// pointing at a locally-managed account, so this can only fire on a corrupt
	// index — and it must still refuse. The local password and its MFA enrolment
	// are what protect that record.
	if isLocalAccount(user.AuthSource) {
		logWarn("auth", "elevation login refused — account is managed locally", map[string]any{"user": user.ID, "provider": pol.Provider})
		s.ssoFail(w, r, "this account is managed locally; sign in with your local password")
		return
	}
	if user.Status == "disabled" {
		s.ssoFail(w, r, "account disabled")
		return
	}
	if msg := s.federatedLoginBarrier(r, user); msg != "" {
		s.ssoFail(w, r, msg)
		return
	}
	// SR-025 still applies: the guard is evaluated against the ACCOUNT's tenant,
	// which is the tenant the grant will be made in. The principal it is handed
	// is the OPAQUE PRINCIPAL ID, never an IdP-derived handle (§4.9).
	role := guardFederatedRole(p.RoleFor(claims), user.TenantID, user.ID, "oidc-elevation")
	// ORDERING, not cleanup: the grant is validated here but PERSISTED last,
	// after every gate that can still refuse this sign-in has passed. A grant
	// written before the deny gate or the session mint would outlive a sign-in
	// the server reported as failed, and elevation resolves by principal id — so
	// the principal's next ordinary session would silently spend it.
	grant, err := s.prepareElevationGrant(pol, user, role, claims.Sid, claims.Claim)
	if err != nil {
		logWarn("auth", "elevation login refused", map[string]any{
			"user": user.ID, "provider": pol.Provider, "reason": err.Error()})
		s.ssoFail(w, r, err.Error())
		return
	}
	if err := s.enforceConcurrentLoginDeny(r, user); err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}
	access, refresh, sid, err := s.mintSessionWithID(r, user)
	if err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}
	b, err := s.commitElevationGrant(r, pol, user, grant, claims.Sid)
	if err != nil {
		// The session opened a moment ago was never handed to the client: this
		// path answers with sso_error and no fragment. Close it rather than
		// leave a live credential behind a refusal.
		s.abandonSession(r, user, sid, "elevation_grant_not_persisted")
		logWarn("auth", "elevation login refused", map[string]any{
			"user": user.ID, "provider": pol.Provider, "reason": err.Error()})
		s.ssoFail(w, r, err.Error())
		return
	}
	s.users.TouchLogin(user.ID)
	logInfo("auth", "elevation login ok", map[string]any{
		"user": user.ID, "role": user.Role, "elevated_role": b.RoleID,
		"provider": pol.Provider, "binding": b.ID, "src": "oidc-elevation"})
	frag := url.Values{}
	frag.Set("token", access)
	frag.Set("refresh", refresh)
	frag.Set("sso", "1")
	frag.Set("elevated", "1")
	// M20: echo the SPA's own nonce so the fragment is accepted only in the tab
	// that started the flow — identical binding to the standing path.
	if feState != "" {
		frag.Set("state", feState)
	}
	// The SAME post-login path the standing success and every ssoFail take: a
	// per-tenant elevation sign-in lands back on ITS OWN entry point, not on the
	// generic one. Derived from the callback path (ssoPostLoginPath), never from
	// anything the browser asked for, so this reuses the one helper rather than
	// building a second redirect.
	http.Redirect(w, r, s.ssoPostLoginPath(r, p)+"#"+frag.Encode(), http.StatusFound)
}

func (s *server) ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	logInfo("auth", "sso login failed", map[string]any{"reason": msg})
	frag := url.Values{}
	frag.Set("sso_error", msg)
	http.Redirect(w, r, s.ssoPostLoginPath(r, s.oidcProvider())+"#"+frag.Encode(), http.StatusFound)
}

// exchange trades an authorization code for tokens at Keycloak's token endpoint
// and returns the raw ID token.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// jwksTTL is how long signing keys are cached before a refresh. This is the IdP
// cert-rollover refresh interval (best practice: hours). We default to 10 minutes
// — well within range and more current than typical — and the cache also refreshes
// on an unknown-kid miss, so a rotation is picked up immediately regardless.
// Tunable via OIDC_JWKS_TTL_MIN (minutes); clamped to [1, 1440].
func jwksTTL() time.Duration {
	m := 10
	if v := os.Getenv("OIDC_JWKS_TTL_MIN"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n >= 1 && n <= 1440 {
			m = n
		}
	}
	return time.Duration(m) * time.Minute
}

// mfaAmrMethods are amr values that indicate a SECOND factor was used (anything
// beyond a bare password). Broad on purpose to interop across IdPs (Okta, Entra,
// Keycloak, Auth0, Ping…). "pwd"/"password" alone is NOT MFA.

// The provider + config domain moved to internal/oidc (Phase-2 W4.4); the
// login-transaction store lives there too (#135 hardening).
type (
	oidcProvider    = oidc.Provider
	oidcConfig      = oidc.Config
	ssoProviderInfo = oidc.ProviderInfo
	ssoTxnStore     = oidc.TxnStore
)

func newSSOTxnStore() *ssoTxnStore { return oidc.NewTxnStore() }

// ---------------------------------------------------------------------------
// TRACKER 300 IDENTITY NAMESPACING — see docs/design/IDENTITY_NAMESPACING_2026-09-13.md
//
// One rule, restated where it is applied: a principal is identified by
// **tenant_id + issuer + subject**, never by a username and never by an e-mail.
// Each door hands the store exactly what it VERIFIED — the issuer it checked the
// signature against and the subject that issuer asserted — and lets
// internal/users resolve it. preferred_username, e-mail and a directory login
// name travel as PROFILE attributes; the one place a username is still consulted
// is Assertion.LegacyUsername, which feeds only the bounded §2.6 lazy bind.
// ---------------------------------------------------------------------------

// oidcSSOAssertion is what the interactive OIDC callback verified.
//
// The ISSUER is the one `iss` this code ever checks a signature against (the
// platform broker's), and the SUBJECT is `claims.Sub` and nothing else. The
// upstream IdP is recorded beside the key as the connection alias, NOT in it
// (design §1.4): brokered identities differ by `sub`, and putting the alias in
// the key would mint a second account for the same person the day an operator
// re-registers a connection.
func oidcSSOAssertion(p *oidcProvider, claims jwks.Claims, tenant, connectionID string) users.Assertion {
	return users.Assertion{
		Identity: users.Identity{
			TenantID:     tenant,
			Issuer:       p.Issuer(),
			Subject:      claims.Sub,
			Protocol:     users.ProtocolOIDC,
			ConnectionID: connectionID,
		},
		Email:       claims.Email,
		DisplayName: firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email),
		Role:        p.RoleFor(claims),
		// §2.6 ONLY: the EXACT legacy derivation this door used before tracker
		// 300, so an SSO account that already exists is adopted once instead of
		// being re-provisioned and re-roled by hand.
		LegacyUsername: legacyOIDCUsername(claims),
	}
}

// legacyOIDCUsername reproduces the pre-tracker-300 username derivation of the
// OIDC doors — `firstNonEmpty(preferred_username, email, sub)` — byte for byte.
// It is an INPUT TO §2.6 AND NOTHING ELSE: getting it wrong cannot link two
// identities (the lazy bind refuses anything already bound, anything created
// after the migration epoch and anything of another auth_source), it can only
// mean an existing account is left pending for an operator.
func legacyOIDCUsername(claims jwks.Claims) string {
	return firstNonEmpty(claims.PreferredUsername, claims.Email, claims.Sub)
}
