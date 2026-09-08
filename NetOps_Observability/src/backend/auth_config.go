// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/tacacs"
	"netops/backend/internal/tenantlocator"
	"netops/backend/internal/vault"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// auth_config.go — runtime-configurable, kv-persisted overlays for the native
// LDAP/AD and TACACS+ authentication providers, their admin GET/PUT +
// test-connection handlers, and the public /api/auth/methods discovery endpoint
// the login page uses to decide which sign-in options to render.
//
// Design mirrors copilotConfigStore (see copilot_config.go): a stored JSON
// document overlays the env-derived defaults, so operators configure providers
// from the admin UI without editing .env and restarting. Two invariants:
//
//   - Secrets are WRITE-ONLY. GET never returns the LDAP bind password or the
//     TACACS shared secret — only a "*_set" boolean. A PUT that omits the secret
//     PRESERVES the stored one, so saving the redacted form never wipes it.
//   - Zero trust at the boundary: every PUT is normalised and validated before
//     it is persisted; an "enabled" config that is missing required fields is
//     rejected rather than silently half-applied.

// ---------------------------------------------------------------------------
// Shared sealed-kv-config plumbing (#147 T4)
// ---------------------------------------------------------------------------

// loadSealedKVConfig reads a sealed provider-config overlay from the kv store.
// THREE states, never two (the cloud_monitor_eval.go shape):
//
//	(nil, nil)  — absent key or empty blob: never configured, env defaults apply
//	(nil, err)  — the store did not answer or the blob would not decode
//	(&c, err)   — loaded, but the secret failed to UNSEAL: clearSecret has run so
//	              the sealed bytes are never used as a credential, while the
//	              non-secret fields stay usable for the operator to inspect
//	(&c, nil)   — loaded
//
// kind is the error-message noun ("LDAP"/"TACACS"), component the log component,
// secretDesc the unseal-failure noun ("LDAP bind password"/"TACACS shared secret").
func loadSealedKVConfig[T any](path, kind, component, secretDesc string, unseal func(T) (T, error), clearSecret func(*T)) (*T, error) {
	b, err := platformdb.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // absent key = never configured; env defaults apply
	}
	if err != nil {
		return nil, fmt.Errorf("read %s config: %w", kind, err)
	}
	if len(b) == 0 {
		return nil, nil // present but empty = never configured
	}
	var c T
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("decode %s config: %w", kind, err)
	}
	var loadErr error
	if dec, derr := unseal(c); derr != nil {
		// Keep the config (host etc. stay usable for the operator to inspect)
		// but never authenticate with the SEALED bytes as the secret.
		clearSecret(&c)
		loadErr = fmt.Errorf("unseal %s: %w", secretDesc, derr)
		logError(component, "decrypt secret", errf(derr))
	} else {
		c = dec
	}
	return &c, loadErr
}

// persistSealedKVConfig seals in (encrypt at rest; the caller's in-memory copy
// stays plaintext) and writes it to the kv store.
func persistSealedKVConfig[T any](path string, in T, seal func(T) (T, error)) error {
	sealed, err := seal(in)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(path, b)
}

// handleProviderConfig serves the admin-gated GET/PUT surface shared by the
// LDAP and TACACS+ config endpoints: GET returns the redacted effective config;
// PUT validates, persists and echoes the redacted result.
func handleProviderConfig[T any](s *server, w http.ResponseWriter, r *http.Request,
	effective func() T, set func(T) (T, error), public func(T) any,
	logMsg string, logFields func(T) map[string]any) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": public(effective())})
	case http.MethodPut:
		var in T
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := set(in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("auth", logMsg, logFields(out))
		writeJSON(w, http.StatusOK, map[string]any{"config": public(out)})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// LDAP config store
// ---------------------------------------------------------------------------

type ldapConfigStore struct {
	mu    sync.RWMutex
	cfg   *ldapConfig // nil until an operator saves; falls back to env defaults
	path  string
	vault *vault.Vault // secret-custody envelope for bind_password at rest (nil = dormant/passthrough)
	// loadErr records that the stored bind password could not be UNSEALED. The
	// in-memory copy is blank in that case, so the "empty PUT preserves the
	// stored secret" shortcut would silently WIPE it — set() refuses instead.
	loadErr error
}

func newLDAPConfigStore(path string, v *vault.Vault) *ldapConfigStore {
	s := &ldapConfigStore{path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		// An unreadable auth config makes the provider fall back to the env
		// defaults (usually: LDAP off). That is a sign-in outage whose CAUSE was
		// previously invisible — it took the same branch as "no operator has
		// configured LDAP yet" (§10).
		logError("ldap.config", "stored LDAP config unreadable — LDAP sign-in falls back to the env defaults", errf(err))
	}
	return s
}

// load reads the stored LDAP overlay via loadSealedKVConfig (three states,
// never two).
func (s *ldapConfigStore) load() error {
	c, err := loadSealedKVConfig(s.path, "LDAP", "ldap.config", "LDAP bind password",
		func(c ldapConfig) (ldapConfig, error) { return mapLDAP(c, openFn(s.vault)) },
		func(c *ldapConfig) { c.BindPassword = "" })
	if c != nil {
		s.mu.Lock()
		s.cfg = c
		s.mu.Unlock()
	}
	return err
}

// effective returns the stored overlay when present, else the env-derived
// defaults (newLDAPConfig) so behaviour matches the original env-only
// resolution until an operator saves from the UI.
func (s *ldapConfigStore) effective() ldapConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c == nil {
		return newLDAPConfig()
	}
	return *c
}

// set validates and persists in. When in.BindPassword is empty the previously
// stored bind password is preserved (the redacted GET form does not round-trip
// the secret). Returns the stored effective config.
func (s *ldapConfigStore) set(in ldapConfig) (ldapConfig, error) {
	in.Normalize()
	if err := in.Validate(); err != nil {
		return ldapConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.BindPassword == "" && s.cfg != nil {
		if s.loadErr != nil {
			return ldapConfig{}, errors.New("the stored bind password could not be read — re-enter it with this save")
		}
		in.BindPassword = s.cfg.BindPassword
	}
	if err := persistSealedKVConfig(s.path, in, func(c ldapConfig) (ldapConfig, error) {
		return mapLDAP(c, sealFn(s.vault))
	}); err != nil {
		return ldapConfig{}, err
	}
	stored := in
	s.cfg = &stored
	s.loadErr = nil // a successful save IS the repair
	return stored, nil
}

// handleLDAPConfig: GET/PUT /api/auth/ldap/config (admin-gated). GET returns the
// redacted effective config; PUT validates and persists.
func (s *server) handleLDAPConfig(w http.ResponseWriter, r *http.Request) {
	handleProviderConfig(s, w, r, s.ldap.effective, s.ldap.set,
		func(c ldapConfig) any { return c.Public() },
		"ldap config updated",
		func(c ldapConfig) map[string]any { return map[string]any{"enabled": c.Enabled, "host": c.Host} })
}

// handleLDAPTest: POST /api/auth/ldap/test (admin-gated). With no body it checks
// connectivity + the service bind; with {username,password} it runs a full
// authentication and previews the resolved DN, groups and assigned role.
func (s *server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.ldap.effective().Test(req.Username, req.Password))
}

// ---------------------------------------------------------------------------
// TACACS+ config store
// ---------------------------------------------------------------------------

// tacacsConfig is the serialisable TACACS+ provider configuration. The runtime
// client (*TACACS) is built from it via client().
type tacacsConfig struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Secret         string `json:"secret,omitempty"` // write-only: persisted to the kv store (UI-configurable); never returned by public()
	TimeoutSeconds int    `json:"timeout_seconds"`
	DefaultRole    string `json:"default_role"`
	DefaultTenant  string `json:"default_tenant"`
}

func newTACACSConfigFromEnv() tacacsConfig {
	port := 49
	if v := strings.TrimSpace(envOr("TACACS_PORT", "49")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	timeout := 5
	if d := durEnv("TACACS_TIMEOUT", 5*time.Second); d > 0 {
		timeout = int(d.Seconds())
	}
	return tacacsConfig{
		Enabled:        os.Getenv("TACACS_ENABLED") == "true" && os.Getenv("TACACS_HOST") != "",
		Host:           os.Getenv("TACACS_HOST"),
		Port:           port,
		Secret:         os.Getenv("TACACS_SECRET"),
		TimeoutSeconds: timeout,
		DefaultRole:    envOr("TACACS_DEFAULT_ROLE", RoleReadOnly),
		DefaultTenant:  os.Getenv("TACACS_DEFAULT_TENANT"),
	}
}

func (c tacacsConfig) Normalize() tacacsConfig {
	c.Host = strings.TrimSpace(c.Host)
	if c.Port == 0 {
		c.Port = 49
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 5
	}
	if strings.TrimSpace(c.DefaultRole) == "" {
		c.DefaultRole = RoleReadOnly
	}
	return c
}

func (c tacacsConfig) Validate() error {
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("tacacs: port out of range (0-65535)")
	}
	if c.Enabled && c.Host == "" {
		return errors.New("tacacs: host is required when enabled")
	}
	return nil
}

// client builds the runtime *TACACS from the config.
func (c tacacsConfig) client() *TACACS {
	port := c.Port
	if port == 0 {
		port = 49
	}
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	role := c.DefaultRole
	if strings.TrimSpace(role) == "" {
		role = RoleReadOnly
	}
	return tacacs.New(
		net.JoinHostPort(c.Host, strconv.Itoa(port)),
		c.Secret,
		timeout,
		c.Enabled && c.Host != "",
		role,
		c.DefaultTenant,
	)
}

type tacacsConfigStore struct {
	mu    sync.RWMutex
	cfg   *tacacsConfig
	path  string
	vault *vault.Vault // secret-custody envelope for the shared secret at rest (nil = dormant)
	// loadErr: the stored shared secret could not be unsealed — see ldapConfigStore.
	loadErr error
}

func newTACACSConfigStore(path string, v *vault.Vault) *tacacsConfigStore {
	s := &tacacsConfigStore{path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		logError("tacacs.config", "stored TACACS+ config unreadable — TACACS+ sign-in falls back to the env defaults", errf(err))
	}
	return s
}

// load reads the stored TACACS+ overlay via loadSealedKVConfig (three states,
// never two).
func (s *tacacsConfigStore) load() error {
	c, err := loadSealedKVConfig(s.path, "TACACS", "tacacs.config", "TACACS shared secret",
		func(c tacacsConfig) (tacacsConfig, error) { return mapTACACS(c, openFn(s.vault)) },
		func(c *tacacsConfig) { c.Secret = "" })
	if c != nil {
		s.mu.Lock()
		s.cfg = c
		s.mu.Unlock()
	}
	return err
}

func (s *tacacsConfigStore) effective() tacacsConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c == nil {
		return newTACACSConfigFromEnv()
	}
	return *c
}

func (s *tacacsConfigStore) set(in tacacsConfig) (tacacsConfig, error) {
	in = in.Normalize()
	if err := in.Validate(); err != nil {
		return tacacsConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Secret == "" && s.cfg != nil {
		if s.loadErr != nil {
			return tacacsConfig{}, errors.New("the stored shared secret could not be read — re-enter it with this save")
		}
		in.Secret = s.cfg.Secret
	}
	// #nosec G117 -- the TACACS shared secret is intentionally persisted to the kv
	// store so the provider is UI-configurable; it is redacted from every API
	// response by publicTACACSConfig and never logged. Encrypted at rest under the
	// platform DEK; the in-memory copy below stays plaintext for the client.
	if err := persistSealedKVConfig(s.path, in, func(c tacacsConfig) (tacacsConfig, error) {
		return mapTACACS(c, sealFn(s.vault))
	}); err != nil {
		return tacacsConfig{}, err
	}
	stored := in
	s.cfg = &stored
	s.loadErr = nil // a successful save IS the repair
	return stored, nil
}

type publicTACACSConfig struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	SecretSet      bool   `json:"secret_set"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	DefaultRole    string `json:"default_role"`
	DefaultTenant  string `json:"default_tenant"`
}

func (c tacacsConfig) Public() publicTACACSConfig {
	return publicTACACSConfig{
		Enabled:        c.Enabled,
		Host:           c.Host,
		Port:           c.Port,
		SecretSet:      c.Secret != "",
		TimeoutSeconds: c.TimeoutSeconds,
		DefaultRole:    c.DefaultRole,
		DefaultTenant:  c.DefaultTenant,
	}
}

// handleTACACSConfig: GET/PUT /api/auth/tacacs/config (admin-gated).
func (s *server) handleTACACSConfig(w http.ResponseWriter, r *http.Request) {
	handleProviderConfig(s, w, r, s.tacacs.effective, s.tacacs.set,
		func(c tacacsConfig) any { return c.Public() },
		"tacacs config updated",
		func(c tacacsConfig) map[string]any { return map[string]any{"enabled": c.Enabled, "host": c.Host} })
}

type tacacsTestResult struct {
	OK           bool   `json:"ok"`
	Stage        string `json:"stage"` // config|connect|auth|done
	Message      string `json:"message"`
	AssignedRole string `json:"assigned_role,omitempty"`
}

// handleTACACSTest: POST /api/auth/tacacs/test (admin-gated). With no body it
// checks TCP connectivity; with {username,password} it runs a full PAP auth and
// previews the assigned role.
func (s *server) handleTACACSTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.tacacs.effective()
	if !cfg.Enabled || cfg.Host == "" {
		writeJSON(w, http.StatusOK, tacacsTestResult{Stage: "config", Message: "TACACS+ is not enabled"})
		return
	}
	client := cfg.client()
	// Connectivity-only probe when no sample user was supplied.
	if strings.TrimSpace(req.Username) == "" {
		conn, err := net.DialTimeout("tcp", client.Addr(), client.Timeout())
		if err != nil {
			writeJSON(w, http.StatusOK, tacacsTestResult{Stage: "connect", Message: "connect failed: " + err.Error()})
			return
		}
		_ = conn.Close() // best-effort: probe socket; nothing actionable on close failure
		writeJSON(w, http.StatusOK, tacacsTestResult{OK: true, Stage: "connect", Message: "TCP connect to " + client.Addr() + " OK (supply a username to test authentication)"})
		return
	}
	ok, err := client.Authenticate(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusOK, tacacsTestResult{Stage: "auth", Message: err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, tacacsTestResult{Stage: "auth", Message: "authentication rejected (FAIL)"})
		return
	}
	writeJSON(w, http.StatusOK, tacacsTestResult{OK: true, Stage: "done", Message: "authentication succeeded", AssignedRole: cfg.DefaultRole})
}

// ---------------------------------------------------------------------------
// Public auth-methods discovery
// ---------------------------------------------------------------------------

// handleAuthMethods: GET /api/auth/methods (public). Tells the login page which
// sign-in options to render: local always; native LDAP/TACACS when enabled; and
// the Keycloak-brokered SSO buttons. No secrets are exposed.
//
// LOCATOR-AWARE (design §6.1, tracker 276): when the caller arrived through a
// per-tenant sign-in URL, the signed candidate cookie names the realm and the
// SSO button list is filtered to the connections that realm reaches — a tenant
// never sees another tenant's identity providers. With no locator the answer is
// unchanged (every configured button), because the bare sign-in page is the
// platform's own front door and every existing deployment depends on it.
func (s *server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	ldap := s.ldap.effective()
	tac := s.tacacs.effective()
	resp := map[string]any{
		"local":  true,
		"ldap":   map[string]any{"enabled": ldap.Enabled, "name": "LDAP / Active Directory"},
		"tacacs": map[string]any{"enabled": tac.Enabled, "name": "TACACS+"},
	}
	var cand *tenantlocator.Candidate
	if c, ok := s.locatorCandidate(r); ok {
		cand = &c
		resp["locator"] = locatorPublic(c)
	}
	if op := s.oidcProvider(); op.Ready() {
		all := op.Providers()
		shown := make([]ssoProviderInfo, 0, len(all))
		for _, pi := range all {
			if s.providerVisible(cand, pi.ID) {
				shown = append(shown, pi)
			}
		}
		resp["sso"] = map[string]any{"enabled": true, "providers": shown}
	} else {
		resp["sso"] = map[string]any{"enabled": false, "providers": []ssoProviderInfo{}}
	}
	writeJSON(w, http.StatusOK, resp)
}

// providerRealm reports the realm a sign-in button belongs to: the tenant its
// connection is BOUND to and that tenant's org. A blank tenant is the PLATFORM
// realm — an unbound connection, or a button that has no stored connection at
// all (the env-configured OIDC_PROVIDERS entries) — offered everywhere.
//
// ok=false means the connection names a tenant that no longer exists. That
// button is then offered to NOBODY: a dangling binding fails closed rather than
// decaying into "platform realm", which would silently republish a decommissioned
// customer's identity provider on every other customer's sign-in page.
func (s *server) providerRealm(alias string) (tenantID, orgID string, ok bool) {
	if s.ssoIdPCfg == nil {
		return "", "", true
	}
	reg, found := s.ssoIdPCfg.Get(strings.ToLower(strings.TrimSpace(alias)))
	if !found {
		return "", "", true
	}
	tid := reg.Realm()
	if tid == "" {
		return "", "", true
	}
	if s.tenants == nil {
		return "", "", false
	}
	t, found := s.tenants.Get(tid)
	if !found {
		return "", "", false
	}
	return tid, orgOf(t), true
}

// providerVisible answers whether a sign-in button is offered at a candidate.
// A nil candidate is the generic sign-in page — unchanged behaviour, every
// configured button.
func (s *server) providerVisible(c *tenantlocator.Candidate, alias string) bool {
	tid, org, ok := s.providerRealm(alias)
	if !ok {
		return false
	}
	if c == nil {
		return true
	}
	return c.Reaches(tid, org)
}

// ---------------------------------------------------------------------------
// Login locators — per-tenant sign-in URLs (design §6.1, tracker 276)
// ---------------------------------------------------------------------------
//
// A customer hands its people ONE URL. Two shapes exist today:
//
//	/t/{tenant-slug}          shared_path — the slug is a display ALIAS
//	/org/{org_public_id}      immutable_org_url — opaque, survives a rename
//
// `managed_subdomain` and `custom_domain` are reserved names and DEFERRED: they
// need a Correlix-operated DNS/TLS plane a single-port compose product does not
// have. See internal/tenantlocator.
//
// HOW THE PIECES FIT (and why the SPA stays a static bundle): nginx already
// history-falls-back every unknown path to index.html, so /t/{slug} serves the
// ordinary SPA with no nginx route of its own. The SPA then asks the api
// GET /api/auth/locator?path=/t/{slug}; the api resolves the slug to the
// IMMUTABLE tenant id, hands back the display name, and sets a signed,
// short-lived, HttpOnly cookie carrying that id. From then on the raw URL is
// never trusted for anything: the cookie is what /api/auth/methods filters the
// provider list by, and what the per-tenant SSO callback is bound against.
//
// A CANDIDATE IS NOT A CLAIM. It decides which doors to show and which callback
// URL is legitimate. It never grants access, never sets a session tenant, and
// never moves an account between tenants.

// loginLocatorCookie carries the SIGNED candidate: locator kind + immutable id,
// nothing else. HttpOnly (the SPA has no business reading it) and short-lived.
const loginLocatorCookie = "netops_login_locator"

// locatorDirectory adapts the tenant + org registries onto the resolver's seam.
// It is deliberately list-shaped: the resolver scans everything on every call so
// an unknown slug and a suspended tenant cost the same (no enumeration oracle).
type locatorDirectory struct{ s *server }

func (d locatorDirectory) Tenants() []tenantlocator.TenantRef {
	if d.s == nil || d.s.tenants == nil {
		return nil
	}
	list := d.s.tenants.List()
	out := make([]tenantlocator.TenantRef, 0, len(list))
	for _, t := range list {
		out = append(out, tenantlocator.TenantRef{
			ID: t.ID, Slug: t.Slug, Name: t.Name, OrgID: orgOf(t), Status: t.EffectiveStatus(),
		})
	}
	return out
}

func (d locatorDirectory) Orgs() []tenantlocator.OrgRef {
	if d.s == nil || d.s.orgs == nil {
		return nil
	}
	list := d.s.orgs.List()
	out := make([]tenantlocator.OrgRef, 0, len(list))
	for _, o := range list {
		out = append(out, tenantlocator.OrgRef{ID: o.ID, Slug: o.Slug, Name: o.Name})
	}
	return out
}

// locatorDir is the resolver seam for this server.
func (s *server) locatorDir() tenantlocator.Directory { return locatorDirectory{s: s} }

// locatorSigner derives the candidate-cookie MAC key from the platform signing
// secret. Derived per call (one SHA-256) rather than held on the server so a
// rotated JWT_SECRET invalidates outstanding candidate cookies exactly like it
// invalidates sessions, with no second key to rotate.
func (s *server) locatorSigner() *tenantlocator.Signer {
	return tenantlocator.NewSigner(jwtSecret())
}

// setLocatorCookie mints and sets the signed candidate cookie.
func (s *server) setLocatorCookie(w http.ResponseWriter, r *http.Request, c tenantlocator.Candidate) {
	tok, err := s.locatorSigner().Mint(c, time.Now())
	if err != nil {
		// Nothing to hand the browser: fall through with no cookie, which lands
		// the caller on the generic sign-in rather than a wrong tenant's.
		logWarn("auth", "login locator not minted", map[string]any{"kind": c.Kind})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginLocatorCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(tenantlocator.TTL / time.Second),
	})
}

// clearLocatorCookie expires the candidate cookie with the SAME attributes it
// was set with (a delete is a Set with MaxAge<0, and a browser rejects a Secure
// cookie arriving over plain HTTP), so a stale candidate cannot survive an
// unresolvable entry URL.
func (s *server) clearLocatorCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: loginLocatorCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: cookieSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// locatorCandidate re-resolves the candidate carried by the request's cookie.
// The signature proves the id came from us; the re-resolution proves the realm
// still exists and is still active, so suspending a tenant takes effect on the
// next request instead of at cookie expiry. ok=false means "no candidate" — the
// generic sign-in, never a fallback tenant.
func (s *server) locatorCandidate(r *http.Request) (tenantlocator.Candidate, bool) {
	ck, err := r.Cookie(loginLocatorCookie)
	if err != nil {
		// No candidate cookie at all — the ordinary generic sign-in page. Kept
		// separate from the blank-value branch below: they are two different
		// events (never arrived vs. deliberately cleared) and collapsing them
		// is exactly the conflation the silent-failure guard forbids.
		return tenantlocator.Candidate{}, false
	}
	if ck.Value == "" {
		// Present but blank: a candidate this server EXPIRED, which is what an
		// unresolvable entry URL does. Also no candidate.
		return tenantlocator.Candidate{}, false
	}
	claim, err := s.locatorSigner().Verify(ck.Value, time.Now())
	if err != nil {
		return tenantlocator.Candidate{}, false
	}
	return tenantlocator.ResolveID(s.locatorDir(), claim.Kind, claim.ID)
}

// locatorPublic is the sign-in page's view of a resolved candidate: a display
// name and the canonical path, never an id the browser could then assert.
func locatorPublic(c tenantlocator.Candidate) map[string]any {
	return map[string]any{"kind": c.Kind, "name": c.DisplayName, "path": c.Path()}
}

// handleAuthLocator: GET /api/auth/locator?path=/t/{slug} (public). Resolves the
// entry URL to a candidate realm and arms the signed candidate cookie.
//
// NO INFORMATION LEAK: an unknown locator and a locator naming a suspended
// tenant get the byte-identical `{"locator":null}` answer, and the resolver does
// the identical amount of work for both (internal/tenantlocator.Resolve), so
// neither the body nor the clock distinguishes "no such customer" from "that
// customer is suspended". Both also CLEAR any stale candidate cookie, so a
// wrong entry URL can never leave an earlier tenant's doors on screen.
func (s *server) handleAuthLocator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := r.URL.Query().Get("path")
	if len(raw) > 256 { // untrusted: bound it before it is parsed or logged
		raw = raw[:256]
	}
	kind, ref, ok := tenantlocator.ParsePath(raw)
	if !ok {
		s.clearLocatorCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"locator": nil})
		return
	}
	c, ok := tenantlocator.Resolve(s.locatorDir(), kind, ref)
	if !ok {
		s.clearLocatorCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"locator": nil})
		return
	}
	s.setLocatorCookie(w, r, c)
	writeJSON(w, http.StatusOK, map[string]any{"locator": locatorPublic(c)})
}
