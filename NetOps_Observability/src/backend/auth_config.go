package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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
// LDAP config store
// ---------------------------------------------------------------------------

type ldapConfigStore struct {
	mu    sync.RWMutex
	cfg   *ldapConfig // nil until an operator saves; falls back to env defaults
	path  string
	vault *Vault // secret-custody envelope for bind_password at rest (nil = dormant/passthrough)
}

func newLDAPConfigStore(path string, v *Vault) *ldapConfigStore {
	s := &ldapConfigStore{path: path, vault: v}
	s.load()
	return s
}

func (s *ldapConfigStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c ldapConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if dec, derr := mapLDAP(c, openFn(s.vault)); derr != nil {
		logError("ldap.config", "decrypt secret", errf(derr))
	} else {
		c = dec
	}
	s.mu.Lock()
	s.cfg = &c
	s.mu.Unlock()
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
	in.normalize()
	if err := in.validate(); err != nil {
		return ldapConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.BindPassword == "" && s.cfg != nil {
		in.BindPassword = s.cfg.BindPassword
	}
	sealed, err := mapLDAP(in, sealFn(s.vault)) // encrypt at rest; in-memory stays plaintext
	if err != nil {
		return ldapConfig{}, err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return ldapConfig{}, err
	}
	if err := kvSave(s.path, b); err != nil {
		return ldapConfig{}, err
	}
	stored := in
	s.cfg = &stored
	return stored, nil
}

// normalize trims and defaults fields so stored config is canonical.
func (c *ldapConfig) normalize() {
	c.Host = strings.TrimSpace(c.Host)
	c.BindDN = strings.TrimSpace(c.BindDN)
	c.BaseDN = strings.TrimSpace(c.BaseDN)
	c.UserFilter = strings.TrimSpace(c.UserFilter)
	if c.UserFilter == "" {
		c.UserFilter = "(uid=%s)"
	}
	c.GroupBaseDN = strings.TrimSpace(c.GroupBaseDN)
	c.GroupFilter = strings.TrimSpace(c.GroupFilter)
	if strings.TrimSpace(c.DefaultRole) == "" {
		c.DefaultRole = RoleReadOnly
	}
	if strings.TrimSpace(c.DefaultTenant) == "" {
		c.DefaultTenant = TenantGlobal
	}
	cleaned := make([]ldapRoleMapping, 0, len(c.RoleMappings))
	for _, m := range c.RoleMappings {
		m.Group = strings.TrimSpace(m.Group)
		m.Role = strings.TrimSpace(m.Role)
		if m.Group != "" && m.Role != "" {
			cleaned = append(cleaned, m)
		}
	}
	c.RoleMappings = cleaned
}

// validate enforces the invariants required for an enabled LDAP provider.
func (c ldapConfig) validate() error {
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("ldap: port out of range (0-65535)")
	}
	if c.UseTLS && c.StartTLS {
		return errors.New("ldap: use_tls (LDAPS) and start_tls are mutually exclusive")
	}
	if !c.Enabled {
		return nil
	}
	if c.Host == "" {
		return errors.New("ldap: host is required when enabled")
	}
	if c.BaseDN == "" {
		return errors.New("ldap: base_dn is required when enabled")
	}
	if !strings.Contains(c.UserFilter, "%s") {
		return errors.New("ldap: user_filter must contain the %s username placeholder")
	}
	return nil
}

// publicLDAPConfig is the redacted view returned by GET: the bind password is
// replaced by a boolean so the secret never leaves the server.
type publicLDAPConfig struct {
	Enabled            bool              `json:"enabled"`
	Host               string            `json:"host"`
	Port               int               `json:"port"`
	UseTLS             bool              `json:"use_tls"`
	StartTLS           bool              `json:"start_tls"`
	BindDN             string            `json:"bind_dn"`
	BindPasswordSet    bool              `json:"bind_password_set"`
	BaseDN             string            `json:"base_dn"`
	UserFilter         string            `json:"user_filter"`
	GroupBaseDN        string            `json:"group_base_dn"`
	GroupFilter        string            `json:"group_filter"`
	RoleMappings       []ldapRoleMapping `json:"role_mappings"`
	DefaultRole        string            `json:"default_role"`
	DefaultTenant      string            `json:"default_tenant"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
}

func (c ldapConfig) public() publicLDAPConfig {
	rm := c.RoleMappings
	if rm == nil {
		rm = []ldapRoleMapping{} // never emit JSON null — the UI maps over this
	}
	return publicLDAPConfig{
		Enabled:            c.Enabled,
		Host:               c.Host,
		Port:               c.Port,
		UseTLS:             c.UseTLS,
		StartTLS:           c.StartTLS,
		BindDN:             c.BindDN,
		BindPasswordSet:    c.BindPassword != "",
		BaseDN:             c.BaseDN,
		UserFilter:         c.UserFilter,
		GroupBaseDN:        c.GroupBaseDN,
		GroupFilter:        c.GroupFilter,
		RoleMappings:       rm,
		DefaultRole:        c.DefaultRole,
		DefaultTenant:      c.DefaultTenant,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
}

// handleLDAPConfig: GET/PUT /api/auth/ldap/config (admin-gated). GET returns the
// redacted effective config; PUT validates and persists.
func (s *server) handleLDAPConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": s.ldap.effective().public()})
	case http.MethodPut:
		var in ldapConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.ldap.set(in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("auth", "ldap config updated", map[string]any{"enabled": out.Enabled, "host": out.Host})
		writeJSON(w, http.StatusOK, map[string]any{"config": out.public()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ldapTestResult is the structured outcome of a test-connection probe. The
// headline value operators care about is assigned_role: "what role would this
// user get" (the Okta UX pattern).
type ldapTestResult struct {
	OK           bool     `json:"ok"`
	Stage        string   `json:"stage"` // config|connect|service_bind|user_search|user_bind|done
	Message      string   `json:"message"`
	ResolvedDN   string   `json:"resolved_dn,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	AssignedRole string   `json:"assigned_role,omitempty"`
}

// handleLDAPTest: POST /api/auth/ldap/test (admin-gated). With no body it checks
// connectivity + the service bind; with {username,password} it runs a full
// authentication and previews the resolved DN, groups and assigned role.
func (s *server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
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
	writeJSON(w, http.StatusOK, s.ldap.effective().test(req.Username, req.Password))
}

// test probes the directory. It never returns an error to the caller — every
// outcome is encoded in the result so the UI can show exactly where it failed.
func (c ldapConfig) test(username, password string) ldapTestResult {
	if !c.Enabled {
		return ldapTestResult{Stage: "config", Message: "LDAP is not enabled"}
	}
	if c.Host == "" || c.BaseDN == "" {
		return ldapTestResult{Stage: "config", Message: "host and base_dn are required"}
	}
	conn, err := c.dial()
	if err != nil {
		return ldapTestResult{Stage: "connect", Message: "connect failed: " + err.Error()}
	}
	defer conn.Close()
	if c.BindDN != "" {
		if err := conn.simpleBind(c.BindDN, c.BindPassword); err != nil {
			return ldapTestResult{Stage: "service_bind", Message: "service bind failed: " + err.Error()}
		}
	}
	// Connectivity-only probe when no sample user was supplied.
	if strings.TrimSpace(username) == "" {
		msg := "connected; service bind OK"
		if c.BindDN == "" {
			msg = "connected (anonymous; no service bind configured)"
		}
		return ldapTestResult{OK: true, Stage: "service_bind", Message: msg}
	}
	id, err := c.authenticate(username, password)
	if err != nil {
		return ldapTestResult{Stage: "user_bind", Message: err.Error()}
	}
	role := ldapRoleFor(id.Groups, c.RoleMappings, c.DefaultRole)
	return ldapTestResult{
		OK:           true,
		Stage:        "done",
		Message:      "authentication succeeded",
		ResolvedDN:   id.DN,
		Groups:       id.Groups,
		AssignedRole: role,
	}
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

func (c tacacsConfig) normalize() tacacsConfig {
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

func (c tacacsConfig) validate() error {
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
	return &TACACS{
		addr:        net.JoinHostPort(c.Host, strconv.Itoa(port)),
		secret:      c.Secret,
		timeout:     timeout,
		enabled:     c.Enabled && c.Host != "",
		defaultRole: role,
		tenant:      c.DefaultTenant,
	}
}

type tacacsConfigStore struct {
	mu    sync.RWMutex
	cfg   *tacacsConfig
	path  string
	vault *Vault // secret-custody envelope for the shared secret at rest (nil = dormant)
}

func newTACACSConfigStore(path string, v *Vault) *tacacsConfigStore {
	s := &tacacsConfigStore{path: path, vault: v}
	s.load()
	return s
}

func (s *tacacsConfigStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c tacacsConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if dec, derr := mapTACACS(c, openFn(s.vault)); derr != nil {
		logError("tacacs.config", "decrypt secret", errf(derr))
	} else {
		c = dec
	}
	s.mu.Lock()
	s.cfg = &c
	s.mu.Unlock()
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
	in = in.normalize()
	if err := in.validate(); err != nil {
		return tacacsConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Secret == "" && s.cfg != nil {
		in.Secret = s.cfg.Secret
	}
	// #nosec G117 -- the TACACS shared secret is intentionally persisted to the kv
	// store so the provider is UI-configurable; it is redacted from every API
	// response by publicTACACSConfig and never logged. Encrypted at rest under the
	// platform DEK; the in-memory copy below stays plaintext for the client.
	sealed, err := mapTACACS(in, sealFn(s.vault))
	if err != nil {
		return tacacsConfig{}, err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return tacacsConfig{}, err
	}
	if err := kvSave(s.path, b); err != nil {
		return tacacsConfig{}, err
	}
	stored := in
	s.cfg = &stored
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

func (c tacacsConfig) public() publicTACACSConfig {
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
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": s.tacacs.effective().public()})
	case http.MethodPut:
		var in tacacsConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.tacacs.set(in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("auth", "tacacs config updated", map[string]any{"enabled": out.Enabled, "host": out.Host})
		writeJSON(w, http.StatusOK, map[string]any{"config": out.public()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
	if _, ok := s.requireAdmin(w, r); !ok {
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
		conn, err := net.DialTimeout("tcp", client.addr, client.timeout)
		if err != nil {
			writeJSON(w, http.StatusOK, tacacsTestResult{Stage: "connect", Message: "connect failed: " + err.Error()})
			return
		}
		_ = conn.Close()
		writeJSON(w, http.StatusOK, tacacsTestResult{OK: true, Stage: "connect", Message: "TCP connect to " + client.addr + " OK (supply a username to test authentication)"})
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
func (s *server) handleAuthMethods(w http.ResponseWriter, _ *http.Request) {
	ldap := s.ldap.effective()
	tac := s.tacacs.effective()
	resp := map[string]any{
		"local":  true,
		"ldap":   map[string]any{"enabled": ldap.Enabled, "name": "LDAP / Active Directory"},
		"tacacs": map[string]any{"enabled": tac.Enabled, "name": "TACACS+"},
	}
	if op := s.oidcProvider(); op.ready() {
		resp["sso"] = map[string]any{"enabled": true, "providers": op.providers}
	} else {
		resp["sso"] = map[string]any{"enabled": false, "providers": []ssoProviderInfo{}}
	}
	writeJSON(w, http.StatusOK, resp)
}
