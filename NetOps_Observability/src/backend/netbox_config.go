package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// netbox_config.go — runtime configuration for the NetBox Source-of-Truth
// discovery integration (Automation → Source of Truth in the UI). Previously
// NetBox was env-only (NETBOX_URL/NETBOX_TOKEN); operators can now configure it
// from the admin UI. The API token is a reversible secret, encrypted at rest via
// the secret-custody Vault (platform DEK, like the notify/OIDC/LDAP secrets) and
// never returned to the client. Platform-owner scoped: discovery is platform
// infrastructure, not a per-tenant concern.

type netboxConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Token       string `json:"token,omitempty"`
	IntervalSec int    `json:"interval_sec"` // poll cadence; 0 → default 60s
}

type netboxConfigStore struct {
	mu    sync.RWMutex
	cfg   *netboxConfig
	path  string
	vault *Vault
}

func newNetboxConfigStore(path string, v *Vault) *netboxConfigStore {
	s := &netboxConfigStore{path: path, vault: v}
	s.load()
	return s
}

func (s *netboxConfigStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c netboxConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	// Decrypt the token (no-op when the Vault is dormant / nil).
	if out, err := mapNetbox(c, openFn(s.vault)); err == nil {
		c = out
	}
	s.cfg = &c
}

// effective returns the live config: the stored config when present, else the
// env-var defaults (NETBOX_URL/NETBOX_TOKEN) so an env-configured deployment
// keeps working until something is saved from the UI.
func (s *netboxConfigStore) effective() netboxConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c != nil {
		return *c
	}
	if tok := os.Getenv("NETBOX_TOKEN"); tok != "" {
		return netboxConfig{Enabled: true, URL: os.Getenv("NETBOX_URL"), Token: tok}
	}
	return netboxConfig{}
}

func (s *netboxConfigStore) set(in netboxConfig) (netboxConfig, error) {
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	if in.Enabled {
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return netboxConfig{}, errors.New("NetBox URL must be a valid http(s):// URL")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A blank token on save preserves the stored one (the GET form is redacted and
	// doesn't round-trip the secret).
	if in.Token == "" && s.cfg != nil {
		in.Token = s.cfg.Token
	}
	sealed, err := mapNetbox(in, sealFn(s.vault)) // encrypt at rest; in-memory stays plaintext
	if err != nil {
		return netboxConfig{}, err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return netboxConfig{}, err
	}
	if err := kvSave(s.path, b); err != nil {
		return netboxConfig{}, err
	}
	stored := in
	s.cfg = &stored
	return stored, nil
}

// publicNetboxConfig is the redacted GET shape — the token is never echoed, only
// whether one is configured.
type publicNetboxConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	TokenSet    bool   `json:"token_set"`
}

func (c netboxConfig) public() publicNetboxConfig {
	return publicNetboxConfig{Enabled: c.Enabled, URL: c.URL, IntervalSec: c.IntervalSec, TokenSet: c.Token != ""}
}

// handleNetboxConfig serves GET/PUT /api/automation/netbox (platform-owner only).
func (s *server) handleNetboxConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": s.netboxCfg.effective().public()})
	case http.MethodPut:
		var in netboxConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.netboxCfg.set(in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": out.public()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
