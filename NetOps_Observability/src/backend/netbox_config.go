package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
	"strings"
	"sync"
)

// netbox_config.go — runtime configuration for the NetBox Source-of-Truth
// discovery integration (Automation → Source of Truth in the UI). Previously
// NetBox was env-only (NETBOX_URL/NETBOX_TOKEN); operators can now configure it
// from the admin UI. The API token is a reversible secret, encrypted at rest via
// the secret-custody vault.Vault (platform DEK, like the notify/OIDC/LDAP secrets) and
// never returned to the client. Platform-owner scoped: discovery is platform
// infrastructure, not a per-tenant concern.

// netboxConfig moved to internal/discovery (the source reads it); the store
// and direction doctrine stay here.
type netboxConfig = discovery.NetboxConfig

type netboxConfigStore struct {
	mu    sync.RWMutex
	cfg   *netboxConfig
	path  string
	vault *vault.Vault
}

func newNetboxConfigStore(path string, v *vault.Vault) *netboxConfigStore {
	s := &netboxConfigStore{path: path, vault: v}
	s.load()
	return s
}

func (s *netboxConfigStore) load() {
	b, err := platformdb.Load(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c netboxConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	// Decrypt the token (no-op when the vault.Vault is dormant / nil).
	if out, err := mapNetbox(c, openFn(s.vault)); err == nil {
		c = out
	}
	s.cfg = &c
}

// effective resolves the live config, internal-first:
//   - an explicitly UI-configured EXTERNAL NetBox (stored cfg with its own URL)
//     wins and is used as-is;
//   - otherwise, if the platform ships a bundled internal NetBox
//     (NETBOX_INTERNAL_URL set, with the seeded NETBOX_TOKEN), that MANAGED
//     connection is used — URL/token are auto-wired, only the enable toggle is
//     stored;
//   - else a legacy env external (NETBOX_URL/NETBOX_TOKEN) keeps working.
func (s *netboxConfigStore) effective() netboxConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()

	if c != nil && strings.TrimSpace(c.URL) != "" {
		return *c // UI-configured external instance
	}
	if internal := strings.TrimRight(os.Getenv("NETBOX_INTERNAL_URL"), "/"); internal != "" {
		enabled, interval, direction := true, 0, ""
		if c != nil { // stored enable/interval/direction override for the managed connector
			enabled, interval, direction = c.Enabled, c.IntervalSec, c.Direction
		}
		return netboxConfig{Enabled: enabled, URL: internal, Token: os.Getenv("NETBOX_TOKEN"), IntervalSec: interval, Managed: true, Direction: direction}
	}
	if tok := os.Getenv("NETBOX_TOKEN"); tok != "" && os.Getenv("NETBOX_URL") != "" {
		return netboxConfig{Enabled: true, URL: os.Getenv("NETBOX_URL"), Token: tok}
	}
	if c != nil {
		return *c
	}
	return netboxConfig{}
}

func (s *netboxConfigStore) set(in netboxConfig) (netboxConfig, error) {
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	in.Managed = false                           // never persisted; derived in effective()
	in.Direction = discovery.NetboxDirection(in) // normalize ("" → "none")
	if in.URL != "" {
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return netboxConfig{}, errors.New("NetBox URL must be a valid http(s):// URL")
		}
	} else if in.Enabled && os.Getenv("NETBOX_INTERNAL_URL") == "" {
		// No URL and no bundled NetBox to fall back on.
		return netboxConfig{}, errors.New("NetBox URL is required (no bundled NetBox is available)")
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
	if err := platformdb.Save(s.path, b); err != nil {
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
	Managed     bool   `json:"managed"`   // bundled internal NetBox (no URL/token needed)
	Direction   string `json:"direction"` // "none" | "write" | "read" | "both" (normalized)
}

func netboxPublic(c netboxConfig) publicNetboxConfig {
	return publicNetboxConfig{Enabled: c.Enabled, URL: c.URL, IntervalSec: c.IntervalSec, TokenSet: c.Token != "", Managed: c.Managed, Direction: discovery.NetboxDirection(c)}
}

// netboxDirection normalizes the configured sync direction. The default is
// "none": automatic device sync is OFF until an operator opts in, so a fresh
// install never auto-populates the bundled inventory off discovery (NetBox's
// product role is still being decided; don't push data into it by default).
// Operators choose "write" (devices → NetBox only; never read back, no
// duplicates), "read" (NetBox is the authoritative intent SoT), or "both".

// netboxReadsDevices reports whether NetBox should be polled as a device source
// (read or both). netboxWritesDevices reports whether discovered devices should
// be reconciled up into NetBox (write or both).

// handleNetboxConfig serves GET/PUT /api/automation/netbox (platform-owner only).
func (s *server) handleNetboxConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": netboxPublic(s.netboxCfg.effective())})
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
		writeJSON(w, http.StatusOK, map[string]any{"config": netboxPublic(out)})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
