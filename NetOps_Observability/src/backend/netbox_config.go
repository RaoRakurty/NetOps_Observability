// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	// unreadable is set when the config file EXISTS but its contents could not
	// be established — an I/O or permission failure, or JSON we could not parse.
	// It is NOT set for an absent file, which simply means NetBox was never
	// configured from the UI.
	//
	// THIS STORE RECOVERS RATHER THAN REFUSES, and it is a deliberate exception
	// alongside the drift register. Everywhere the file holds many owners' rows
	// — seven notification channels, every tenant's watchlist, a register of
	// sealed blobs — a write over contents we never read is refused, because it
	// would silently delete rows the operator was not editing. Here the file
	// holds ONE object that the admin PUT replaces WHOLE, so an operator who
	// re-enters the connection is performing the repair, not losing somebody
	// else's data.
	//
	// The recovery is explicit, not silent: the failure is logged at load, the
	// GET reports it so the UI cannot render "not configured" as truth, and the
	// one shortcut that WOULD lose a secret — a blank token meaning "keep the
	// stored one" — is refused, because there is no stored one we can read.
	unreadable error
}

func newNetboxConfigStore(path string, v *vault.Vault) *netboxConfigStore {
	s := &netboxConfigStore{path: path, vault: v}
	s.load()
	return s
}

func (s *netboxConfigStore) load() {
	b, err := platformdb.Load(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return // never configured from the UI; the env/managed paths still apply
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folded together, the store read as "NetBox
		// was never configured" — discovery silently stopped using it — and the
		// next admin save wrote over a file nobody had read.
		s.unreadable = fmt.Errorf("read NetBox config %s: %w", s.path, err)
		logError("netbox.config", "stored NetBox config could not be read; it reads as NOT CONFIGURED and the next save will REPLACE the file",
			map[string]any{"error": err.Error(), "path": s.path})
		return
	case len(b) == 0:
		return // present but empty: nothing stored yet, nothing broken
	}
	var c netboxConfig
	if uerr := json.Unmarshal(b, &c); uerr != nil {
		s.unreadable = fmt.Errorf("decode NetBox config %s: %w", s.path, uerr)
		logError("netbox.config", "stored NetBox config could not be parsed; it reads as NOT CONFIGURED and the next save will REPLACE the file",
			map[string]any{"error": uerr.Error(), "path": s.path})
		return
	}
	// Decrypt the token (no-op when the vault.Vault is dormant / nil).
	if out, err := mapNetbox(c, openFn(s.vault)); err == nil {
		c = out
	}
	s.cfg = &c
}

// unavailable reports why the stored config could not be read, or nil. The GET
// discloses it so the form cannot present "not configured" as the stored truth.
func (s *netboxConfigStore) unavailable() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unreadable
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
	if in.Token == "" && s.unreadable != nil && in.URL != "" {
		// There is no stored token we can read, so "leave it as it is" would
		// quietly save an EMPTY token and the redacted form would report the
		// connection as configured. Make the operator say what the token is.
		return netboxConfig{}, fmt.Errorf("the stored NetBox config could not be read, so the saved API token cannot be reused — enter the token again: %w", s.unreadable)
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
	if s.unreadable != nil {
		// The repair: this PUT replaces the whole object, which is exactly what
		// the file holds, so the operator's explicit save is allowed to stand in
		// for the unreadable one. Say so rather than let it pass silently.
		logError("netbox.config", "an operator save REPLACED the NetBox config file that could not be read at start-up",
			map[string]any{"path": s.path})
		s.unreadable = nil
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
		out := map[string]any{"config": netboxPublic(s.netboxCfg.effective())}
		if err := s.netboxCfg.unavailable(); err != nil {
			// An unreadable store must never render as a deliberate "not
			// configured": the operator sees UNKNOWN plus the reason (the
			// verification-settings precedent).
			out["config_unavailable"] = true
			out["config_error"] = "the stored NetBox config could not be read — what is shown is not the stored state, and saving will replace the file"
		}
		writeJSON(w, http.StatusOK, out)
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
