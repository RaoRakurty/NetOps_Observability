package main

// snmp_creds.go — SNMP credential profiles (v1 / v2c / v3 USM).
//
// A device references a profile by name via Device.credential_ref; the poller
// resolves it to a community (v2c) or USM parameters (v3). Multiple profiles let
// different device groups use different communities/credentials. Secrets
// (community, auth key, priv key) are stored on disk (0600) but NEVER returned
// by the API — list/get responses redact them to booleans, like the existing
// /api/credentials endpoint. File-backed (snmp_credentials.json).
//
// Option set mirrors what SolarWinds NPM exposes for SNMP credentials.

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Allowed enum values (surfaced to the UI via /api/snmp/options).
var (
	SNMPVersions       = []string{"v1", "v2c", "v3"}
	SNMPSecurityLevels = []string{"noAuthNoPriv", "authNoPriv", "authPriv"}
	SNMPAuthProtocols  = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	SNMPPrivProtocols  = []string{"DES", "3DES", "AES128", "AES192", "AES256"}
)

func inList(v string, list []string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

type SNMPCredential struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TenantID string `json:"tenant_id,omitempty"` // owning tenant ("" = global/platform-owned)
	Version  string `json:"version"`             // v1 | v2c | v3
	Port    int    `json:"port"`    // default 161
	Timeout int    `json:"timeout_ms"`
	Retries int    `json:"retries"`

	// v1 / v2c
	Community string `json:"community,omitempty"` // secret

	// v3 (USM)
	SecurityName  string `json:"security_name,omitempty"`
	SecurityLevel string `json:"security_level,omitempty"` // noAuthNoPriv|authNoPriv|authPriv
	AuthProtocol  string `json:"auth_protocol,omitempty"`
	AuthKey       string `json:"auth_key,omitempty"` // secret
	PrivProtocol  string `json:"priv_protocol,omitempty"`
	PrivKey       string `json:"priv_key,omitempty"` // secret
	Context       string `json:"context,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// publicSNMPCredential redacts every secret to a boolean for safe display.
type publicSNMPCredential struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	TenantID      string    `json:"tenant_id,omitempty"`
	Version       string    `json:"version"`
	Port          int       `json:"port"`
	Timeout       int       `json:"timeout_ms"`
	Retries       int       `json:"retries"`
	HasCommunity  bool      `json:"has_community"`
	Community     string    `json:"community,omitempty"` // v1/v2c RO community — shown so operators can verify it (v3 USM keys stay masked below)
	SecurityName  string    `json:"security_name,omitempty"`
	SecurityLevel string    `json:"security_level,omitempty"`
	AuthProtocol  string    `json:"auth_protocol,omitempty"`
	HasAuthKey    bool      `json:"has_auth_key"`
	PrivProtocol  string    `json:"priv_protocol,omitempty"`
	HasPrivKey    bool      `json:"has_priv_key"`
	Context       string    `json:"context,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

func (c SNMPCredential) public() publicSNMPCredential {
	return publicSNMPCredential{
		ID: c.ID, Name: c.Name, TenantID: c.TenantID, Version: c.Version, Port: c.Port, Timeout: c.Timeout, Retries: c.Retries,
		HasCommunity: c.Community != "", Community: c.Community, SecurityName: c.SecurityName, SecurityLevel: c.SecurityLevel,
		AuthProtocol: c.AuthProtocol, HasAuthKey: c.AuthKey != "", PrivProtocol: c.PrivProtocol,
		HasPrivKey: c.PrivKey != "", Context: c.Context, CreatedAt: c.CreatedAt,
	}
}

func validateSNMPCredential(c *SNMPCredential) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("credential name required")
	}
	if !inList(c.Version, SNMPVersions) {
		return errors.New("version must be one of v1, v2c, v3")
	}
	if c.Port == 0 {
		c.Port = 161
	}
	if c.Timeout == 0 {
		c.Timeout = 2000
	}
	if c.Retries == 0 {
		c.Retries = 1
	}
	switch strings.ToLower(c.Version) {
	case "v1", "v2c":
		if c.Community == "" {
			return errors.New("community required for v1/v2c")
		}
	case "v3":
		if c.SecurityName == "" {
			return errors.New("security name required for v3")
		}
		if !inList(c.SecurityLevel, SNMPSecurityLevels) {
			return errors.New("invalid security level")
		}
		lvl := strings.ToLower(c.SecurityLevel)
		if lvl == "authnopriv" || lvl == "authpriv" {
			if !inList(c.AuthProtocol, SNMPAuthProtocols) {
				return errors.New("invalid auth protocol")
			}
			if c.AuthKey == "" {
				return errors.New("auth key required for this security level")
			}
		}
		if lvl == "authpriv" {
			if !inList(c.PrivProtocol, SNMPPrivProtocols) {
				return errors.New("invalid privacy protocol")
			}
			if c.PrivKey == "" {
				return errors.New("privacy key required for authPriv")
			}
		}
	}
	return nil
}

type snmpCredStore struct {
	mu    sync.RWMutex
	path  string
	creds map[string]SNMPCredential // id -> credential
}

func newSNMPCredStore(path string) (*snmpCredStore, error) {
	if path == "" {
		path = "/data/snmp_credentials.json"
	}
	s := &snmpCredStore{path: path, creds: make(map[string]SNMPCredential)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *snmpCredStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []SNMPCredential
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, c := range list {
		s.creds[c.ID] = c
	}
	return nil
}

func (s *snmpCredStore) flushLocked() error {
	list := make([]SNMPCredential, 0, len(s.creds))
	for _, c := range s.creds {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

func (s *snmpCredStore) List() []publicSNMPCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]publicSNMPCredential, 0, len(s.creds))
	for _, c := range s.creds {
		out = append(out, c.public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the redacted credential for an id (for tenant-ownership checks at
// the API boundary), without exposing secrets.
func (s *snmpCredStore) Get(id string) (publicSNMPCredential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.creds[id]
	if !ok {
		return publicSNMPCredential{}, false
	}
	return c.public(), true
}

// Resolve returns the full (secret-bearing) credential for a device's
// credential_ref. Matches by id or by name (case-insensitive). Used by the
// poller, not the API.
func (s *snmpCredStore) Resolve(ref string) (SNMPCredential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.creds[ref]; ok {
		return c, true
	}
	for _, c := range s.creds {
		if strings.EqualFold(c.Name, ref) {
			return c, true
		}
	}
	return SNMPCredential{}, false
}

// Upsert creates or replaces a credential. On update, empty secret fields keep
// the existing stored secret (so the UI need not re-send them).
func (s *snmpCredStore) Upsert(c SNMPCredential) (publicSNMPCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == "" {
		c.ID = slugify(c.Name)
	}
	if c.ID == "" {
		return publicSNMPCredential{}, errors.New("credential name must contain letters or digits")
	}
	if existing, ok := s.creds[c.ID]; ok {
		if c.Community == "" {
			c.Community = existing.Community
		}
		if c.AuthKey == "" {
			c.AuthKey = existing.AuthKey
		}
		if c.PrivKey == "" {
			c.PrivKey = existing.PrivKey
		}
		if c.CreatedAt.IsZero() {
			c.CreatedAt = existing.CreatedAt
		}
		if c.TenantID == "" {
			c.TenantID = existing.TenantID // don't silently re-home a credential
		}
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if err := validateSNMPCredential(&c); err != nil {
		return publicSNMPCredential{}, err
	}
	s.creds[c.ID] = c
	if err := s.flushLocked(); err != nil {
		return publicSNMPCredential{}, err
	}
	return c.public(), nil
}

func (s *snmpCredStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.creds[id]; !ok {
		return errors.New("no such credential")
	}
	delete(s.creds, id)
	return s.flushLocked()
}
