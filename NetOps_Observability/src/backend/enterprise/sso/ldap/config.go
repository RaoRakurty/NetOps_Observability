// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
// Copyright 2026 Correlix
//
// COMMERCIAL ADD-ON MODULE. This package implements the `ldap` entitlement
// (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE notice file in
// this directory, ../../../../../LICENSING.md, and LICENSES/Correlix-Enterprise.txt.

package ldap

// config.go — the operator-facing configuration domain for the LDAP provider
// (Phase-2 W1.8): canonicalisation, enable-invariants, the redacted public
// projection, and the staged live test probe. The kv-backed store (vault
// sealing via main's secrets machinery) and the HTTP handlers stay in main.

import (
	"errors"
	"strings"
)

// normalize trims and defaults fields so stored config is canonical.
func (c *Config) Normalize() {
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
		c.DefaultRole = "read-only"
	}
	if strings.TrimSpace(c.DefaultTenant) == "" {
		c.DefaultTenant = "global"
	}
	cleaned := make([]RoleMapping, 0, len(c.RoleMappings))
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
func (c Config) Validate() error {
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

// PublicConfig is the redacted view returned by GET: the bind password is
// replaced by a boolean so the secret never leaves the server.
type PublicConfig struct {
	Enabled            bool          `json:"enabled"`
	Host               string        `json:"host"`
	Port               int           `json:"port"`
	UseTLS             bool          `json:"use_tls"`
	StartTLS           bool          `json:"start_tls"`
	BindDN             string        `json:"bind_dn"`
	BindPasswordSet    bool          `json:"bind_password_set"`
	BaseDN             string        `json:"base_dn"`
	UserFilter         string        `json:"user_filter"`
	GroupBaseDN        string        `json:"group_base_dn"`
	GroupFilter        string        `json:"group_filter"`
	RoleMappings       []RoleMapping `json:"role_mappings"`
	DefaultRole        string        `json:"default_role"`
	DefaultTenant      string        `json:"default_tenant"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
}

func (c Config) Public() PublicConfig {
	rm := c.RoleMappings
	if rm == nil {
		rm = []RoleMapping{} // never emit JSON null — the UI maps over this
	}
	return PublicConfig{
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

// TestResult is the structured outcome of a test-connection probe. The
// headline value operators care about is assigned_role: "what role would this
// user get" (the Okta UX pattern).
type TestResult struct {
	OK           bool     `json:"ok"`
	Stage        string   `json:"stage"` // config|connect|service_bind|user_search|user_bind|done
	Message      string   `json:"message"`
	ResolvedDN   string   `json:"resolved_dn,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	AssignedRole string   `json:"assigned_role,omitempty"`
}

// test probes the directory. It never returns an error to the caller — every
// outcome is encoded in the result so the UI can show exactly where it failed.
func (c Config) Test(username, password string) TestResult {
	if !c.Enabled {
		return TestResult{Stage: "config", Message: "LDAP is not enabled"}
	}
	if c.Host == "" || c.BaseDN == "" {
		return TestResult{Stage: "config", Message: "host and base_dn are required"}
	}
	conn, err := c.dial()
	if err != nil {
		return TestResult{Stage: "connect", Message: "connect failed: " + err.Error()}
	}
	defer conn.Close()
	if c.BindDN != "" {
		if err := conn.simpleBind(c.BindDN, c.BindPassword); err != nil {
			return TestResult{Stage: "service_bind", Message: "service bind failed: " + err.Error()}
		}
	}
	// Connectivity-only probe when no sample user was supplied.
	if strings.TrimSpace(username) == "" {
		msg := "connected; service bind OK"
		if c.BindDN == "" {
			msg = "connected (anonymous; no service bind configured)"
		}
		return TestResult{OK: true, Stage: "service_bind", Message: msg}
	}
	id, err := c.Authenticate(username, password)
	if err != nil {
		return TestResult{Stage: "user_bind", Message: err.Error()}
	}
	role := RoleFor(id.Groups, c.RoleMappings, c.DefaultRole)
	return TestResult{
		OK:           true,
		Stage:        "done",
		Message:      "authentication succeeded",
		ResolvedDN:   id.DN,
		Groups:       id.Groups,
		AssignedRole: role,
	}
}
