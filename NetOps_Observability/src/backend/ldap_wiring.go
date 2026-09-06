// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ldap_wiring.go — what stays in main after the LDAP protocol core moved to
// enterprise/sso/ldap (Phase-2 W1.8): the LDAP_* env constructor, the login handler
// and the source-compat aliases. The config STORE (operator overlay) is in
// auth_config.go and consumes these aliases.

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	// ENTERPRISE-ASSEMBLY-BEGIN (ldap)
	// LDAP directory authentication is a commercial add-on module. package
	// main is the assembly layer and the only layer permitted to name both
	// licences; deleting enterprise/ means deleting this block and the code
	// that uses it (see LICENSING.md).
	"netops/backend/enterprise/sso/ldap"
	// ENTERPRISE-ASSEMBLY-END
)

type (
	ldapConfig      = ldap.Config
	ldapRoleMapping = ldap.RoleMapping
)

// newLDAPConfig builds the LDAP config from the environment. It returns a
// disabled config (Enabled=false) when LDAP_ENABLED!=true, so local accounts /
// other providers remain the always-available fallback.
//
// LDAP_ROLE_MAP is a ";"-separated list of "<group>=<role>" pairs, where the
// group is matched (case-insensitive) against either a full group DN or its
// leading "cn=" component, e.g.:
//
//	cn=admins,ou=groups,dc=example,dc=com=super-admin;cn=netops,...=operator
func newLDAPConfig() ldapConfig {
	port := 0
	if v := strings.TrimSpace(os.Getenv("LDAP_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	return ldapConfig{
		Enabled:            os.Getenv("LDAP_ENABLED") == "true" && os.Getenv("LDAP_HOST") != "",
		Host:               os.Getenv("LDAP_HOST"),
		Port:               port,
		UseTLS:             os.Getenv("LDAP_USE_TLS") == "true",
		StartTLS:           os.Getenv("LDAP_START_TLS") == "true",
		BindDN:             os.Getenv("LDAP_BIND_DN"),
		BindPassword:       os.Getenv("LDAP_BIND_PASSWORD"),
		BaseDN:             os.Getenv("LDAP_BASE_DN"),
		UserFilter:         envOr("LDAP_USER_FILTER", "(uid=%s)"),
		GroupBaseDN:        os.Getenv("LDAP_GROUP_BASE_DN"),
		GroupFilter:        os.Getenv("LDAP_GROUP_FILTER"),
		RoleMappings:       ldap.ParseRoleMap(os.Getenv("LDAP_ROLE_MAP")),
		DefaultRole:        envOr("LDAP_DEFAULT_ROLE", RoleReadOnly),
		DefaultTenant:      envOr("LDAP_DEFAULT_TENANT", TenantGlobal),
		CAFile:             os.Getenv("LDAP_CA_FILE"),
		InsecureSkipVerify: os.Getenv("LDAP_INSECURE_SKIP_VERIFY") == "true",
	}
}

func (s *server) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	// F-32: PRE-AUTH route — an LDAP sign-in is a username/password pair. Same
	// loginRequest struct as /api/auth/login, which caps at 64 KiB; this sibling
	// was missed.
	if err := decodeJSONBody(w, r, authCredentialBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.ldap.effective()
	if !cfg.Enabled {
		writeError(w, http.StatusNotFound, errors.New("ldap authentication not configured"))
		return
	}
	id, err := cfg.Authenticate(req.Username, req.Password)
	if err != nil {
		// Generic message: don't leak whether the username exists.
		logInfo("auth", "ldap login failed", map[string]any{"user": req.Username, "reason": err.Error()})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	role := ldap.RoleFor(id.Groups, cfg.RoleMappings, cfg.DefaultRole)
	// Provisioning + account-state gates + session, shared with TACACS+ (auth.go).
	// H1: refuses outright when the username names a LOCALLY-managed account.
	s.completeFederatedLogin(w, r, req.Username, id.Email, firstNonEmpty(id.DisplayName, req.Username), role, "ldap", cfg.DefaultTenant)
}
