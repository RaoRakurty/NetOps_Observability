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

	"netops/backend/internal/users"

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
	// ldapIdentity is what a successful bind returned (username, DN, e-mail,
	// display name, groups). Aliased here because the identity tuple is built
	// from it (identity_doors.go) and package main is the only assembly layer
	// permitted to name the enterprise module.
	ldapIdentity = ldap.Identity
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
	// Resolution + account-state gates + session, shared with TACACS+ (auth.go).
	//
	// THE KEY IS ("ldap:" + host:port, lower(DN or login)) — tracker 300 §2.3, so
	// two directories are two namespaces even when they hand out the same login
	// names, and a login name is no longer an identity anywhere. The DN is
	// preferred when the directory returned one and `subject_kind` records which
	// was used. H1: refuses outright when the tuple would reach a LOCALLY-managed
	// account.
	s.completeFederatedLogin(w, r, ldapAssertion(cfg, id, req.Username, role))
}

// ldapDirectoryIssuer is the issuer namespace of the configured directory:
// "ldap:" + host:port, derived from the SAME host/port/TLS triple the client
// dials, so the namespace and the connection cannot disagree.
//
// KEY MATERIAL: changing LDAP_HOST/LDAP_PORT, or flipping LDAP_USE_TLS (which
// moves the default port 389→636), re-namespaces the directory and the next
// sign-in provisions fresh accounts. That is the design's intent (two directories
// are two namespaces) and is documented for the operator in the SSO runbook;
// StartTLS on 389 keeps the plain-port namespace, as it keeps the plain port.
func ldapDirectoryIssuer(cfg ldapConfig) string {
	scheme := "ldap"
	if cfg.UseTLS {
		scheme = "ldaps"
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return ""
	}
	if cfg.Port > 0 {
		host = host + ":" + intToString(cfg.Port)
	}
	return users.LDAPIssuer(scheme + "://" + host)
}

// ldapAssertion is what the directory verified: the DN it returned when it
// returned one, else the login name it accepted — and `subject_kind` records
// WHICH, so a later DN-vs-login policy change is visible rather than silent
// (§2.3). A DN move (an OU change) therefore yields a new account by design; the
// old one surfaces as `identity_status: pending` for the operator.
func ldapAssertion(cfg ldapConfig, id *ldap.Identity, login, role string) users.Assertion {
	var dn, email, display string
	if id != nil {
		dn, email, display = id.DN, id.Email, id.DisplayName
	}
	subject, kind := strings.ToLower(strings.TrimSpace(dn)), users.SubjectKindDN
	if subject == "" {
		subject, kind = strings.ToLower(strings.TrimSpace(login)), users.SubjectKindLogin
	}
	return users.Assertion{
		Identity: users.Identity{
			// One platform-global directory today, so the account's own tenant is
			// authoritative and the provisioning tenant is the configured default.
			TenantID:    cfg.DefaultTenant,
			Issuer:      ldapDirectoryIssuer(cfg),
			Subject:     subject,
			Protocol:    users.ProtocolLDAP,
			SubjectKind: kind,
		},
		Email:       email,
		DisplayName: firstNonEmpty(display, login),
		Role:        role,
		// §2.6: the legacy LDAP door keyed on the TYPED LOGIN NAME, not the DN.
		LegacyUsername: login,
	}
}
