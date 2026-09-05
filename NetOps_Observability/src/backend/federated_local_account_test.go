package backend

// federated_local_account_test.go — H1: a federated (TACACS+/LDAP/SSO) sign-in
// whose username collides with a LOCALLY-managed account must be REFUSED, never
// accepted against (or merged into) the local record. Before this fix the
// bootstrap admin's empty AuthSource counted as federated, so a TACACS+/LDAP/
// OIDC identity named "admin" was merged straight into the platform owner —
// re-roled, re-sourced, and issued a session with NO MFA challenge even though
// the local account had MFA enrolled.
//
// The TACACS+ test drives the REAL /api/auth/tacacs/login handler against an
// in-process TACACS+ server that replies PASS (unencrypted mode — the client
// sends TAC_PLUS_UNENCRYPTED_FLAG when no shared secret is configured, RFC 8907
// §4.5, so the mock needs no MD5-pad protocol code). The LDAP handler shares
// the same completeFederatedLogin tail, exercised directly below; the SSO
// callback is covered in sso_local_account_test-style via the parity harness.

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGuardFederatedRoleNormalization (H1c): the guard's predicate must match
// isPlatformOwner's — tenant lowercased/trimmed with "" meaning the global
// realm, and the role matched via isSuperAdminRole so the legacy "admin" alias
// cannot slip past. Each miss was a federated platform-owner escalation.
func TestGuardFederatedRoleNormalization(t *testing.T) {
	for _, tc := range []struct {
		role, tenant string
		want         string
	}{
		{RoleSuperAdmin, "", RoleReadOnly},    // empty tenant IS the global realm (isPlatformOwner treats it so)
		{"admin", "Global", RoleReadOnly},     // legacy alias + case-insensitive tenant
		{"admin", "  global  ", RoleReadOnly}, // whitespace normalization
		{RoleSuperAdmin, TenantGlobal, RoleReadOnly},
		{RoleSuperAdmin, "acme", RoleSuperAdmin}, // tenant-scoped admin is untouched
		{"admin", "acme", "admin"},               // ...alias included
		{RoleOperator, "", RoleOperator},         // non-super roles never downgraded
	} {
		if got := guardFederatedRole(tc.role, tc.tenant, "u1", "oidc"); got != tc.want {
			t.Errorf("guardFederatedRole(%q, %q) = %q, want %q", tc.role, tc.tenant, got, tc.want)
		}
	}
	// The explicit opt-in still allows a federated platform owner — for every
	// spelling the guard would otherwise downgrade.
	t.Setenv("FEDERATION_ALLOW_PLATFORM_OWNER", "true")
	if got := guardFederatedRole("admin", "", "u1", "oidc"); got != "admin" {
		t.Errorf("opted-in guardFederatedRole = %q, want role kept", got)
	}
}

// mockTacacsPassServer accepts TACACS+ AUTHEN START packets and always replies
// PASS, unencrypted (flag 0x01) — valid for a client configured with no shared
// secret, which sends and expects clear bodies. Enough protocol to drive the
// real handler through a successful external authentication.
func mockTacacsPassServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 12)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint32(hdr[8:12]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				// REPLY: status PASS(0x01), flags 0, server_msg_len 0, data_len 0.
				reply := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
				rhdr := make([]byte, 12)
				rhdr[0] = hdr[0]          // same version for the whole session
				rhdr[1] = 0x01            // TAC_PLUS_AUTHEN
				rhdr[2] = hdr[2] + 1      // next seq_no
				rhdr[3] = 0x01            // TAC_PLUS_UNENCRYPTED_FLAG (clear body)
				copy(rhdr[4:8], hdr[4:8]) // echo session id
				binary.BigEndian.PutUint32(rhdr[8:12], uint32(len(reply)))
				_, _ = c.Write(append(rhdr, reply...))
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestTACACSLoginRefusedForLocalAccount: TACACS+ says PASS for "admin", but
// "admin" is the LOCAL bootstrap account (with MFA enrolled). The login must be
// refused with NO session, and the local record must come through unchanged —
// role, auth_source, everything. Without the fix this path re-sourced the
// bootstrap admin to "tacacs", re-roled it to the TACACS default role, and
// minted a session with no MFA challenge.
func TestTACACSLoginRefusedForLocalAccount(t *testing.T) {
	srv, s := newTestServerState(t)
	host, port := mockTacacsPassServer(t)
	s.tacacs = &tacacsConfigStore{cfg: &tacacsConfig{
		Enabled: true, Host: host, Port: port, Secret: "", TimeoutSeconds: 2,
		DefaultRole: RoleReadOnly, DefaultTenant: "",
	}}
	// The local admin has MFA enrolled — the exact account whose second factor
	// the federated path used to skip.
	if err := s.users.SetMFA("admin", true, "sealed-secret", ""); err != nil {
		t.Fatal(err)
	}
	before, ok := s.users.Get("admin")
	if !ok {
		t.Fatal("seeded admin missing")
	}

	st, b := do(t, srv, "POST", "/api/auth/tacacs/login", "", map[string]string{
		"username": "admin", "password": "whatever-tacacs-accepted",
	})
	if st != http.StatusForbidden {
		t.Fatalf("TACACS login against local admin: status %d (%s), want 403", st, b)
	}
	if strings.Contains(string(b), `"token"`) {
		t.Fatalf("refusal body carries a token: %s", b)
	}
	if got := activeSessions(s, "admin"); len(got) != 0 {
		t.Fatalf("refused TACACS login minted %d session(s), want 0", len(got))
	}
	after, _ := s.users.Get("admin")
	if after.Role != before.Role || after.AuthSource != before.AuthSource || after.MFAEnabled != before.MFAEnabled {
		t.Errorf("local admin mutated by refused TACACS login: before role=%q src=%q mfa=%v, after role=%q src=%q mfa=%v",
			before.Role, before.AuthSource, before.MFAEnabled, after.Role, after.AuthSource, after.MFAEnabled)
	}
	if isSuperAdminRole(after.Role) != isSuperAdminRole(before.Role) {
		t.Error("platform-admin standing changed across a refused federated login")
	}
}

// TestCompleteFederatedLoginRefusesLocalAccount exercises the shared tail the
// LDAP handler calls after its external bind succeeds (the LDAP wire protocol
// itself is proven in enterprise/sso/ldap): a colliding local account → 403, no
// session, record untouched.
func TestCompleteFederatedLoginRefusesLocalAccount(t *testing.T) {
	_, s := newTestServerState(t)
	if err := s.users.SetMFA("admin", true, "sealed-secret", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := s.users.Get("admin")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/ldap/login", nil)
	s.completeFederatedLogin(rec, r, "admin", "a@idp.example", "IdP Admin", RoleSuperAdmin, "ldap", "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("completeFederatedLogin for local admin: status %d (%s), want 403", rec.Code, rec.Body.String())
	}
	if got := activeSessions(s, "admin"); len(got) != 0 {
		t.Fatalf("refused LDAP login minted %d session(s), want 0", len(got))
	}
	after, _ := s.users.Get("admin")
	if after.Role != before.Role || after.AuthSource != before.AuthSource {
		t.Errorf("local admin mutated: role %q→%q, auth_source %q→%q", before.Role, after.Role, before.AuthSource, after.AuthSource)
	}
	// A NON-colliding federated user still signs in through the same tail.
	rec2 := httptest.NewRecorder()
	s.completeFederatedLogin(rec2, r, "ldap-only-user", "", "LDAP User", RoleReadOnly, "ldap", "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("fresh federated login: status %d (%s), want 200", rec2.Code, rec2.Body.String())
	}
	var lr loginResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &lr); err != nil || lr.Token == "" {
		t.Fatalf("fresh federated login response invalid: %v (%s)", err, rec2.Body.String())
	}
}

// TestSSOCallbackRefusedForLocalAccount: the full SSO callback (state txn +
// PKCE + RS256 ID token) against a LOCAL account named like the IdP subject —
// refused, no session, record untouched. Uses the #146b parity harness whose
// test IdP asserts subject "user-1".
func TestSSOCallbackRefusedForLocalAccount(t *testing.T) {
	h := newSSOHarness(t, "")
	if _, err := h.s.users.CreateFull(User{Username: fedSSOUser, Role: RoleSuperAdmin}, "Passw0rd!2345"); err != nil {
		t.Fatal(err)
	}
	if err := h.s.users.SetMFA(fedSSOUser, true, "sealed-secret", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := h.s.users.Get(fedSSOUser)

	assertSSORefused(t, h.login(t), "managed locally")
	if got := activeSessions(h.s, fedSSOUser); len(got) != 0 {
		t.Fatalf("refused SSO login minted %d session(s), want 0", len(got))
	}
	after, _ := h.s.users.Get(fedSSOUser)
	if after.Role != before.Role || after.AuthSource != "local" || after.MFAEnabled != before.MFAEnabled {
		t.Errorf("local account mutated by refused SSO login: %+v", after)
	}
}
