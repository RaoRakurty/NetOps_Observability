package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/tlsconfig"
)

// ldap.go — stdlib-only LDAP/Active Directory authentication backend (RFC 4511
// bind + RFC 4515 string filters). Env-driven config (LDAP_*), mirroring the
// OIDC/TACACS providers. A successful bind JIT-provisions a local user and
// re-issues a native session (same as handleLogin / the SSO callback) so the
// hot-path middleware stays on a single verification path.

// ldapConfig is the LDAP/AD backend configuration (built from LDAP_* env vars).
type ldapConfig struct {
	Enabled            bool              `json:"enabled"`
	Host               string            `json:"host"`
	Port               int               `json:"port"`
	UseTLS             bool              `json:"use_tls"`   // LDAPS (TLS from connect, typically :636)
	StartTLS           bool              `json:"start_tls"` // plain :389 then upgrade via StartTLS extended op
	BindDN             string            `json:"bind_dn"`   // service account to search with (empty = anonymous search)
	BindPassword       string            `json:"bind_password"`
	BaseDN             string            `json:"base_dn"`
	UserFilter         string            `json:"user_filter"` // e.g. (uid=%s) or (sAMAccountName=%s); %s = escaped username
	GroupBaseDN        string            `json:"group_base_dn"`
	GroupFilter        string            `json:"group_filter"` // e.g. (member=%s); %s = escaped user DN
	RoleMappings       []ldapRoleMapping `json:"role_mappings"`
	DefaultRole        string            `json:"default_role"`
	DefaultTenant      string            `json:"default_tenant"`
	CAFile             string            `json:"ca_file"` // explicit CA bundle for the LDAP server cert; empty → system trust pool
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
}

type ldapRoleMapping struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

const ldapDialTimeout = 8 * time.Second

// ldapIdentity is the normalized result of a successful LDAP authentication.
type ldapIdentity struct {
	Username    string
	DN          string
	Email       string
	DisplayName string
	Groups      []string
}

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
		RoleMappings:       parseLDAPRoleMap(os.Getenv("LDAP_ROLE_MAP")),
		DefaultRole:        envOr("LDAP_DEFAULT_ROLE", RoleReadOnly),
		DefaultTenant:      envOr("LDAP_DEFAULT_TENANT", TenantGlobal),
		CAFile:             os.Getenv("LDAP_CA_FILE"),
		InsecureSkipVerify: os.Getenv("LDAP_INSECURE_SKIP_VERIFY") == "true",
	}
}

// parseLDAPRoleMap turns "group=role;group2=role2" into role mappings. The
// group token may itself contain '=' (DNs do), so we split on the LAST '='.
func parseLDAPRoleMap(csv string) []ldapRoleMapping {
	var out []ldapRoleMapping
	for _, raw := range strings.Split(csv, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		i := strings.LastIndex(raw, "=")
		if i <= 0 || i == len(raw)-1 {
			continue
		}
		group := strings.TrimSpace(raw[:i])
		role := strings.TrimSpace(raw[i+1:])
		if group != "" && role != "" {
			out = append(out, ldapRoleMapping{Group: group, Role: role})
		}
	}
	return out
}

// rolePrivilege ranks the built-in roles so that, when a user's groups match
// several mappings, we pick the most privileged. Unknown/custom roles rank
// above read-only but below the built-ins so an explicit mapping still wins
// over the default.
func rolePrivilege(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleSuperAdmin, "admin":
		return 3
	case RoleOperator:
		return 2
	case RoleReadOnly, "viewer", "":
		return 0
	default:
		return 1
	}
}

// groupMatches reports whether a directory group value (a full DN or a bare cn)
// matches a configured mapping key (also a full DN or bare cn), case-insensitively.
// A "cn=<x>,..." DN matches a mapping that names just "<x>" or "cn=<x>", and a
// full-DN mapping matches the identical DN.
func groupMatches(group, mapping string) bool {
	g := strings.ToLower(strings.TrimSpace(group))
	m := strings.ToLower(strings.TrimSpace(mapping))
	if g == "" || m == "" {
		return false
	}
	if g == m {
		return true
	}
	// Compare leading cn= components / bare cn names.
	return leadingCN(g) == leadingCN(m)
}

// leadingCN extracts the value of the first "cn=" component of a DN, or returns
// the input unchanged (lower-cased, trimmed) when it carries no "cn=".
func leadingCN(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "cn=")
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ldapRoleFor resolves a SINGLE local role from the user's groups. If any group
// matches a mapping it returns the most privileged matched role; otherwise it
// returns defaultRole (or RoleReadOnly when defaultRole is empty).
func ldapRoleFor(groups []string, mappings []ldapRoleMapping, defaultRole string) string {
	best := ""
	bestRank := -1
	for _, g := range groups {
		for _, m := range mappings {
			if groupMatches(g, m.Group) {
				if r := rolePrivilege(m.Role); r > bestRank {
					bestRank = r
					best = m.Role
				}
			}
		}
	}
	if best != "" {
		return best
	}
	if strings.TrimSpace(defaultRole) == "" {
		return RoleReadOnly
	}
	return defaultRole
}

// authenticate verifies username/password against the directory and returns a
// normalized identity. It is a pure method over lc (no server state).
//
// Flow (RFC 4511): connect (+ optional LDAPS/StartTLS) → optional service bind →
// search BaseDN with UserFilter to resolve the user's DN and attributes → bind
// as that DN with the supplied password (the actual credential check) → gather
// group memberships (memberOf attr, else a GroupFilter search).
func (lc ldapConfig) authenticate(username, password string) (*ldapIdentity, error) {
	if !lc.Enabled {
		return nil, errors.New("ldap not enabled")
	}
	if strings.TrimSpace(lc.Host) == "" || strings.TrimSpace(lc.BaseDN) == "" {
		return nil, errors.New("ldap host and base_dn are required")
	}
	// Reject empty credentials: an LDAP bind with an empty password is an
	// "unauthenticated bind" (RFC 4513 §5.1.2) that succeeds WITHOUT verifying
	// the user — accepting it would be an authentication bypass.
	if username == "" || password == "" {
		return nil, errors.New("username and password required")
	}

	conn, err := lc.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	// 1) Bind as the service account (or anonymously) so we can search.
	if lc.BindDN != "" {
		if err := conn.simpleBind(lc.BindDN, lc.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap service bind: %w", err)
		}
	}

	// 2) Find the user entry.
	userFilter := lc.UserFilter
	if strings.TrimSpace(userFilter) == "" {
		userFilter = "(uid=%s)"
	}
	filter := strings.ReplaceAll(userFilter, "%s", ldapEscapeFilterValue(username))
	entries, err := conn.search(lc.BaseDN, filter, []string{"mail", "cn", "displayName", "memberOf"})
	if err != nil {
		return nil, fmt.Errorf("ldap user search: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("user not found")
	}
	if len(entries) > 1 {
		return nil, errors.New("user filter matched multiple entries")
	}
	entry := entries[0]
	userDN := entry.dn
	if userDN == "" {
		return nil, errors.New("user entry has no DN")
	}

	// 3) Verify the password by binding AS the user. Use a fresh connection so
	// the service-account session is not disturbed.
	userConn, err := lc.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap connect (user bind): %w", err)
	}
	defer userConn.Close()
	if err := userConn.simpleBind(userDN, password); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// 4) Group membership: prefer memberOf on the entry; otherwise search.
	groups := entry.attr("memberOf")
	if len(groups) == 0 && strings.TrimSpace(lc.GroupFilter) != "" {
		gbase := lc.GroupBaseDN
		if gbase == "" {
			gbase = lc.BaseDN
		}
		gfilter := strings.ReplaceAll(lc.GroupFilter, "%s", ldapEscapeFilterValue(userDN))
		gEntries, gErr := conn.search(gbase, gfilter, []string{"cn"})
		if gErr == nil {
			for _, ge := range gEntries {
				if cns := ge.attr("cn"); len(cns) > 0 {
					groups = append(groups, cns[0])
				} else if ge.dn != "" {
					groups = append(groups, ge.dn)
				}
			}
		}
	}

	return &ldapIdentity{
		Username:    username,
		DN:          userDN,
		Email:       first(entry.attr("mail")),
		DisplayName: firstNonEmpty(first(entry.attr("displayName")), first(entry.attr("cn")), username),
		Groups:      groups,
	}, nil
}

// handleLDAPLogin (public) authenticates {username,password} against the LDAP/AD
// directory, JIT-provisions a local user, and issues the same access + refresh
// session as handleLogin.
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
	id, err := cfg.authenticate(req.Username, req.Password)
	if err != nil {
		// Generic message: don't leak whether the username exists.
		logInfo("auth", "ldap login failed", map[string]any{"user": req.Username, "reason": err.Error()})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	role := ldapRoleFor(id.Groups, cfg.RoleMappings, cfg.DefaultRole)
	user, err := s.users.UpsertFederated(req.Username, id.Email, firstNonEmpty(id.DisplayName, req.Username), role, "ldap", cfg.DefaultTenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.logBindingSync(user, "ldap") // PBAC Phase A: mirror the provisioned identity
	if user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role, "src": "ldap"})
	s.issueSession(w, r, user) // server-side session + tokens (same as password login)
}

func first(ss []string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return ""
}

// ---------------------------------------------------------------------------
// LDAP connection
// ---------------------------------------------------------------------------

type ldapConn struct {
	conn  net.Conn
	msgID int32
}

func (lc ldapConfig) addr() string {
	port := lc.Port
	if port == 0 {
		if lc.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}
	return net.JoinHostPort(lc.Host, fmt.Sprintf("%d", port))
}

// tlsConfig builds the LDAP client TLS config through the hardened tlsconfig
// package (SR-014): TLS 1.2+ floor, vetted ciphers/curves, no renegotiation, and
// — critically — hostname/chain verification that can no longer be silently
// disabled. An explicit CA bundle (LDAP_CA_FILE) is preferred; absent one we
// verify against the host's system trust pool (LDAP/AD usually presents a
// corporate/public cert). InsecureSkipVerify is honored ONLY behind the loud
// dev-only ALLOW_DEV_SECRETS gate — otherwise it is refused, because skipping
// verification lets an attacker MITM the bind and harvest every user's password.
func (lc ldapConfig) tlsConfig() (*tls.Config, error) {
	opts := tlsconfig.ClientOptions{ServerName: lc.Host}
	if strings.TrimSpace(lc.CAFile) != "" {
		bundle, err := tlsconfig.LoadTrustBundle(lc.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap CA bundle: %w", err)
		}
		opts.RootCAs = bundle
	} else {
		opts.SystemRoots = true
	}
	cfg, err := tlsconfig.ClientConfig(opts)
	if err != nil {
		return nil, err
	}
	if lc.InsecureSkipVerify {
		if os.Getenv("ALLOW_DEV_SECRETS") != "true" {
			return nil, errors.New("LDAP_INSECURE_SKIP_VERIFY=true requires ALLOW_DEV_SECRETS=true (dev only) — refusing to disable LDAP certificate verification, which would expose every user's password to a MITM")
		}
		logWarn("ldap", "LDAP certificate verification DISABLED (LDAP_INSECURE_SKIP_VERIFY + ALLOW_DEV_SECRETS) — bind credentials are MITM-able; dev only", nil)
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicit dev-only opt-in, gated behind ALLOW_DEV_SECRETS
	}
	return cfg, nil
}

func (lc ldapConfig) dial() (*ldapConn, error) {
	d := &net.Dialer{Timeout: ldapDialTimeout}
	if lc.UseTLS {
		cfg, err := lc.tlsConfig()
		if err != nil {
			return nil, err
		}
		c, err := tls.DialWithDialer(d, "tcp", lc.addr(), cfg)
		if err != nil {
			return nil, err
		}
		return &ldapConn{conn: c}, nil
	}
	c, err := d.Dial("tcp", lc.addr())
	if err != nil {
		return nil, err
	}
	lconn := &ldapConn{conn: c}
	if lc.StartTLS {
		cfg, err := lc.tlsConfig()
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
		if err := lconn.startTLS(cfg); err != nil {
			c.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return lconn, nil
}

func (c *ldapConn) Close() error { return c.conn.Close() }

func (c *ldapConn) nextID() int32 {
	c.msgID++
	return c.msgID
}

// startTLS issues the StartTLS extended request (OID 1.3.6.1.4.1.1466.20037)
// and, on success, upgrades the connection to TLS in place.
func (c *ldapConn) startTLS(tlsCfg *tls.Config) error {
	const startTLSOID = "1.3.6.1.4.1.1466.20037"
	id := c.nextID()
	req := berTLV(tagExtendedRequest, berTLV(0x80, []byte(startTLSOID)))
	if err := c.writeMessage(id, req); err != nil {
		return err
	}
	_, op, err := c.readMessage(id)
	if err != nil {
		return err
	}
	rc, _ := parseLDAPResult(op.content)
	if rc != 0 {
		return fmt.Errorf("starttls refused (resultCode %d)", rc)
	}
	tlsConn := tls.Client(c.conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	c.conn = tlsConn
	return nil
}

// simpleBind performs an LDAP simple bind. A non-zero resultCode means the
// credentials (or DN) were rejected.
func (c *ldapConn) simpleBind(dn, password string) error {
	id := c.nextID()
	content := concat(
		berInt(tagInteger, 3), // version 3
		berTLV(tagOctetString, []byte(dn)),
		berTLV(0x80, []byte(password)), // [0] simple authentication
	)
	req := berTLV(tagBindRequest, content)
	if err := c.writeMessage(id, req); err != nil {
		return err
	}
	_, op, err := c.readMessage(id)
	if err != nil {
		return err
	}
	if op.tag != tagBindResponse {
		return fmt.Errorf("unexpected response to bind (tag 0x%02x)", op.tag)
	}
	rc, msg := parseLDAPResult(op.content)
	if rc != 0 {
		if msg != "" {
			return fmt.Errorf("bind failed: %s (code %d)", msg, rc)
		}
		return fmt.Errorf("bind failed (code %d)", rc)
	}
	return nil
}

type ldapEntry struct {
	dn    string
	attrs map[string][]string
}

func (e ldapEntry) attr(name string) []string {
	for k, v := range e.attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// search runs a subtree search and returns the matched entries. attrs is the
// list of attributes to retrieve (nil/empty = all user attributes).
func (c *ldapConn) search(baseDN, filter string, attrs []string) ([]ldapEntry, error) {
	filterBER, err := parseFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter %q: %w", filter, err)
	}
	var attrSeq []byte
	for _, a := range attrs {
		attrSeq = append(attrSeq, berTLV(tagOctetString, []byte(a))...)
	}
	content := concat(
		berTLV(tagOctetString, []byte(baseDN)),
		berInt(tagEnumerated, 2), // scope: wholeSubtree
		berInt(tagEnumerated, 0), // derefAliases: neverDerefAliases
		berInt(tagInteger, 0),    // sizeLimit
		berInt(tagInteger, 30),   // timeLimit (seconds)
		berBool(false),           // typesOnly
		filterBER,
		berTLV(tagSequence, attrSeq),
	)
	id := c.nextID()
	if err := c.writeMessage(id, berTLV(tagSearchRequest, content)); err != nil {
		return nil, err
	}

	var entries []ldapEntry
	for {
		_, op, err := c.readMessage(id)
		if err != nil {
			return nil, err
		}
		switch op.tag {
		case tagSearchResultEntry:
			e, perr := parseSearchEntry(op.content)
			if perr != nil {
				return nil, perr
			}
			entries = append(entries, e)
		case tagSearchResultDone:
			rc, msg := parseLDAPResult(op.content)
			if rc != 0 && rc != 4 { // 4 = sizeLimitExceeded: keep what we have
				if msg != "" {
					return nil, fmt.Errorf("search failed: %s (code %d)", msg, rc)
				}
				return nil, fmt.Errorf("search failed (code %d)", rc)
			}
			return entries, nil
		case tagSearchResultReference:
			// referrals: ignore for our use cases
		default:
			return nil, fmt.Errorf("unexpected message in search (tag 0x%02x)", op.tag)
		}
	}
}

// ---------------------------------------------------------------------------
// Message framing (LDAPMessage ::= SEQUENCE { messageID, protocolOp, ... })
// ---------------------------------------------------------------------------

type protocolOp struct {
	tag     byte
	content []byte
}

func (c *ldapConn) writeMessage(id int32, op []byte) error {
	msg := berTLV(tagSequence, concat(berInt(tagInteger, int(id)), op))
	_ = c.conn.SetWriteDeadline(time.Now().Add(ldapDialTimeout))
	_, err := c.conn.Write(msg)
	return err
}

// readMessage reads one LDAPMessage, validates the messageID, and returns the
// protocol-op tag and its content.
func (c *ldapConn) readMessage(wantID int32) (int32, protocolOp, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(ldapDialTimeout))
	tag, body, err := readBERElement(c.conn)
	if err != nil {
		return 0, protocolOp{}, err
	}
	if tag != tagSequence {
		return 0, protocolOp{}, fmt.Errorf("malformed LDAPMessage (tag 0x%02x)", tag)
	}
	r := &berReader{b: body}
	idTag, idBytes, err := r.next()
	if err != nil || idTag != tagInteger {
		return 0, protocolOp{}, errors.New("malformed messageID")
	}
	id := int32(beInt(idBytes)) // #nosec G115 -- LDAP messageID is INTEGER 0..2^31-1 (RFC 4511); int32 is the protocol type
	opTag, opContent, err := r.next()
	if err != nil {
		return 0, protocolOp{}, errors.New("missing protocolOp")
	}
	if wantID != 0 && id != wantID {
		return id, protocolOp{}, fmt.Errorf("messageID mismatch (got %d want %d)", id, wantID)
	}
	return id, protocolOp{tag: opTag, content: opContent}, nil
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

// parseLDAPResult reads resultCode + errorMessage from an LDAPResult-shaped op.
func parseLDAPResult(content []byte) (int, string) {
	r := &berReader{b: content}
	rcTag, rcBytes, err := r.next()
	if err != nil || rcTag != tagEnumerated {
		return -1, ""
	}
	rc := beInt(rcBytes)
	_, _, _ = r.next() // matchedDN
	_, msgBytes, merr := r.next()
	msg := ""
	if merr == nil {
		msg = string(msgBytes)
	}
	return rc, msg
}

// parseSearchEntry parses a SearchResultEntry: objectName + PartialAttributeList.
func parseSearchEntry(content []byte) (ldapEntry, error) {
	r := &berReader{b: content}
	_, dnBytes, err := r.next()
	if err != nil {
		return ldapEntry{}, errors.New("entry missing DN")
	}
	e := ldapEntry{dn: string(dnBytes), attrs: map[string][]string{}}
	_, attrList, err := r.next() // SEQUENCE OF PartialAttribute
	if err != nil {
		return e, nil // entry with no attributes is valid
	}
	ar := &berReader{b: attrList}
	for {
		_, attrSeq, aerr := ar.next()
		if aerr != nil {
			break
		}
		pr := &berReader{b: attrSeq}
		_, nameBytes, nerr := pr.next()
		if nerr != nil {
			continue
		}
		name := string(nameBytes)
		_, valSet, verr := pr.next() // SET OF AttributeValue
		if verr != nil {
			continue
		}
		vr := &berReader{b: valSet}
		for {
			_, vBytes, vverr := vr.next()
			if vverr != nil {
				break
			}
			e.attrs[name] = append(e.attrs[name], string(vBytes))
		}
	}
	return e, nil
}

// ---------------------------------------------------------------------------
// RFC 4515 filter string → BER
// ---------------------------------------------------------------------------

// parseFilter compiles an RFC 4515 string filter (e.g. "(&(objectClass=person)
// (uid=jdoe))") into its BER encoding. Supports &, |, !, equality, presence
// (attr=*), and substrings (attr=a*b*c). >= and <= are accepted as equality-
// shaped comparators.
func parseFilter(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty filter")
	}
	p := &filterParser{s: s}
	out, err := p.parse()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return nil, errors.New("trailing characters after filter")
	}
	return out, nil
}

type filterParser struct {
	s   string
	pos int
}

func (p *filterParser) skipSpace() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n') {
		p.pos++
	}
}

func (p *filterParser) parse() ([]byte, error) {
	p.skipSpace()
	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		return nil, errors.New("expected '('")
	}
	p.pos++ // consume '('
	p.skipSpace()
	if p.pos >= len(p.s) {
		return nil, errors.New("unexpected end of filter")
	}
	var out []byte
	var err error
	switch p.s[p.pos] {
	case '&':
		p.pos++
		out, err = p.parseSet(tagFilterAnd)
	case '|':
		p.pos++
		out, err = p.parseSet(tagFilterOr)
	case '!':
		p.pos++
		inner, ierr := p.parse()
		if ierr != nil {
			return nil, ierr
		}
		out = berTLV(tagFilterNot, inner)
	default:
		out, err = p.parseItem()
	}
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos >= len(p.s) || p.s[p.pos] != ')' {
		return nil, errors.New("expected ')'")
	}
	p.pos++ // consume ')'
	return out, nil
}

func (p *filterParser) parseSet(tag byte) ([]byte, error) {
	var children []byte
	for {
		p.skipSpace()
		if p.pos < len(p.s) && p.s[p.pos] == '(' {
			child, err := p.parse()
			if err != nil {
				return nil, err
			}
			children = append(children, child...)
			continue
		}
		break
	}
	if len(children) == 0 {
		return nil, errors.New("empty filter set")
	}
	return berTLV(tag, children), nil
}

// parseItem parses "attr=value", "attr=*", "attr=a*b", "attr>=v", "attr<=v".
func (p *filterParser) parseItem() ([]byte, error) {
	// attribute name runs until one of = < > ~
	start := p.pos
	for p.pos < len(p.s) && !strings.ContainsRune("=<>~)", rune(p.s[p.pos])) {
		p.pos++
	}
	attr := strings.TrimSpace(p.s[start:p.pos])
	if attr == "" || p.pos >= len(p.s) {
		return nil, errors.New("malformed filter item")
	}
	var comp byte
	switch p.s[p.pos] {
	case '=':
		comp = '='
		p.pos++
	case '>':
		comp = '>'
		p.pos++
		if p.pos < len(p.s) && p.s[p.pos] == '=' {
			p.pos++
		}
	case '<':
		comp = '<'
		p.pos++
		if p.pos < len(p.s) && p.s[p.pos] == '=' {
			p.pos++
		}
	case '~':
		comp = '~'
		p.pos++
		if p.pos < len(p.s) && p.s[p.pos] == '=' {
			p.pos++
		}
	default:
		return nil, errors.New("unknown comparator")
	}
	// value runs until ')'
	vstart := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != ')' {
		p.pos++
	}
	rawVal := p.s[vstart:p.pos]

	switch comp {
	case '>':
		return berTLV(tagFilterGE, concat(berTLV(tagOctetString, []byte(attr)), berTLV(tagOctetString, ldapUnescape(rawVal)))), nil
	case '<':
		return berTLV(tagFilterLE, concat(berTLV(tagOctetString, []byte(attr)), berTLV(tagOctetString, ldapUnescape(rawVal)))), nil
	case '~':
		return berTLV(tagFilterApprox, concat(berTLV(tagOctetString, []byte(attr)), berTLV(tagOctetString, ldapUnescape(rawVal)))), nil
	}
	// equality / presence / substrings
	if rawVal == "*" {
		// present: [7] primitive, content = attribute description
		return berTLV(tagFilterPresent, []byte(attr)), nil
	}
	if strings.Contains(rawVal, "*") {
		return buildSubstringFilter(attr, rawVal), nil
	}
	return berTLV(tagFilterEquality, concat(berTLV(tagOctetString, []byte(attr)), berTLV(tagOctetString, ldapUnescape(rawVal)))), nil
}

// buildSubstringFilter encodes attr=a*b*c into a SubstringFilter.
func buildSubstringFilter(attr, val string) []byte {
	parts := strings.Split(val, "*")
	var subs []byte
	for i, part := range parts {
		if part == "" {
			continue
		}
		b := ldapUnescape(part)
		switch {
		case i == 0:
			subs = append(subs, berTLV(0x80, b)...) // initial [0]
		case i == len(parts)-1:
			subs = append(subs, berTLV(0x82, b)...) // final [2]
		default:
			subs = append(subs, berTLV(0x81, b)...) // any [1]
		}
	}
	content := concat(berTLV(tagOctetString, []byte(attr)), berTLV(tagSequence, subs))
	return berTLV(tagFilterSubstrings, content)
}

// ldapUnescape decodes RFC 4515 \XX hex escapes in a filter value.
func ldapUnescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 < len(s) {
			if b, ok := hexByte(s[i+1], s[i+2]); ok {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexVal(a)
	lo, ok2 := hexVal(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ldapEscapeFilterValue escapes the RFC 4515 special characters so that
// user-supplied input cannot alter filter structure (LDAP injection defense).
func ldapEscapeFilterValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0:
			b.WriteString(`\00`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Minimal BER encode / decode
// ---------------------------------------------------------------------------

const (
	tagBool        byte = 0x01
	tagInteger     byte = 0x02
	tagOctetString byte = 0x04
	tagEnumerated  byte = 0x0a
	tagSequence    byte = 0x30 // constructed

	// LDAP protocol ops (APPLICATION, constructed)
	tagBindRequest           byte = 0x60
	tagBindResponse          byte = 0x61
	tagSearchRequest         byte = 0x63
	tagSearchResultEntry     byte = 0x64
	tagSearchResultDone      byte = 0x65
	tagSearchResultReference byte = 0x73
	tagExtendedRequest       byte = 0x77

	// Filter tags (CONTEXT class)
	tagFilterAnd        byte = 0xa0
	tagFilterOr         byte = 0xa1
	tagFilterNot        byte = 0xa2
	tagFilterEquality   byte = 0xa3
	tagFilterSubstrings byte = 0xa4
	tagFilterGE         byte = 0xa5
	tagFilterLE         byte = 0xa6
	tagFilterPresent    byte = 0x87 // primitive
	tagFilterApprox     byte = 0xa8
)

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// berTLV builds a tag-length-value element with a definite-form length.
func berTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, berLength(len(content))...)
	return append(out, content...)
}

func berBool(v bool) []byte {
	b := byte(0x00)
	if v {
		b = 0xff
	}
	return berTLV(tagBool, []byte{b})
}

// berInt encodes a non-negative integer with the given tag (minimal big-endian,
// padded to keep it positive). Used for small values (version, limits, results).
func berInt(tag byte, v int) []byte {
	if v == 0 {
		return berTLV(tag, []byte{0x00})
	}
	var raw []byte
	for n := v; n > 0; n >>= 8 {
		raw = append([]byte{byte(n & 0xff)}, raw...)
	}
	if raw[0]&0x80 != 0 { // ensure positive
		raw = append([]byte{0x00}, raw...)
	}
	return berTLV(tag, raw)
}

// berLength encodes a length in definite form (short or long).
func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var raw []byte
	for x := n; x > 0; x >>= 8 {
		raw = append([]byte{byte(x & 0xff)}, raw...)
	}
	return append([]byte{0x80 | byte(len(raw))}, raw...)
}

// beInt reads a big-endian (signed-but-small) integer from BER content bytes.
func beInt(b []byte) int {
	n := 0
	for _, x := range b {
		n = n<<8 | int(x)
	}
	return n
}

// berReader walks the TLV elements of a BER content buffer.
type berReader struct {
	b   []byte
	pos int
}

func (r *berReader) next() (byte, []byte, error) {
	if r.pos >= len(r.b) {
		return 0, nil, io.EOF
	}
	tag := r.b[r.pos]
	r.pos++
	length, n, err := readLength(r.b[r.pos:])
	if err != nil {
		return 0, nil, err
	}
	r.pos += n
	if r.pos+length > len(r.b) {
		return 0, nil, errors.New("ber: length exceeds buffer")
	}
	content := r.b[r.pos : r.pos+length]
	r.pos += length
	return tag, content, nil
}

// readLength parses a definite-form length from the head of b, returning the
// length value and the number of bytes consumed.
func readLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("ber: missing length")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	num := int(b[0] & 0x7f)
	if num == 0 || num > 4 || 1+num > len(b) {
		return 0, 0, errors.New("ber: bad long-form length")
	}
	length := 0
	for i := 1; i <= num; i++ {
		length = length<<8 | int(b[i])
	}
	return length, 1 + num, nil
}

// readBERElement reads one complete BER element (tag + length + content) from a
// stream and returns its tag and content bytes.
func readBERElement(conn net.Conn) (byte, []byte, error) {
	var tagb [1]byte
	if _, err := io.ReadFull(conn, tagb[:]); err != nil {
		return 0, nil, err
	}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return 0, nil, err
	}
	var length int
	if first[0] < 0x80 {
		length = int(first[0])
	} else {
		num := int(first[0] & 0x7f)
		if num == 0 || num > 4 {
			return 0, nil, errors.New("ber: bad stream length")
		}
		lb := make([]byte, num)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return 0, nil, err
		}
		for _, x := range lb {
			length = length<<8 | int(x)
		}
	}
	if length < 0 || length > 8<<20 { // 8 MiB sanity cap
		return 0, nil, errors.New("ber: element too large")
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(conn, content); err != nil {
		return 0, nil, err
	}
	return tagb[0], content, nil
}
