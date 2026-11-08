// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package backendauth attaches file-backed, origin-scoped Basic credentials
// to the api's (and prober's) calls to its internal backends — tracker 367
// layer 1: no secrets in URLs.
//
// Before: VICTORIA_URL / METRICS_URL / OPENSEARCH_URL carried the service
// password as URL userinfo (https://svc-api:<pw>@vmauth:8427). Anything that
// printed the URL printed the password — `docker inspect`, an error string, a
// push-failure log line (734 of them on the lab, tracker 367).
//
// Now: the URL is credential-free, and the password lives in a read-only
// bind-mounted file rendered by scripts/install.py:
//
//	VICTORIA_AUTH_USER=svc-api
//	VICTORIA_AUTH_PASSWORD_FILE=/run/secrets/vmauth/api/password
//	OPENSEARCH_AUTH_USER=svc_api
//	OPENSEARCH_AUTH_PASSWORD_FILE=/run/secrets/opensearch/api/password
//
// Each credential is bound to the ORIGIN (scheme + host + port) of the URL it
// was configured for. Transport attaches it to a request only when the
// request's origin matches exactly — so a VictoriaMetrics password can never
// ride a request to OpenSearch, a redirect target, or any other host that
// shares the hardened client.
//
// Back-compat (one release, then a FATAL posture finding): userinfo in those
// URLs is still honoured, with ONE boot warning naming the variable (never the
// value), netops_config_url_credential{var}=1, and the secprofile CRED-001
// warning. When both forms are configured, the file wins and the userinfo is
// stripped. DATABASE_URL is deliberately out of scope (libpq DSN; its own
// follow-up).
//
// The package has no global state: the caller owns the parsed *Set and hands
// Transport a function that returns it. Stdlib + internal/credfile only.
package backendauth

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"netops/backend/internal/credfile"
)

// family is one backend whose credential can be file-backed.
type family struct {
	backend    string   // metric/log label
	userEnv    string   // username env var
	fileEnv    string   // password-file env var
	urlEnvs    []string // the URL env vars whose origins the credential is bound to
	defaultURL string   // what the call sites fall back to when no URL env is set
}

// families mirrors the call sites: every VictoriaMetrics reader resolves
// VICTORIA_URL then METRICS_URL then http://victoria:8428, every OpenSearch
// reader OPENSEARCH_URL then http://opensearch:9200.
func families() []family {
	return []family{
		{backend: "victoria", userEnv: "VICTORIA_AUTH_USER", fileEnv: "VICTORIA_AUTH_PASSWORD_FILE",
			urlEnvs: []string{"VICTORIA_URL", "METRICS_URL"}, defaultURL: "http://victoria:8428"},
		{backend: "opensearch", userEnv: "OPENSEARCH_AUTH_USER", fileEnv: "OPENSEARCH_AUTH_PASSWORD_FILE",
			urlEnvs: []string{"OPENSEARCH_URL"}, defaultURL: "http://opensearch:9200"},
	}
}

// URLVars is every URL env var the legacy-userinfo check covers, in a stable
// order (metric output, tests).
func URLVars() []string {
	var out []string
	for _, f := range families() {
		out = append(out, f.urlEnvs...)
	}
	return out
}

// Credential is one Basic credential and the exact origins it may be sent to.
type Credential struct {
	backend string
	origins map[string]struct{}
	basic   *credfile.Basic
}

// Backend is the backend label ("victoria" | "opensearch").
func (c *Credential) Backend() string { return c.backend }

// Basic is the file-backed Basic credential.
func (c *Credential) Basic() *credfile.Basic { return c.basic }

// Origins are the origins this credential is bound to, sorted.
func (c *Credential) Origins() []string {
	out := make([]string, 0, len(c.origins))
	for k := range c.origins {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Set is the immutable result of parsing the credential env.
type Set struct {
	creds  []*Credential
	legacy map[string]bool // URL env var -> carries userinfo (value never kept)
}

// Credentials are the configured file-backed credentials.
func (s *Set) Credentials() []*Credential {
	if s == nil {
		return nil
	}
	return s.creds
}

// Legacy reports whether the URL env var still carries userinfo.
func (s *Set) Legacy(v string) bool { return s != nil && s.legacy[v] }

// ForOrigin returns the credential bound to origin, or nil.
func (s *Set) ForOrigin(origin string) *Credential {
	if s == nil || origin == "" {
		return nil
	}
	for _, c := range s.creds {
		if _, ok := c.origins[origin]; ok {
			return c
		}
	}
	return nil
}

// OriginOf returns "scheme://host:port" with the scheme and host lower-cased
// and the port made explicit, or "" for a URL that is not http(s) with a host.
func OriginOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	switch scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return ""
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// HasUserinfo reports whether a URL env value carries userinfo. A value that
// does not parse is checked textually, so a malformed credential-bearing URL
// is still flagged rather than silently ignored.
func HasUserinfo(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if u, err := url.Parse(raw); err == nil {
		return u.User != nil
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		authority := raw[i+3:]
		if j := strings.IndexAny(authority, "/?#"); j >= 0 {
			authority = authority[:j]
		}
		return strings.Contains(authority, "@")
	}
	return false
}

// Parse builds the credential set from env. It returns the set, the operator
// warnings (variable names only — never values) and a configuration error for
// anything that must not boot: half a credential, a malformed username or
// URL, or two backends claiming one origin. It reads no file: the password
// files load lazily on first use (credfile).
func Parse(getenv func(string) string, opt credfile.Options) (*Set, []string, error) {
	set := &Set{legacy: map[string]bool{}}
	var warnings []string
	owner := map[string]string{} // origin -> backend, to refuse ambiguity

	for _, fam := range families() {
		var legacyVars []string
		for _, v := range fam.urlEnvs {
			if HasUserinfo(getenv(v)) {
				set.legacy[v] = true
				legacyVars = append(legacyVars, v)
			}
		}
		user := strings.TrimSpace(getenv(fam.userEnv))
		file := strings.TrimSpace(getenv(fam.fileEnv))
		switch {
		case user == "" && file == "":
			for _, v := range legacyVars {
				warnings = append(warnings, fmt.Sprintf(
					"%s carries a credential in its URL userinfo — still honoured for one release; move it to %s + %s (tracker 367). The URL value is not logged.",
					v, fam.userEnv, fam.fileEnv))
			}
			continue
		case user == "" || file == "":
			return nil, nil, fmt.Errorf("%s and %s must be set together (got %s=%t, %s=%t)",
				fam.userEnv, fam.fileEnv, fam.userEnv, user != "", fam.fileEnv, file != "")
		}

		pw, err := credfile.New(file, opt)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", fam.fileEnv, err)
		}
		basic, err := credfile.NewBasic(user, pw)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", fam.userEnv, err)
		}
		cred := &Credential{backend: fam.backend, origins: map[string]struct{}{}, basic: basic}

		type named struct{ name, raw string }
		var raws []named
		for _, v := range fam.urlEnvs {
			if r := strings.TrimSpace(getenv(v)); r != "" {
				raws = append(raws, named{v, r})
			}
		}
		if len(raws) == 0 {
			raws = []named{{"default " + fam.backend + " URL", fam.defaultURL}}
		}
		for _, n := range raws {
			u, err := url.Parse(n.raw)
			if err != nil {
				// url.Parse quotes the input — which may carry userinfo — so
				// the error is reported by variable name only.
				return nil, nil, fmt.Errorf("%s is not a valid URL", n.name)
			}
			o := OriginOf(u)
			if o == "" {
				return nil, nil, fmt.Errorf("%s must be an http(s) URL with a host to carry %s", n.name, fam.fileEnv)
			}
			if prev, taken := owner[o]; taken && prev != fam.backend {
				return nil, nil, fmt.Errorf("%s and the %s backend resolve to the same origin %s — a credential must be bound to exactly one backend", n.name, prev, o)
			}
			owner[o] = fam.backend
			cred.origins[o] = struct{}{}
			if strings.EqualFold(u.Scheme, "http") {
				warnings = append(warnings, fmt.Sprintf(
					"%s is plaintext http:// — the %s Basic credential (%s) is sent unencrypted; use https:// via the TLS variant",
					n.name, fam.backend, fam.userEnv))
			}
		}
		for _, v := range legacyVars {
			warnings = append(warnings, fmt.Sprintf(
				"%s carries a credential in its URL userinfo AND %s is set — the file wins and the userinfo is stripped from every request; remove it from %s (tracker 367)",
				v, fam.fileEnv, v))
		}
		set.creds = append(set.creds, cred)
	}
	return set, warnings, nil
}

// ErrCredentialUnavailable marks a request that was refused, unsent, because
// its backend's credential could not be produced.
var ErrCredentialUnavailable = errors.New("backend credential unavailable — request not sent")

// Transport attaches credentials and strips userinfo:
//
//   - the URL's userinfo is ALWAYS removed from the outgoing request, so it
//     cannot reach the wire, a proxy log or an error string;
//   - an Authorization header the CALLER set is never overridden;
//   - a configured file credential is attached only when the request origin
//     matches the origin it was configured for, and it wins over userinfo;
//   - if that credential cannot be produced the request is refused, unsent;
//   - legacy: userinfo on a URL with no file credential is still applied.
//
// net/http's Client already turns URL userinfo into a Basic header before the
// transport runs (client.go send) — the comment this replaced claimed it did
// not. That header is recognised here as userinfo-derived, not
// caller-explicit, by comparing it with the userinfo's own encoding, which is
// what lets the file win.
type Transport struct {
	Base  http.RoundTripper
	Creds func() *Set // nil, or returning nil, means "no file credentials"
}

// RoundTrip implements http.RoundTripper.
func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	derived := ""
	if ui := req.URL.User; ui != nil {
		pass, _ := ui.Password()
		derived = BasicHeader(ui.Username(), pass)
	}
	explicit := req.Header.Get("Authorization")

	var cred *Credential
	if t.Creds != nil {
		cred = t.Creds().ForOrigin(OriginOf(req.URL))
	}

	header := ""
	switch {
	case explicit != "" && explicit != derived:
		// The caller's own Authorization: leave it exactly as set.
	case cred != nil:
		h, err := cred.basic.Header()
		if err != nil {
			// RoundTripper contract: the body is closed even on error.
			if req.Body != nil {
				_ = req.Body.Close() // nothing was sent; a close error changes nothing
			}
			return nil, fmt.Errorf("%w (%s): %w", ErrCredentialUnavailable, cred.backend, err)
		}
		header = h
	case derived != "":
		header = derived
	}

	if req.URL.User == nil && header == "" {
		return t.Base.RoundTrip(req)
	}
	// Clone before mutating — a RoundTripper must not modify the caller's
	// request (net/http contract). Clone deep-copies URL and Header.
	out := req.Clone(req.Context())
	out.URL.User = nil
	if header != "" {
		out.Header.Set("Authorization", header)
	}
	return t.Base.RoundTrip(out)
}

// BasicHeader is the Authorization value net/http produces for user:pass.
func BasicHeader(user, pass string) string {
	r := &http.Request{Header: http.Header{}}
	r.SetBasicAuth(user, pass)
	return r.Header.Get("Authorization")
}

// CheckRedirect keeps net/http's 10-hop limit and drops credentials on any
// hop that leaves the original origin. net/http already strips Authorization
// when the HOSTNAME changes, but keeps it across a port change or into a
// subdomain; the origin rule here is stricter. (Transport never attaches a
// file credential off-origin either way.)
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && OriginOf(req.URL) != OriginOf(via[0].URL) {
		req.Header.Del("Authorization")
		req.URL.User = nil
	}
	return nil
}

// WriteMetrics renders the credential gauges in Prometheus exposition format.
func WriteMetrics(w io.Writer, set *Set) {
	fmt.Fprintf(w, "# HELP netops_config_url_credential Whether a backend URL env var still carries a credential in its userinfo (1 = legacy form in use; move it to *_AUTH_PASSWORD_FILE, tracker 367).\n")
	fmt.Fprintf(w, "# TYPE netops_config_url_credential gauge\n")
	for _, v := range URLVars() {
		n := 0
		if set.Legacy(v) {
			n = 1
		}
		fmt.Fprintf(w, "netops_config_url_credential{var=%q} %d\n", v, n)
	}
	creds := set.Credentials()
	if len(creds) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP netops_backend_credential_loaded Whether a file-backed backend credential holds a valid value (0 = every request to that backend is refused).\n")
	fmt.Fprintf(w, "# TYPE netops_backend_credential_loaded gauge\n")
	for _, c := range creds {
		loaded, _, _ := c.basic.File().Status()
		n := 0
		if loaded {
			n = 1
		}
		fmt.Fprintf(w, "netops_backend_credential_loaded{backend=%q} %d\n", c.backend, n)
	}
	fmt.Fprintf(w, "# HELP netops_backend_credential_reload_errors_total Failed re-reads of a backend credential file (the last good value is kept).\n")
	fmt.Fprintf(w, "# TYPE netops_backend_credential_reload_errors_total counter\n")
	for _, c := range creds {
		_, failures, _ := c.basic.File().Status()
		fmt.Fprintf(w, "netops_backend_credential_reload_errors_total{backend=%q} %d\n", c.backend, failures)
	}
}
