// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package corsallow is the cross-origin allowlist (SR-005, tracker 439): the
// web addresses of a customer's own apps that may call the API from a browser —
// what the real-user tag needs, since it posts from the customer's pages to
// Correlix. It is platform-GLOBAL plumbing (CLAUDE.md §3a rule 3): one list for
// the stack, changed only by the platform administrator.
//
// The list was environment-only (CORS_ALLOWED_ORIGINS), read once at start, and
// customers never edit .env. It is now a saved setting, read LIVE by the CORS
// middleware and the WebSocket origin check. The environment value stays as the
// seed: a saved list wins over it (the Features-page rule), and "reset" returns
// to it.
//
// An origin is a scheme and a host, with an optional port — exactly what a
// browser sends in the Origin header. Nothing looser is accepted: no `*`, no
// wildcards, no path, query, fragment or credentials, and plain http only for a
// developer's own machine (localhost, 127.0.0.1, [::1]).
package corsallow

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Bounds on the list. A real deployment allows a handful of apps; the caps keep
// a pasted mistake (or an abuse) from becoming an unbounded set on every request.
const (
	MaxOrigins   = 50
	MaxOriginLen = 300
)

// ErrInvalid wraps every refusal of an origin or a list.
var ErrInvalid = errors.New("invalid web address")

// devHosts are the only hosts plain http is accepted for.
var devHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// Normalize returns the canonical form of one origin — lower-case scheme and
// host, the default port dropped — or an error saying, in plain words, why it
// is refused. The canonical form is what a browser puts in its Origin header,
// so a match is a plain string comparison.
func Normalize(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return "", fmt.Errorf("%w: empty", ErrInvalid)
	case len(s) > MaxOriginLen:
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalid, MaxOriginLen)
	case strings.Contains(s, "*"):
		return "", fmt.Errorf("%w: %q — wildcards are never allowed; list each app's address", ErrInvalid, s)
	case strings.ContainsAny(s, " \t\r\n?#\\"):
		return "", fmt.Errorf("%w: %q — only a scheme and a host (and port), like https://app.example.com", ErrInvalid, s)
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("%w: %q — write it like https://app.example.com", ErrInvalid, s)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: %q — a web address with a user name or password is not an origin", ErrInvalid, s)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%w: %q — no path; just the scheme and host, like https://app.example.com", ErrInvalid, s)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || !validHost(host) {
		return "", fmt.Errorf("%w: %q — the host name is not valid", ErrInvalid, s)
	}
	switch scheme {
	case "https":
	case "http":
		if !devHosts[host] {
			return "", fmt.Errorf("%w: %q — use https; plain http is accepted only for localhost", ErrInvalid, s)
		}
	default:
		return "", fmt.Errorf("%w: %q — the address must start with https://", ErrInvalid, s)
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("%w: %q — the port is empty", ErrInvalid, s)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("%w: %q — the port must be a number from 1 to 65535", ErrInvalid, s)
		}
		port = strconv.Itoa(n) // "0443" → "443"
		if (scheme == "https" && n == 443) || (scheme == "http" && n == 80) {
			port = "" // a browser omits the default port from Origin
		}
	}
	hostPart := host
	if strings.Contains(host, ":") { // IPv6 literal
		hostPart = "[" + host + "]"
	}
	if port != "" {
		hostPart = net.JoinHostPort(host, port)
	}
	return scheme + "://" + hostPart, nil
}

// validHost accepts an IP literal or a DNS name of letters, digits, hyphens and
// dots (an internationalised name must be given in its xn-- form, which is what
// the browser sends).
func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidateList normalizes every entry, drops exact duplicates (first wins, order
// kept) and refuses the WHOLE list if any entry is invalid — naming every bad
// entry at once, so the operator fixes them in one pass.
func ValidateList(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	var bad []string
	for _, raw := range in {
		o, err := Normalize(raw)
		if err != nil {
			bad = append(bad, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
			continue
		}
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(bad, "; "))
	}
	if len(out) > MaxOrigins {
		return nil, fmt.Errorf("%w: %d web addresses, at most %d", ErrInvalid, len(out), MaxOrigins)
	}
	return out, nil
}

// ParseEnv splits the comma-separated environment value into its valid origins
// and the entries it had to drop (each with its reason). The environment is a
// seed written by an installer or by hand, so a bad entry there is reported,
// not fatal: the rest still apply.
func ParseEnv(raw string) (origins []string, dropped []string) {
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		o, err := Normalize(part)
		if err != nil {
			dropped = append(dropped, err.Error())
			continue
		}
		if !seen[o] && len(origins) < MaxOrigins {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	return origins, dropped
}
