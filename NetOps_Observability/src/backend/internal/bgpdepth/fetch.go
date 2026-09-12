// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Fetcher is the ONLY way this package reaches the network. The root package
// supplies the real implementation (bgp_ops.go's cached RIPEstat/RDAP client);
// every test supplies a fake, which is what keeps CI offline (§11).
type Fetcher interface {
	// RIPEstat performs a RIPEstat data call and returns the "data" object.
	// extra is an already-escaped query fragment ("prefix=1.2.3.0%2F24").
	RIPEstat(ctx context.Context, call, resource, extra string, ttl time.Duration) (json.RawMessage, error)
	// Get fetches an ARBITRARY absolute https URL discovered from untrusted
	// registry data. Implementations MUST enforce SafeOutboundURL, cap the
	// response at maxBytes and apply a hard timeout.
	Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error)
}

// ErrUnsafeURL is returned for any URL that fails the SSRF gate.
var ErrUnsafeURL = errors.New("bgpdepth: refused unsafe outbound URL")

// SafeOutboundURL validates a URL that came from UNTRUSTED external data (a
// whois remark, an operator-configured provider). It is the first half of the
// SSRF gate; CheckDialAddress is the second and non-optional half, because a
// hostname that passes here can still resolve to 127.0.0.1.
//
// Rules: absolute https only, a real host, no userinfo (credential smuggling
// into a log), no explicit non-443 port (a geofeed lives on the web, not on an
// internal admin port), and a literal-IP host must already be public.
func SafeOutboundURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q (https only)", ErrUnsafeURL, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: URL carries userinfo", ErrUnsafeURL)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: no host", ErrUnsafeURL)
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, fmt.Errorf("%w: port %q (443 only)", ErrUnsafeURL, p)
	}
	if addr, err := netip.ParseAddr(host); err == nil && !publicAddr(addr) {
		return nil, fmt.Errorf("%w: host %s is not a public address", ErrUnsafeURL, host)
	}
	return u, nil
}

// CheckDialAddress is the second — and non-optional — half of the SSRF gate.
// The caller wires it into net.Dialer.Control, so it runs AFTER DNS resolution
// on the address actually being dialed: a hostname that resolves to
// 169.254.169.254 (cloud metadata) or 10.x (the customer's own network) is
// stopped even though the URL looked fine. This closes the DNS-rebinding hole
// SafeOutboundURL alone cannot. Kept syscall-free so this package stays
// portable; the root does the two-line net.Dialer wiring.
func CheckDialAddress(address string) error { return checkDialAddress(address) }

// checkDialAddress refuses any dial to a non-public address.
func checkDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable dial address", ErrUnsafeURL)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: non-IP dial address", ErrUnsafeURL)
	}
	if !publicAddr(addr) {
		return fmt.Errorf("%w: refused to dial non-public address %s", ErrUnsafeURL, addr)
	}
	return nil
}

// publicAddr reports whether addr is a globally routable unicast address.
// Everything else — loopback, link-local (incl. 169.254.169.254), private,
// CGNAT, multicast, unspecified, IPv4-mapped v6, unique-local v6 — is refused.
func publicAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch {
	case !addr.IsValid(),
		addr.IsLoopback(), addr.IsUnspecified(), addr.IsMulticast(),
		addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(), addr.IsPrivate():
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 0, // "this network"
			b[0] == 100 && b[1] >= 64 && b[1] <= 127, // CGNAT 100.64/10
			b[0] == 127,
			b[0] == 192 && b[1] == 0 && b[2] == 0, // IETF protocol assignments
			b[0] >= 240:                           // reserved / broadcast
			return false
		}
		return true
	}
	// IPv6: refuse unique-local (fc00::/7). Everything else that mattered
	// (loopback, link-local, multicast, unspecified) was rejected above.
	b := addr.As16()
	return b[0]&0xfe != 0xfc
}

// urlEscape escapes a value for a query fragment. Kept here so every outbound
// URL this package composes goes through exactly one escaper.
func urlEscape(v string) string { return url.QueryEscape(v) }

// clip bounds an untrusted upstream string WITHOUT splitting a UTF-8 rune —
// the same discipline the watchlist note uses. Everything this package copies
// out of a third-party payload passes through it.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.ToValidUTF8(s[:cut], "")
}

// ── error text that cannot carry a URL ──────────────────────────────────────

// SafeErrorText renders err as text that cannot contain any of the given URLs.
//
// WHY THIS EXISTS. Go's http.Client wraps every transport failure in a
// *url.Error, and its Error() prints the FULL request URL. The URLs this
// package fetches are operator-configured (BGP_ASPA_PROVIDER_URL) or discovered
// in untrusted registry data, and an operator's own validator endpoint may
// authenticate with a query-string token. SafeOutboundURL already refuses
// userinfo for exactly that reason; it cannot refuse a query parameter, because
// that is how the query is legitimately carried. So the credential rides inside
// the error, and these errors are handed to readers: the ASPA route puts one in
// a 200 body for any infrastructure:read caller (CLAUDE.md §8).
//
// TWO MECHANISMS, because one is not enough:
//
//  1. *url.Error is rebuilt as "<op> <hostname>: <cause>". The hostname is kept
//     deliberately — an operator has to be able to tell WHICH upstream failed,
//     which is the same trade ASPAStatus.Host already makes. The cause names a
//     dial address or a TLS fault, never a query.
//  2. Every supplied URL is then removed from whatever text is left, along with
//     its raw query and any query value long enough to be a credential. A
//     Fetcher implementation is free to format the URL into its own error text
//     and no interface can stop it, so the boundary must survive that too.
//
// The result is clipped: an upstream does not get to write an unbounded string
// into a response body.
func SafeErrorText(err error, urls ...string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		op := strings.ToLower(strings.TrimSpace(ue.Op))
		if op == "" {
			op = "request"
		}
		cause := "the request failed"
		if ue.Err != nil {
			cause = ue.Err.Error()
		}
		if host := urlHostname(ue.URL); host != "" {
			msg = op + " " + host + ": " + cause
		} else {
			msg = op + ": " + cause
		}
		// The URL that produced the error is itself something to scrub from the
		// cause text, whether or not the caller thought to pass it in.
		urls = append(urls, ue.URL)
	}
	for _, raw := range urls {
		msg = scrubURL(msg, raw)
	}
	return clip(strings.TrimSpace(msg), 200)
}

// SafeFetchError is SafeErrorText as an error, for returning from a fetch.
//
// It deliberately does NOT wrap the original: an Unwrap would hand the
// *url.Error, and its URL, straight back to any caller that reached for
// errors.As. Nothing in this package matches on a fetch error's identity, so
// there is nothing to lose and a leak to close.
func SafeFetchError(err error, urls ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(SafeErrorText(err, urls...))
}

// urlHostname returns raw's hostname, or "" when it has none.
func urlHostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// scrubURL removes one URL — and any query hung off the same origin — from a
// message, leaving the hostname in its place.
func scrubURL(msg, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return msg
	}
	repl := "the configured URL"
	u, err := url.Parse(raw)
	if err == nil && u.Hostname() != "" {
		repl = u.Hostname()
	}
	if err == nil && u.Scheme != "" && u.Host != "" {
		// The big hammer: anything in the message that STARTS with this origin
		// is a URL, whatever query an implementation hung off it, so the whole
		// token goes. This is what makes the scrub independent of the exact
		// string we happened to request.
		msg = stripURLToken(msg, u.Scheme+"://"+u.Host, repl)
	}
	msg = strings.ReplaceAll(msg, raw, repl)
	if err != nil {
		return msg
	}
	if q := u.RawQuery; q != "" {
		msg = strings.ReplaceAll(msg, q, "...")
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			// Short values are identifiers (an ASN, a version); anything longer
			// is the shape a token takes and is removed on sight.
			if len(v) >= 8 {
				msg = strings.ReplaceAll(msg, v, "[redacted]")
			}
		}
	}
	return msg
}

// stripURLToken replaces every whitespace-delimited token in msg that begins
// with origin ("https://host") by repl.
//
// The offsets here are measured on msg and used on msg, which is the whole
// point: see internal/asciifold for what happens when they are not.
func stripURLToken(msg, origin, repl string) string {
	if origin == "" || strings.Contains(repl, origin) {
		return msg // a replacement containing the origin would never terminate
	}
	for {
		i := strings.Index(msg, origin)
		if i < 0 {
			return msg
		}
		j := i + len(origin)
		for j < len(msg) && !isURLBreak(msg[j]) {
			j++
		}
		msg = msg[:i] + repl + msg[j:]
	}
}

// isURLBreak reports whether c ends a URL inside a sentence.
func isURLBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', ')', '}', ']', '>':
		return true
	}
	return false
}
