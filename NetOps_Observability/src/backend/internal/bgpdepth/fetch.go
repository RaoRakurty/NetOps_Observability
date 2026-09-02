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
		return nil, fmt.Errorf("%w: %v", ErrUnsafeURL, err)
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
