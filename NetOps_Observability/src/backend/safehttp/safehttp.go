// Package safehttp provides an SSRF-hardened HTTP client for outbound calls to
// operator/tenant-configurable destinations (SR-015): notification webhooks and
// ITSM connectors whose URLs an admin can set to an arbitrary host.
//
// Without this, a tenant admin could point ServiceNow.InstanceURL / Jira.BaseURL
// / Slack.WebhookURL at an internal address and have the backend make an
// authenticated request there — probing the internal network, hitting cloud
// metadata (169.254.169.254), or exfiltrating the configured API token to an
// attacker-controlled host.
//
// The guard runs in the dialer Control hook, which fires AFTER DNS resolution
// but BEFORE connect, so it inspects the ACTUAL IP being dialed. That defeats
// DNS-rebinding (a hostname that resolves public on validation then private on
// connect) and is re-checked on every redirect hop.
//
// Legitimately-internal targets (self-hosted ServiceNow/Jira/ntfy/Netbox, or a
// lab fabric) are accommodated via an explicit allowlist:
//
//	SSRF_ALLOWED_HOSTS   comma-separated hostnames, IPs, or CIDRs that bypass the
//	                     private-range block (e.g. "jira.corp.local,10.0.0.0/8")
//	SSRF_ALLOW_PRIVATE   "true" disables the block entirely (single-network / lab
//	                     deployments where every integration target is internal)
package safehttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// maxRedirects bounds redirect chains; each hop is re-validated by the dialer.
const maxRedirects = 5

// Client returns an *http.Client whose dialer refuses to connect to non-public
// addresses (SSRF guard), with the given overall timeout.
func Client(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: guardControl}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			Proxy:                 http.ProxyFromEnvironment,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("safehttp: stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

// guardControl runs after DNS resolution, before connect: address is "ip:port".
func guardControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safehttp: bad dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("safehttp: could not parse resolved address %q", host)
	}
	if allowPrivate() || allowlisted(ip) {
		return nil
	}
	if blockedIP(ip) {
		return fmt.Errorf("safehttp: refusing to connect to non-public address %s (SSRF guard); add it to SSRF_ALLOWED_HOSTS if intentional", ip)
	}
	return nil
}

func allowPrivate() bool { return os.Getenv("SSRF_ALLOW_PRIVATE") == "true" }

// allowlisted reports whether ip is covered by SSRF_ALLOWED_HOSTS (IPs or CIDRs).
// Bare hostnames in the env are resolved here so an allowlisted name's current
// addresses bypass the block.
func allowlisted(ip net.IP) bool {
	raw := strings.TrimSpace(os.Getenv("SSRF_ALLOWED_HOSTS"))
	if raw == "" {
		return false
	}
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(tok); err == nil {
			if cidr.Contains(ip) {
				return true
			}
			continue
		}
		if parsed := net.ParseIP(tok); parsed != nil {
			if parsed.Equal(ip) {
				return true
			}
			continue
		}
		// Hostname: resolve and compare.
		if addrs, err := net.LookupIP(tok); err == nil {
			for _, a := range addrs {
				if a.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

// blockedIP reports whether ip is in a range we never dial for SSRF reasons:
// unspecified, loopback, link-local (incl. 169.254.169.254 cloud metadata),
// private (RFC1918 / IPv6 ULA), CGNAT (100.64.0.0/10), and multicast.
func blockedIP(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return true
	}
	// CGNAT 100.64.0.0/10 — shared address space, not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
	}
	return false
}

// ErrBlocked is returned by ValidateURL for a destination the guard would refuse.
var ErrBlocked = errors.New("destination is a non-public address (SSRF guard)")

// ValidateURL is a config-save-time pre-check (defense in depth + early UX): it
// resolves the host of rawURL and reports ErrBlocked if every resolved address
// would be refused at dial time. The dialer Control hook remains the actual
// enforcement (this can't see rebinding). A host that doesn't resolve yet is
// allowed (it may resolve later) — the dialer still guards it.
func ValidateURL(host string) error {
	if host == "" {
		return nil
	}
	if allowPrivate() {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if allowlisted(ip) || !blockedIP(ip) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrBlocked, ip)
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil // unresolved — let the dialer decide at request time
	}
	for _, a := range addrs {
		if allowlisted(a) || !blockedIP(a) {
			return nil // at least one usable public address
		}
	}
	return fmt.Errorf("%w: %s resolves only to non-public addresses", ErrBlocked, host)
}
