// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

// fetch_test.go — the SSRF gate. Every case here is an input a THIRD PARTY can
// choose (a geofeed URL published in a whois remark), so a regression is a
// server-side request forgery, not a cosmetic bug. Nothing touches the network.

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSafeOutboundURLRefusesEverythingButPublicHTTPS(t *testing.T) {
	bad := []string{
		"http://example.com/feed.csv",              // plaintext
		"ftp://example.com/feed.csv",               // wrong scheme
		"file:///etc/passwd",                       // local file
		"gopher://example.com/",                    //
		"https://user:pass@example.com/feed.csv",   // credential smuggling
		"https://example.com:8080/feed.csv",        // non-443 (internal admin port)
		"https://127.0.0.1/feed.csv",               // loopback literal
		"https://[::1]/feed.csv",                   // v6 loopback literal
		"https://10.1.2.3/feed.csv",                // RFC1918 literal
		"https://192.168.0.1/feed.csv",             //
		"https://172.16.0.1/feed.csv",              //
		"https://169.254.169.254/latest/meta-data", // cloud metadata
		"https://100.64.0.1/feed.csv",              // CGNAT
		"https://0.0.0.0/feed.csv",                 //
		"https://[fd00::1]/feed.csv",               // unique-local v6
		"https://[fe80::1]/feed.csv",               // link-local v6
		"https:///feed.csv",                        // no host
		"",                                         //
		"   ",                                      //
	}
	for _, u := range bad {
		if got, err := SafeOutboundURL(u); err == nil {
			t.Errorf("SafeOutboundURL(%q) ACCEPTED %v — SSRF hole", u, got)
		}
	}
	good := []string{
		"https://api.cloudflare.com/local-ip-ranges.csv",
		"https://example.com:443/geofeed.csv",
		"https://8.8.8.8/feed.csv",
	}
	for _, u := range good {
		if _, err := SafeOutboundURL(u); err != nil {
			t.Errorf("SafeOutboundURL(%q) refused a legitimate URL: %v", u, err)
		}
	}
}

func TestCheckDialAddressIsTheSecondHalfOfTheGate(t *testing.T) {
	// A hostname that PASSES the URL gate can still resolve to a private
	// address. These are the addresses the dialer must refuse.
	for _, a := range []string{
		"127.0.0.1:443", "10.0.0.5:443", "169.254.169.254:443",
		"192.168.1.1:443", "[::1]:443", "[fd12::1]:443", "0.0.0.0:443",
		"100.100.100.200:443", "240.0.0.1:443", "[::ffff:127.0.0.1]:443",
	} {
		if err := CheckDialAddress(a); err == nil {
			t.Errorf("CheckDialAddress(%q) allowed a non-public dial — DNS rebinding is open", a)
		}
	}
	for _, a := range []string{"104.28.0.1:443", "[2606:4700::1]:443"} {
		if err := CheckDialAddress(a); err != nil {
			t.Errorf("CheckDialAddress(%q) refused a public dial: %v", a, err)
		}
	}
	if err := CheckDialAddress("not-an-address"); err == nil {
		t.Error("an unparsable dial address must be refused, not allowed")
	}
	if err := CheckDialAddress("example.com:443"); err == nil {
		t.Error("a non-IP dial address must be refused (the Control hook only ever sees IPs)")
	}
}

func TestPublicAddrClassification(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "193.0.0.1": true,
		"2606:4700::1": true,
		"127.0.0.1":    false, "10.0.0.1": false, "172.31.255.255": false,
		"192.168.1.1": false, "169.254.1.1": false, "100.64.0.1": false,
		"224.0.0.1": false, "255.255.255.255": false, "0.0.0.0": false,
		"192.0.0.1": false, "fd00::1": false, "fe80::1": false, "::": false,
	}
	for s, want := range cases {
		a := netip.MustParseAddr(s)
		if got := publicAddr(a); got != want {
			t.Errorf("publicAddr(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestClipIsRuneSafe(t *testing.T) {
	if got := clip(strings.Repeat("a", 10)+"🌍", 12); !isValidUTF8(got) {
		t.Fatalf("clip split a rune: %q", got)
	}
	if got := clip("abc", 10); got != "abc" {
		t.Fatalf("clip shortened a short string: %q", got)
	}
	if got := clip("abcdef", 3); got != "abc" {
		t.Fatalf("clip = %q, want abc", got)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}
