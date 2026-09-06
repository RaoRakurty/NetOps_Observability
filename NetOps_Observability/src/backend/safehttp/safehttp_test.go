// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package safehttp

import (
	"net"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"169.254.169.254", // cloud metadata (link-local)
		"10.1.2.3",        // RFC1918
		"192.168.1.1",     // RFC1918
		"172.16.0.5",      // RFC1918
		"100.64.0.1",      // CGNAT
		"0.0.0.0",         // unspecified
		"::1",             // IPv6 loopback
		"fc00::1",         // IPv6 ULA
		"fe80::1",         // IPv6 link-local
		"224.0.0.1",       // multicast
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); ip == nil || !blockedIP(ip) {
			t.Errorf("%s should be blocked", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range public {
		if ip := net.ParseIP(s); ip == nil || blockedIP(ip) {
			t.Errorf("%s should NOT be blocked", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	if err := ValidateURL("10.0.0.1"); err == nil {
		t.Error("private literal IP host must be rejected")
	}
	if err := ValidateURL("169.254.169.254"); err == nil {
		t.Error("cloud-metadata IP must be rejected")
	}
	if err := ValidateURL("8.8.8.8"); err != nil {
		t.Errorf("public IP must pass: %v", err)
	}
	// Empty host (relative/unset) is a no-op — the dialer still guards it.
	if err := ValidateURL(""); err != nil {
		t.Errorf("empty host must be a no-op: %v", err)
	}
}

func TestAllowlistBypass(t *testing.T) {
	t.Setenv("SSRF_ALLOWED_HOSTS", "10.0.0.0/8,192.168.5.5")
	if !allowlisted(net.ParseIP("10.9.9.9")) {
		t.Error("CIDR allowlist must match 10.9.9.9")
	}
	if !allowlisted(net.ParseIP("192.168.5.5")) {
		t.Error("exact-IP allowlist must match 192.168.5.5")
	}
	if allowlisted(net.ParseIP("192.168.5.6")) {
		t.Error("192.168.5.6 must NOT be allowlisted")
	}
	if err := ValidateURL("10.1.1.1"); err != nil {
		t.Errorf("allowlisted private IP must pass ValidateURL: %v", err)
	}
}

func TestAllowPrivateEscape(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	if err := ValidateURL("10.0.0.1"); err != nil {
		t.Errorf("SSRF_ALLOW_PRIVATE=true must allow private targets: %v", err)
	}
}
