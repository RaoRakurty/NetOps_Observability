// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probetarget

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func ownedSet(addrs ...string) Owned {
	m := map[netip.Addr]bool{}
	for _, a := range addrs {
		m[netip.MustParseAddr(a)] = true
	}
	return func(a netip.Addr) bool { return m[a] }
}

// TestCheckTable is the safety table: what is never probed, what is probed
// only when it is the caller's own device, and what is probed.
func TestCheckTable(t *testing.T) {
	own := ownedSet("10.0.0.5", "172.16.4.1", "192.168.222.101", "100.64.1.1", "fd12::5")
	cases := []struct {
		addr string
		ok   bool
		why  string
	}{
		// Always refused, even when an inventory row claims the address.
		{"127.0.0.1", false, "loopback"},
		{"::1", false, "loopback v6"},
		{"::ffff:127.0.0.1", false, "mapped loopback"},
		{"169.254.169.254", false, "cloud metadata (link-local)"},
		{"169.254.10.10", false, "link-local"},
		{"fe80::1", false, "link-local v6"},
		{"100.100.100.200", false, "Alibaba metadata"},
		{"fd00:ec2::254", false, "AWS IPv6 metadata"},
		{"0.0.0.0", false, "unspecified"},
		{"0.1.2.3", false, "this network"},
		{"::", false, "unspecified v6"},
		{"224.0.0.1", false, "multicast"},
		{"ff02::1", false, "multicast v6"},
		{"255.255.255.255", false, "broadcast"},
		{"240.0.0.1", false, "reserved"},
		// Internal space: only the caller's own devices.
		{"10.0.0.5", true, "own device (RFC 1918)"},
		{"10.0.0.6", false, "someone else's RFC 1918 address"},
		{"172.16.4.1", true, "own device 172.16/12"},
		{"172.31.255.1", false, "unowned 172.16/12"},
		{"192.168.222.101", true, "own device 192.168/16"},
		{"192.168.1.1", false, "unowned 192.168/16"},
		{"100.64.1.1", true, "own device CGNAT"},
		{"100.64.9.9", false, "unowned CGNAT"},
		{"198.18.0.1", false, "unowned benchmark range"},
		{"fd12::5", true, "own device ULA"},
		{"fd12::6", false, "unowned ULA"},
		// Public unicast.
		{"93.184.216.34", true, "public v4"},
		{"2606:4700:4700::1111", true, "public v6"},
	}
	for _, c := range cases {
		err := Check(netip.MustParseAddr(c.addr), own)
		if (err == nil) != c.ok {
			t.Errorf("%s (%s): ok=%v, err=%v", c.addr, c.why, err == nil, err)
		}
		if err != nil {
			if !errors.Is(err, ErrRefused) {
				t.Errorf("%s: refusal does not match ErrRefused: %v", c.addr, err)
			}
			if strings.Contains(err.Error(), c.addr) {
				t.Errorf("%s: refusal names the address: %q", c.addr, err.Error())
			}
		}
	}
}

// TestOwnershipCannotUnlockRefusedSpace: an inventory row naming the metadata
// address or loopback does not make it probeable.
func TestOwnershipCannotUnlockRefusedSpace(t *testing.T) {
	own := ownedSet("169.254.169.254", "127.0.0.1", "100.100.100.200")
	for _, a := range []string{"169.254.169.254", "127.0.0.1", "100.100.100.200"} {
		if err := Check(netip.MustParseAddr(a), own); err == nil {
			t.Errorf("%s was allowed because an inventory row claimed it", a)
		}
	}
	if err := Check(netip.MustParseAddr("10.1.1.1"), nil); err == nil {
		t.Error("nil ownership allowed an internal address")
	}
	if Classify(netip.Addr{}) != ClassRefused {
		t.Error("the zero address is not refused")
	}
}

func lookupOf(m map[string][]string) Lookup {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		raw, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, r := range raw {
			out = append(out, netip.MustParseAddr(r))
		}
		return out, nil
	}
}

// TestResolveRebindingAndPinning: a declared name that resolves into internal
// space is refused (the rebinding shape); a name mixing one refused answer
// with good ones is refused whole; a good name is pinned to an IPv4 answer.
func TestResolveRebindingAndPinning(t *testing.T) {
	ctx := context.Background()
	own := ownedSet("10.0.0.5")
	lk := lookupOf(map[string][]string{
		"portal.example":   {"2606:4700::1", "93.184.216.34"},
		"rebind.example":   {"10.9.9.9"},
		"metadata.example": {"169.254.169.254"},
		"mixed.example":    {"93.184.216.34", "127.0.0.1"},
		"owned.example":    {"10.0.0.5"},
	})
	a, err := Resolve(ctx, lk, "portal.example.", own)
	if err != nil || a.String() != "93.184.216.34" {
		t.Fatalf("public name: %v %v (want the IPv4 answer pinned)", a, err)
	}
	for _, h := range []string{"rebind.example", "metadata.example", "mixed.example"} {
		if _, err := Resolve(ctx, lk, h, own); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: got %v, want a refusal", h, err)
		}
	}
	if a, err := Resolve(ctx, lk, "owned.example", own); err != nil || a.String() != "10.0.0.5" {
		t.Errorf("a name resolving to the caller's own device: %v %v", a, err)
	}
	if _, err := Resolve(ctx, lk, "missing.example", own); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("an unresolvable name should fail without a refusal: %v", err)
	}
	if _, err := Resolve(ctx, nil, "portal.example", own); !errors.Is(err, ErrRefused) {
		t.Errorf("no resolver must refuse a name: %v", err)
	}
	if _, err := Resolve(ctx, lk, "  ", own); !errors.Is(err, ErrRefused) {
		t.Errorf("an empty host must be refused: %v", err)
	}
	// Literals are checked too, including bracketed IPv6.
	if _, err := Resolve(ctx, lk, "[::1]", own); !errors.Is(err, ErrRefused) {
		t.Errorf("a bracketed loopback literal was not refused: %v", err)
	}
	if a, err := Resolve(ctx, lk, "10.0.0.5", own); err != nil || a.String() != "10.0.0.5" {
		t.Errorf("an owned literal: %v %v", a, err)
	}
}

func TestLimiterWindowAndKeys(t *testing.T) {
	now := time.Unix(1_000, 0)
	l := NewLimiter(func() time.Time { return now })
	for i := 0; i < 2; i++ {
		if !l.Allow("t1|a", 2) {
			t.Fatalf("call %d refused under the limit", i+1)
		}
	}
	if l.Allow("t1|a", 2) {
		t.Fatal("third call in the window was allowed")
	}
	if !l.Allow("t1|b", 2) || !l.Allow("t2|a", 2) {
		t.Fatal("another target or another tenant shares the budget")
	}
	now = now.Add(time.Minute)
	if !l.Allow("t1|a", 2) {
		t.Fatal("the window did not roll over")
	}
	var nilL *Limiter
	if nilL.Allow("x", 5) || l.Allow("x", 0) {
		t.Fatal("a nil limiter or a zero budget allowed a probe")
	}
}

func TestSlots(t *testing.T) {
	s := NewSlots(1)
	rel, ok := s.TryAcquire()
	if !ok {
		t.Fatal("first slot refused")
	}
	if _, ok2 := s.TryAcquire(); ok2 {
		t.Fatal("second concurrent probe admitted with one slot")
	}
	rel()
	if _, ok3 := s.TryAcquire(); !ok3 {
		t.Fatal("slot not returned")
	}
	var nilS *Slots
	if _, ok4 := nilS.TryAcquire(); ok4 {
		t.Fatal("nil slots admitted a probe")
	}
}
