// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package probetarget decides whether Correlix may send an on-demand test
// packet or request to an address (tracker 337 N-I3, design item 14).
//
// Iris's active probes (run_ping, run_traceroute, run_dns_test, run_http_test)
// leave from Correlix's OWN collector — never from a customer device, never
// through a third-party service (owner rule, 2026-11-13). That makes the
// collector a network vantage the model can point, so the target is the attack
// surface: a probe aimed at a cloud metadata service, at the collector's own
// loopback, or at an internal address nobody declared would turn a
// troubleshooting tool into a server-side request forgery primitive.
//
// The rule, applied to every address a target resolves to:
//
//   - ALWAYS refused, whoever claims it: unspecified, loopback, link-local
//     (169.254.0.0/16 and fe80::/10, which covers the 169.254.169.254 metadata
//     service), multicast, broadcast, "this network" 0.0.0.0/8, the reserved
//     240.0.0.0/4, and the known cloud metadata addresses outside link-local
//     (Alibaba 100.100.100.200, AWS IPv6 fd00:ec2::254).
//   - INTERNAL space (RFC 1918, RFC 6598 carrier-grade NAT, RFC 2544
//     benchmarking, IPv6 ULA fc00::/7) is allowed ONLY when the exact address
//     belongs to a device in the caller's own inventory. A declared name that
//     resolves into internal space is refused: that is the DNS-rebinding shape.
//   - Everything else (public unicast) is allowed — the caller still had to
//     name a target it owns (an inventory device or a probe it declared) for
//     the address to be resolved at all; this package never sees free text.
//
// A name that resolves to several addresses is refused if ANY of them is
// refused (no "first good answer" — a resolver that mixes an internal answer
// into a public name is exactly what rebinding looks like), and the address
// that passed is PINNED: the caller dials that address, never the name again.
package probetarget

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Refusal is why an address may not be probed. Its Reason is operator-facing
// and never contains the address itself (a refused address is still the
// customer's data).
type Refusal struct {
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

// ErrRefused matches any Refusal through errors.Is.
var ErrRefused = errors.New("probe target refused")

// Is lets errors.Is(err, ErrRefused) match every Refusal.
func (r *Refusal) Is(target error) bool { return target == ErrRefused }

func refuse(reason string) error { return &Refusal{Reason: reason} }

// metadataAddrs are cloud instance-metadata endpoints OUTSIDE link-local
// space (the link-local rule already covers 169.254.169.254 and fe80::/10).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	benchmark   = netip.MustParsePrefix("198.18.0.0/15")
	broadcast   = netip.MustParseAddr("255.255.255.255")
)

// Class names how an address is treated.
type Class string

const (
	ClassRefused  Class = "refused"  // never probed
	ClassInternal Class = "internal" // probed only when owned
	ClassPublic   Class = "public"   // probed
)

// Classify places an address. IPv4-mapped IPv6 is unmapped first, so
// ::ffff:127.0.0.1 is loopback, not "some IPv6 address".
func Classify(a netip.Addr) Class {
	if !a.IsValid() {
		return ClassRefused
	}
	a = a.Unmap()
	if a.Zone() != "" {
		return ClassRefused // a zoned address is link-scoped by definition
	}
	switch {
	case a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(),
		a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return ClassRefused
	case a == broadcast, thisNetwork.Contains(a), reserved.Contains(a):
		return ClassRefused
	}
	for _, m := range metadataAddrs {
		if a == m {
			return ClassRefused
		}
	}
	if a.IsPrivate() || cgnat.Contains(a) || benchmark.Contains(a) {
		return ClassInternal
	}
	return ClassPublic
}

// Owned answers whether an exact address belongs to a device in the caller's
// own inventory. nil owns nothing.
type Owned func(netip.Addr) bool

// Check decides one address.
func Check(a netip.Addr, owned Owned) error {
	switch Classify(a) {
	case ClassRefused:
		return refuse("that address is never probed (loopback, link-local, metadata, multicast or reserved space)")
	case ClassInternal:
		if owned != nil && owned(a.Unmap()) {
			return nil
		}
		return refuse("that target resolves to an internal address that is not a device in this workspace's inventory")
	default:
		return nil
	}
}

// Lookup resolves a host name to addresses. Injected so tests never touch DNS.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// maxAnswers bounds how many resolved addresses are examined.
const maxAnswers = 16

// Resolve turns a host (a name or an address literal) into ONE address that
// may be probed, applying Check to every answer. The returned address is the
// one to dial; the caller must not resolve the name again.
func Resolve(ctx context.Context, lookup Lookup, host string, owned Owned) (netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return netip.Addr{}, refuse("no target address")
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if cerr := Check(a, owned); cerr != nil {
			return netip.Addr{}, cerr
		}
		return a.Unmap(), nil
	}
	if lookup == nil {
		return netip.Addr{}, refuse("names cannot be resolved here")
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("the target name did not resolve: %w", err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, refuse("the target name resolved to no address")
	}
	if len(addrs) > maxAnswers {
		addrs = addrs[:maxAnswers]
	}
	var pick netip.Addr
	for _, a := range addrs {
		if cerr := Check(a, owned); cerr != nil {
			return netip.Addr{}, cerr // one refused answer refuses the name
		}
		if !pick.IsValid() && a.Unmap().Is4() {
			pick = a.Unmap() // the collectors probe IPv4; prefer an IPv4 answer
		}
	}
	if !pick.IsValid() {
		pick = addrs[0].Unmap()
	}
	return pick, nil
}

// Limiter is a fixed one-minute window per key, swept as windows roll over,
// so its memory is bounded by the keys active in the last minute. It caps how
// often one target is probed, on top of the gateway's per-tool budget.
type Limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	start time.Time
	n     map[string]int
}

// NewLimiter returns a limiter on the given clock (time.Now in production).
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, start: now(), n: map[string]int{}}
}

// Allow reports whether one more probe fits under perMin for key.
func (l *Limiter) Allow(key string, perMin int) bool {
	if l == nil || perMin <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if t := l.now(); t.Sub(l.start) >= time.Minute {
		l.start, l.n = t, map[string]int{}
	}
	if l.n[key] >= perMin {
		return false
	}
	l.n[key]++
	return true
}

// Slots bounds how many probes run at once across the whole process, so a
// burst of investigations cannot turn the collector into a traffic source.
type Slots struct{ ch chan struct{} }

// NewSlots returns a gate admitting n concurrent probes (n < 1 → 1).
func NewSlots(n int) *Slots {
	if n < 1 {
		n = 1
	}
	return &Slots{ch: make(chan struct{}, n)}
}

// TryAcquire takes a slot without waiting; release must be called when true.
func (s *Slots) TryAcquire() (release func(), ok bool) {
	if s == nil {
		return func() {}, false
	}
	select {
	case s.ch <- struct{}{}:
		return func() { <-s.ch }, true
	default:
		return func() {}, false
	}
}
