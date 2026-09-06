// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// helpers.go — the package's own small primitives. Duplicated rather than
// shared through a "utils" package (CLAUDE.md §2 forbids the dumping ground),
// exactly as internal/bgpdepth and secapi each keep their own.

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// normTenant is the ONE tenant-key normalization in this package, matching the
// API boundary's (lowercase, trimmed).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// concreteTenant fails CLOSED on a write/read that has no single tenant to
// scope to. "" and "*" are refused at the store, so no future caller can
// reintroduce a wildcard (§3a, the bgpWatchTenant precedent).
func concreteTenant(t string) (string, error) {
	n := normTenant(t)
	if n == "" || n == "*" {
		return "", errors.New("bgpwatch: a concrete tenant is required (cross-tenant access is refused)")
	}
	return n, nil
}

// clip bounds an untrusted string WITHOUT splitting a UTF-8 rune.
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

// parsePrefix parses a canonical prefix. A bare address is accepted as its host
// prefix, matching the API boundary's bgpNormalizeResource.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits), nil
}

// ParseASN parses "AS64500" or "64500" into an ASN. AS0 is reserved (RFC 7607)
// and is refused, so it can never enter a declared set.
func ParseASN(raw string) (uint32, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	s = strings.TrimPrefix(s, "As")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, errors.New("not an ASN: " + clip(raw, 32))
	}
	if n == 0 {
		return 0, errors.New("AS0 is reserved (RFC 7607) and is never a real ASN")
	}
	return uint32(n), nil
}

// sleepCtx sleeps for d or until ctx is done. The injectable clock seam every
// bounded loop in this package uses, so tests are deterministic and no test
// ever actually waits.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
