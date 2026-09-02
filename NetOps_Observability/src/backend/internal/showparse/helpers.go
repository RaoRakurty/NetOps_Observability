package showparse

// helpers.go — the small, shared, allocation-cheap primitives every parser is
// built from.
//
// Deliberately field-splitting and prefix-matching rather than regexp: the
// package's stated bound is "no nested quantifier anywhere", and the simplest
// way to keep that promise is to not reach for a regexp when strings.Fields,
// strings.Cut and strconv already answer the question. Everything here is a
// pure function of its input.

import (
	"strconv"
	"strings"
)

// ── pointer constructors (absent means absent) ──────────────────────────────

func strPtr(s string) *string   { v := s; return &v }
func intPtr(n int) *int         { v := n; return &v }
func i64Ptr(n int64) *int64     { v := n; return &v }
func f64Ptr(f float64) *float64 { v := f; return &v }
func boolPtr(b bool) *bool      { v := b; return &v }

// ── scalar parsing: nil on anything that is not exactly the thing ───────────

// atoiOK parses a decimal integer, tolerating a single trailing "," or ":" or
// "%" that CLI tables routinely append. It returns ok=false for anything else —
// there is no "best effort" number in this package.
func atoiOK(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ",:;%")
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// atofOK parses a decimal float with the same trailing-punctuation tolerance.
func atofOK(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ",:;%")
	s = strings.TrimPrefix(s, "+")
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// ── shape predicates ────────────────────────────────────────────────────────

// looksIPv4 reports whether s is a dotted-quad IPv4 literal (no mask). It is a
// SHAPE test used to recognize a table row, not an address validator.
func looksIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, ok := atoiOK(p)
		if !ok || n < 0 || n > 255 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// looksIPv6 reports whether s has the coarse shape of an IPv6 literal: at least
// two colons' worth of hex groups and nothing outside the hex/colon alphabet.
func looksIPv6(s string) bool {
	if !strings.Contains(s, ":") || len(s) < 3 || len(s) > 45 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == ':':
		default:
			return false
		}
	}
	return true
}

// looksPeerAddress reports whether s could be a BGP peer address.
func looksPeerAddress(s string) bool { return looksIPv4(s) || looksIPv6(s) }

// looksPrefix reports whether s has the shape "<address>/<len>".
func looksPrefix(s string) bool {
	addr, mask, ok := strings.Cut(s, "/")
	if !ok {
		return false
	}
	if n, ok := atoiOK(mask); !ok || n < 0 || n > 128 {
		return false
	}
	return looksIPv4(addr) || looksIPv6(addr)
}

// looksMAC reports whether s is a hardware address in any of the three vendor
// spellings: Cisco dotted (aabb.ccdd.eeff), colon/hyphen separated
// (aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff) or Huawei dotted-quad (aabb-ccdd-eeff).
func looksMAC(s string) bool {
	sep := byte(0)
	switch {
	case strings.Count(s, ".") == 2:
		sep = '.'
	case strings.Count(s, ":") == 5:
		sep = ':'
	case strings.Count(s, "-") == 5, strings.Count(s, "-") == 2:
		sep = '-'
	default:
		return false
	}
	groups := strings.Split(s, string(sep))
	total := 0
	for _, g := range groups {
		if g == "" {
			return false
		}
		for _, c := range g {
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
		total += len(g)
	}
	return total == 12
}

// looksDuration reports whether s is one of the up/down timer spellings CLI
// tables use: "00:12:34", "2d03h", "1w2d", "never", "02h31m11s". It is used to
// recognize a column, never to compute an age.
func looksDuration(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.EqualFold(s, "never") {
		return true
	}
	digits, letters, colons := 0, 0, 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == ':':
			colons++
		case c == '.':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letters++
			if !strings.ContainsRune("dhmswyDHMSWY", c) {
				return false
			}
		default:
			return false
		}
	}
	return digits > 0 && (colons >= 1 || letters >= 1)
}

// ── line / field helpers ────────────────────────────────────────────────────

// fields splits a line on whitespace.
func fields(line string) []string { return strings.Fields(line) }

// trim is strings.TrimSpace, named for readability at call sites.
func trim(s string) string { return strings.TrimSpace(s) }

// hasFold reports whether s contains sub, case-insensitively. Both operands are
// short, so this is a plain scan with no allocation surprises.
func hasFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// isSeparator reports whether a line is a table rule ("-----", "=====", "+---+").
func isSeparator(line string) bool {
	l := trim(line)
	if l == "" {
		return false
	}
	for _, c := range l {
		if c != '-' && c != '=' && c != '+' && c != ' ' {
			return false
		}
	}
	return true
}

// kv splits "  Key : value" (or "Key: value") into key and value, trimmed. ok is
// false when the line carries no colon at all.
func kv(line string) (string, string, bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return trim(k), trim(v), true
}

// kvPairs splits a line carrying one or SEVERAL "Key : value" columns — the
// Nokia SR OS table shape:
//
//	Admin State        : up                     Oper State       : up
//
// It splits on the COLONS, then cuts each middle part at its LAST run of two or
// more spaces: everything left of that run belongs to the previous key's value,
// everything right of it is the next key. That is the only split that survives
// values containing single spaces ("1 Gbps", "64 Bytes") and keys containing
// them ("Min Frame Length"). A line with no colon yields nothing, so prose and
// banner lines contribute no pairs. Keys are lower-cased; values are verbatim.
func kvPairs(line string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return out
	}
	key := trim(parts[0])
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 {
			if key != "" {
				if v := trim(parts[i]); v != "" {
					out[strings.ToLower(key)] = v
				}
			}
			break
		}
		val, next, ok := cutAtLastGap(strings.TrimRight(parts[i], " "))
		if !ok {
			// No column break inside this part: the colon belongs to the value
			// (a MAC address, a timestamp). Refuse the whole line rather than
			// mis-split it.
			return map[string]string{}
		}
		if key != "" && trim(val) != "" {
			out[strings.ToLower(key)] = trim(val)
		}
		key = trim(next)
	}
	return out
}

// cutAtLastGap splits s at its LAST run of two or more spaces.
func cutAtLastGap(s string) (before, after string, ok bool) {
	idx := -1
	for i := 0; i+1 < len(s); i++ {
		if s[i] == ' ' && s[i+1] == ' ' {
			idx = i
		}
	}
	if idx < 0 {
		return "", "", false
	}
	end := idx
	for end < len(s) && s[end] == ' ' {
		end++
	}
	return s[:idx], s[end:], true
}

// valueAfter returns the text following the first occurrence of marker, trimmed,
// and whether the marker was present.
func valueAfter(line, marker string) (string, bool) {
	idx := strings.Index(strings.ToLower(line), strings.ToLower(marker))
	if idx < 0 {
		return "", false
	}
	return trim(line[idx+len(marker):]), true
}

// numberBefore returns the numeric token immediately preceding word in the
// line's field list (e.g. "12 input errors" → 12 for word "input"). It is the
// Cisco counter idiom and is exact: a non-numeric predecessor yields ok=false.
func numberBefore(fs []string, word string) (int64, bool) {
	for i := 1; i < len(fs); i++ {
		if strings.EqualFold(strings.TrimRight(fs[i], ",:"), word) {
			if n, ok := atoiOK(fs[i-1]); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// numberAfter returns the numeric token immediately following word.
func numberAfter(fs []string, word string) (int64, bool) {
	for i := 0; i+1 < len(fs); i++ {
		if strings.EqualFold(strings.TrimRight(fs[i], ",:"), word) {
			if n, ok := atoiOK(fs[i+1]); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// speedTokenMbps converts a speed token to megabits per second. It recognizes
// ONLY the spellings the supported dialects actually print
// ("1000Mbps", "1000Mb/s", "10Gbps", "1 Gbps", "100000 Kbit/sec" via kbitsMbps).
// Anything else yields ok=false — an unrecognized speed is absent, not zero.
func speedTokenMbps(tok string) (int64, bool) {
	t := strings.ToLower(trim(tok))
	t = strings.TrimSuffix(t, ",")
	switch {
	case strings.HasSuffix(t, "mb/s"):
		t = strings.TrimSuffix(t, "mb/s")
	case strings.HasSuffix(t, "mbps"):
		t = strings.TrimSuffix(t, "mbps")
	case strings.HasSuffix(t, "gb/s"):
		if f, ok := atofOK(strings.TrimSuffix(t, "gb/s")); ok {
			return int64(f * 1000), true
		}
		return 0, false
	case strings.HasSuffix(t, "gbps"):
		if f, ok := atofOK(strings.TrimSuffix(t, "gbps")); ok {
			return int64(f * 1000), true
		}
		return 0, false
	default:
		return 0, false
	}
	if f, ok := atofOK(t); ok {
		return int64(f), true
	}
	return 0, false
}

// kbitsToMbps converts a Cisco "BW <n> Kbit/sec" figure to Mbps. A bandwidth
// below 1000 Kbit (sub-megabit) yields ok=false rather than rounding to 0.
func kbitsToMbps(kbit int64) (int64, bool) {
	if kbit < 1000 {
		return 0, false
	}
	return kbit / 1000, true
}
