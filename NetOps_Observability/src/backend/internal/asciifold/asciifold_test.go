// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package asciifold

import (
	"strings"
	"testing"
)

// The three inputs that make strings.ToLower grow. Each one is what turned the
// idiom this package replaces into a panic in showparse and a leaked credential
// in pipedebug.
var growers = []struct {
	name string
	pad  string
}{
	{"U+023A", "Ⱥ"},               // Ⱥ: 2 bytes, lowers to 3
	{"U+023E", "Ⱦ"},               // Ⱦ: 2 bytes, lowers to 3
	{"invalid UTF-8", "\xff\xfe"}, // each byte becomes a 3-byte U+FFFD
}

func TestIndexReturnsAnOffsetValidForTheORIGINALString(t *testing.T) {
	const marker = "MARKER"
	const tail = "the-part-after"
	for _, g := range growers {
		t.Run(g.name, func(t *testing.T) {
			// Enough padding that a ToLower-measured offset would be far off.
			s := strings.Repeat(g.pad, 12) + " " + marker + tail
			i := Index(s, "marker")
			if i < 0 {
				t.Fatalf("marker not found in %q", s)
			}
			if i+len(marker) > len(s) {
				t.Fatalf("offset %d runs past the %d-byte string", i, len(s))
			}
			if got := s[i : i+len(marker)]; got != marker {
				t.Fatalf("offset %d addresses %q, not the marker", i, got)
			}
			if got := s[i+len(marker):]; got != tail {
				t.Fatalf("the text after the marker is %q, want %q", got, tail)
			}
			// The defect, stated as an assertion: the folded copy disagrees.
			if bad := strings.Index(strings.ToLower(s), "marker"); bad == i {
				t.Fatalf("this input does not exercise the growth case (both offsets are %d)", i)
			}
		})
	}
}

func TestLastIndexReturnsAnOffsetValidForTheORIGINALString(t *testing.T) {
	const marker = "NEEDS "
	for _, g := range growers {
		t.Run(g.name, func(t *testing.T) {
			s := strings.Repeat(g.pad, 12) + " first NEEDS a " + marker + "key_name"
			i := LastIndex(s, "needs ")
			if i < 0 {
				t.Fatalf("marker not found in %q", s)
			}
			if got := s[i+len(marker):]; got != "key_name" {
				t.Fatalf("the text after the last marker is %q, want %q", got, "key_name")
			}
			if bad := strings.LastIndex(strings.ToLower(s), "needs "); bad == i {
				t.Fatalf("this input does not exercise the growth case (both offsets are %d)", i)
			}
		})
	}
}

// On ASCII input the answer must be identical to the standard library's, so a
// call site can be swapped over without changing behaviour.
func TestMatchesTheStandardLibraryOnASCII(t *testing.T) {
	haystacks := []string{"", "a", "Authorization: Bearer x", "aaa", "no marker here",
		"BEARER bearer Bearer", "trailing bearer "}
	markers := []string{"", "a", "bearer ", "BEARER ", "zzz", "authorization: bearer "}
	for _, h := range haystacks {
		for _, m := range markers {
			wantFirst := strings.Index(strings.ToLower(h), strings.ToLower(m))
			if got := Index(h, m); got != wantFirst {
				t.Errorf("Index(%q, %q) = %d, want %d", h, m, got, wantFirst)
			}
			wantLast := strings.LastIndex(strings.ToLower(h), strings.ToLower(m))
			if got := LastIndex(h, m); got != wantLast {
				t.Errorf("LastIndex(%q, %q) = %d, want %d", h, m, got, wantLast)
			}
			if got, want := Contains(h, m), strings.Contains(strings.ToLower(h), strings.ToLower(m)); got != want {
				t.Errorf("Contains(%q, %q) = %v, want %v", h, m, got, want)
			}
		}
	}
}

// A non-ASCII byte must never be folded into a match: that would let hostile
// input impersonate a marker it does not contain.
func TestNonASCIIBytesAreNeverFolded(t *testing.T) {
	if i := Index("Ⱥbearer x", "Ⱥbearer "); i != 0 {
		t.Fatalf("an exact non-ASCII marker did not match at 0: %d", i)
	}
	if i := Index("ⱥbearer x", "Ⱥbearer "); i >= 0 {
		t.Fatalf("a lower-cased non-ASCII rune was folded into a match at %d", i)
	}
}

func TestOffsetIsAlwaysInRange(t *testing.T) {
	cases := []struct{ s, marker string }{
		{"", ""}, {"", "x"}, {"x", ""}, {"short", "much longer marker"},
		{"\xff", "\xff"}, {"Ⱦ", "Ⱦ"},
	}
	for _, c := range cases {
		for _, got := range []int{Index(c.s, c.marker), LastIndex(c.s, c.marker)} {
			if got > len(c.s) {
				t.Errorf("Index/LastIndex(%q, %q) = %d, past the %d-byte string", c.s, c.marker, got, len(c.s))
			}
			if got >= 0 {
				_ = c.s[got:] // must not panic
			}
		}
	}
}
