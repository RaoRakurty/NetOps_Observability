package main

import (
	"testing"
)

// isUUIDToken gates every value interpolated into correlations SQL / proxied
// replay URLs — shape validation, never quote-escaping (SR-011 discipline).
func TestIsUUIDToken(t *testing.T) {
	valid := []string{
		"9f0537bd-0787-547e-a6fc-6692acaec13c",
		"B8C6C907-D0FD-570C-BE97-D18E257FC61F",
	}
	for _, v := range valid {
		if !isUUIDToken(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	invalid := []string{
		"",
		"9f0537bd",
		"9f0537bd-0787-547e-a6fc-6692acaec13cX", // too long
		"9f0537bd-0787-547e-a6fc-6692acaec13'",  // quote
		"9f0537bd_0787_547e_a6fc_6692acaec13c",  // wrong separators
		"zf0537bd-0787-547e-a6fc-6692acaec13c",  // non-hex
		"9f0537bd-0787-547e-a6fc-6692acaec13c; DROP ALL", // injection shape
	}
	for _, v := range invalid {
		if isUUIDToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// isDatetimeToken gates the object-window bounds before they are interpolated
// into the timeline ts filter (same SR-011 shape-validation discipline).
func TestIsDatetimeToken(t *testing.T) {
	valid := []string{
		"2026-06-14 05:11:39.836", "2026-06-14 05:11:39", "2026-01-01 00:00:00.000",
		"2026-06-14T05:11:39Z", "2026-06-14T05:11:39.836Z", // RFC 3339 wire form (chISO, S3)
	}
	for _, v := range valid {
		if !isDatetimeToken(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	invalid := []string{
		"",
		"short",                      // < 10 chars
		"2026-06-14 05:11:39'; DROP", // quote + injection
		"now() - INTERVAL 1 DAY",     // function call (parens/letters)
		"2026-06-14 05:11:39.836xxxxxxxxxxxxxxxxxxxxxxxx", // too long (> 32)
	}
	for _, v := range invalid {
		if isDatetimeToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}
