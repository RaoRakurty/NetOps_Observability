package main

import "testing"

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
		"9f0537bd-0787-547e-a6fc-6692acaec13cX",          // too long
		"9f0537bd-0787-547e-a6fc-6692acaec13'",           // quote
		"9f0537bd_0787_547e_a6fc_6692acaec13c",           // wrong separators
		"zf0537bd-0787-547e-a6fc-6692acaec13c",           // non-hex
		"9f0537bd-0787-547e-a6fc-6692acaec13c; DROP ALL", // injection shape
	}
	for _, v := range invalid {
		if isUUIDToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}
