package main

import "testing"

func TestValidateServiceInput(t *testing.T) {
	if err := validateServiceInput("Teams", "critical"); err != nil {
		t.Errorf("valid input rejected: %v", err)
	}
	if err := validateServiceInput("SAP", ""); err != nil {
		t.Errorf("empty criticality should default-ok: %v", err)
	}
	if err := validateServiceInput("  ", "normal"); err == nil {
		t.Error("blank name should be rejected")
	}
	if err := validateServiceInput("x", "bogus"); err == nil {
		t.Error("invalid criticality should be rejected")
	}
	long := make([]byte, 121)
	for i := range long {
		long[i] = 'a'
	}
	if err := validateServiceInput(string(long), "low"); err == nil {
		t.Error("over-long name should be rejected")
	}
}

func TestNewUUIDv4(t *testing.T) {
	a, err := newUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	if !isUUIDToken(a) {
		t.Errorf("generated UUID %q fails isUUIDToken", a)
	}
	b, _ := newUUIDv4()
	if a == b {
		t.Error("two UUIDs collided")
	}
	// version 4 / variant nibble checks
	if a[14] != '4' {
		t.Errorf("expected version 4 nibble, got %c in %s", a[14], a)
	}
	switch a[19] {
	case '8', '9', 'a', 'b':
	default:
		t.Errorf("expected RFC-4122 variant nibble (8/9/a/b), got %c in %s", a[19], a)
	}
}

func TestBindingKindAllowlist(t *testing.T) {
	for _, k := range []string{"probe", "path", "seam"} {
		if !validBindingKind[k] {
			t.Errorf("%q should be a valid binding kind", k)
		}
	}
	for _, k := range []string{"", "device", "service", "url"} {
		if validBindingKind[k] {
			t.Errorf("%q should NOT be a valid binding kind", k)
		}
	}
}
