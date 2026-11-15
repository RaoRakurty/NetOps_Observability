// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package evalconsent

import (
	"context"
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

func TestDefaultOffSetGetRevoke(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if c, err := m.Get(ctx, "acme", "carol"); err != nil || c.Consented {
		t.Fatalf("default must be off: %+v %v", c, err)
	}
	if c, err := m.Set(ctx, "acme", "carol", true, t0); err != nil || !c.Consented || !c.UpdatedAt.Equal(t0) {
		t.Fatalf("grant: %+v %v", c, err)
	}
	if got, _ := m.Consenting(ctx, "acme"); !got["carol"] || len(got) != 1 {
		t.Fatalf("consenting %v", got)
	}
	if _, err := m.Set(ctx, "acme", "carol", false, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Consenting(ctx, "acme"); len(got) != 0 {
		t.Fatalf("revoked consent still listed: %v", got)
	}
}

func TestConsentNeverCrossesTenants(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if _, err := m.Set(ctx, "acme", "carol", true, t0); err != nil {
		t.Fatal(err)
	}
	if c, _ := m.Get(ctx, "globex", "carol"); c.Consented {
		t.Fatal("consent leaked into another tenant under the same principal name")
	}
	if got, _ := m.Consenting(ctx, "globex"); len(got) != 0 {
		t.Fatalf("globex sees acme's consent: %v", got)
	}
}

func TestInvalidInputsAreRefused(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	for _, c := range []struct{ tenant, principal string }{{"", "carol"}, {"acme", ""}, {"  ", "carol"}} {
		if _, err := m.Set(ctx, c.tenant, c.principal, true, t0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Set(%q,%q): %v", c.tenant, c.principal, err)
		}
		if _, err := m.Get(ctx, c.tenant, c.principal); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Get(%q,%q): %v", c.tenant, c.principal, err)
		}
	}
	if _, err := m.Consenting(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Consenting(\"\"): %v", err)
	}
}
