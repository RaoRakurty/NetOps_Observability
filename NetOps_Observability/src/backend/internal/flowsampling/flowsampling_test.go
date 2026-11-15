// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowsampling

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/platformdb"
)

func TestValidate(t *testing.T) {
	for name, c := range map[string]struct {
		d  Declaration
		ok bool
	}{
		"ok":            {Declaration{Exporter: "10.0.0.1", Rate: 1000, Note: "flow sampler 1:1000"}, true},
		"ipv6 mapped":   {Declaration{Exporter: "::ffff:10.0.0.1", Rate: 2}, true},
		"rate 1":        {Declaration{Exporter: "10.0.0.1", Rate: 1}, false},
		"rate too big":  {Declaration{Exporter: "10.0.0.1", Rate: MaxRate + 1}, false},
		"not an ip":     {Declaration{Exporter: "edge-1", Rate: 10}, false},
		"zone":          {Declaration{Exporter: "fe80::1%eth0", Rate: 10}, false},
		"long note":     {Declaration{Exporter: "10.0.0.1", Rate: 10, Note: strings.Repeat("x", MaxNote+1)}, false},
		"control chars": {Declaration{Exporter: "10.0.0.1", Rate: 10, Note: "a\x07b"}, false},
		"invisible":     {Declaration{Exporter: "10.0.0.1", Rate: 10, Note: "a" + string(rune(0x200b)) + "b"}, false},
	} {
		d, err := Validate(c.d)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
		}
		if name == "ipv6 mapped" && d.Exporter != "10.0.0.1" {
			t.Errorf("mapped address not normalised: %q", d.Exporter)
		}
	}
}

// Two tenants behind one exporter address declare independently; one tenant
// never reads, replaces or deletes the other's declaration.
func TestFileStoreIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	if _, err := s.Put(ctx, "acme", Declaration{Exporter: "10.0.0.1", Rate: 100, UpdatedBy: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "globex", Declaration{Exporter: "10.0.0.1", Rate: 7, UpdatedBy: "g"}); err != nil {
		t.Fatal(err)
	}
	a, _ := s.List(ctx, "acme", false)
	if len(a) != 1 || a[0].Rate != 100 || a[0].TenantID != "acme" {
		t.Fatalf("acme's list = %+v", a)
	}
	if err := s.Delete(ctx, "acme", "10.0.0.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of an absent declaration = %v", err)
	}
	if err := s.Delete(ctx, "acme", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	g, _ := s.List(ctx, "globex", false)
	if len(g) != 1 || g[0].Rate != 7 {
		t.Fatalf("acme's delete touched globex: %+v", g)
	}
	if all, _ := s.List(ctx, "", true); len(all) != 1 {
		t.Fatalf("cross list = %+v", all)
	}
}

func TestFileStorePersistsAndBounds(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "decl.json")
	t.Cleanup(platformdb.SwapBackendForTest(platformdb.FileKV{}))
	s := NewFileStore(path)
	if _, err := s.Put(ctx, "acme", Declaration{Exporter: "10.0.0.1", Rate: 50}); err != nil {
		t.Fatal(err)
	}
	if got, _ := NewFileStore(path).List(ctx, "acme", false); len(got) != 1 || got[0].Rate != 50 {
		t.Fatalf("not persisted: %+v", got)
	}
	m := NewFileStore("")
	for i := 0; i < MaxPerTenant; i++ {
		if _, err := m.Put(ctx, "acme", Declaration{Exporter: "10.1." + itoa(i/250) + "." + itoa(i%250), Rate: 2}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if _, err := m.Put(ctx, "acme", Declaration{Exporter: "10.9.9.9", Rate: 2}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("over the cap = %v", err)
	}
	if _, err := m.Put(ctx, "acme", Declaration{Exporter: "10.1.0.0", Rate: 3}); err != nil {
		t.Fatalf("replacing an existing one at the cap must work: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
