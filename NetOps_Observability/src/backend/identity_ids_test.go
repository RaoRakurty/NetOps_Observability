package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the opaque-identity foundation (identity_ids.go + orgs/tenants):
// opaque immutable ids, validated/unique/immutable slugs, and slug→id resolution.

func TestOpaqueIDGenerator(t *testing.T) {
	// Prefixed, opaque, and unique across many mints.
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		o, tn := mintOrgID(), mintTenantID()
		if !strings.HasPrefix(o, "org_") || !isOrgID(o) {
			t.Fatalf("org id %q missing org_ prefix", o)
		}
		if !strings.HasPrefix(tn, "t_") || !isTenantID(tn) {
			t.Fatalf("tenant id %q missing t_ prefix", tn)
		}
		// 16 random bytes → 32 hex chars after the prefix.
		if len(strings.TrimPrefix(o, "org_")) != 32 || len(strings.TrimPrefix(tn, "t_")) != 32 {
			t.Fatalf("unexpected id length: org=%q tenant=%q", o, tn)
		}
		for _, id := range []string{o, tn} {
			if seen[id] {
				t.Fatalf("duplicate opaque id minted: %q", id)
			}
			seen[id] = true
		}
	}
}

func TestValidateSlug(t *testing.T) {
	good := []string{"acme", "acme-prod", "a1", "team-42-west"}
	for _, s := range good {
		if got, err := validateSlug(s); err != nil || got != s {
			t.Errorf("validateSlug(%q) = (%q,%v), want (%q,nil)", s, got, err, s)
		}
	}
	bad := map[string]string{
		"":                      "empty",
		"a":                     "too short",
		"Acme":                  "uppercase",
		"acme_prod":             "underscore",
		"acme prod":             "space",
		"-acme":                 "leading hyphen",
		"acme-":                 "trailing hyphen",
		"acme--prod":            "consecutive hyphens",
		"acme.prod":             "dot",
		"admin":                 "reserved",
		"api":                   "reserved",
		"login":                 "reserved",
		"system":                "reserved",
		"global":                "reserved sentinel",
		"platform":              "reserved sentinel",
		strings.Repeat("a", 41): "too long",
	}
	for s, why := range bad {
		if _, err := validateSlug(s); err == nil {
			t.Errorf("validateSlug(%q) should be rejected (%s)", s, why)
		}
	}
}

// TestTenantOpaqueIdentity: id is opaque (not the slugified name), slug is the
// human handle, and they are different. Plus reserved/duplicate/malformed slugs.
func TestTenantOpaqueIdentity(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := ts.Create("Acme Corporation", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !isTenantID(tn.ID) {
		t.Errorf("tenant id %q is not an opaque t_ id", tn.ID)
	}
	if tn.ID == tn.Slug || tn.ID == slugify(tn.Name) {
		t.Errorf("tenant id must differ from slug/slugified-name: id=%q slug=%q", tn.ID, tn.Slug)
	}
	if tn.Slug != "acme-corporation" {
		t.Errorf("slug = %q, want acme-corporation (derived from name)", tn.Slug)
	}
	// duplicate slug rejected (globally unique)
	if _, err := ts.Create("Acme Corporation", "", "", "", ""); err == nil {
		t.Error("duplicate slug should be rejected")
	}
	if _, err := ts.Create("Other", "acme-corporation", "", "", ""); err == nil {
		t.Error("explicit duplicate slug should be rejected")
	}
	// malformed + reserved slugs rejected
	if _, err := ts.Create("Bad", "Bad_Slug", "", "", ""); err == nil {
		t.Error("malformed slug should be rejected")
	}
	if _, err := ts.Create("Admin", "admin", "", "", ""); err == nil {
		t.Error("reserved slug should be rejected")
	}
}

// TestSlugResolvesToOpaqueID: a slug reference resolves to the opaque id (the
// compatibility resolver), and an opaque id resolves to itself.
func TestSlugResolvesToOpaqueID(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, _ := ts.Create("Acme", "acme", "", "", "")
	if got, ok := ts.Resolve("acme"); !ok || got.ID != tn.ID {
		t.Errorf("Resolve(slug) = (%q,%v), want (%s,true)", got.ID, ok, tn.ID)
	}
	if got, ok := ts.Resolve(tn.ID); !ok || got.ID != tn.ID {
		t.Errorf("Resolve(id) = (%q,%v), want self", got.ID, ok)
	}
	if _, ok := ts.Resolve("nope"); ok {
		t.Error("Resolve of an unknown ref must fail closed")
	}
	// Get is the slug-aware compat alias of Resolve.
	if got, ok := ts.Get("acme"); !ok || got.ID != tn.ID {
		t.Errorf("Get(slug) should resolve to the opaque id, got (%q,%v)", got.ID, ok)
	}
}

// TestRenameKeepsIdentity: an org/tenant display-name change (here via the org
// Update path) never changes the immutable id or slug.
func TestRenameKeepsIdentity(t *testing.T) {
	os, err := newOrgStore(filepath.Join(t.TempDir(), "orgs.json"))
	if err != nil {
		t.Fatal(err)
	}
	o, _ := os.Create("Acme Corp", "", "a note", "", "")
	note := "renamed context"
	got, err := os.Update(o.ID, orgUpdate{Note: &note})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != o.ID || got.Slug != o.Slug {
		t.Errorf("update changed identity: id %q→%q slug %q→%q", o.ID, got.ID, o.Slug, got.Slug)
	}
	// The org is still addressable by its original slug and opaque id.
	if _, ok := os.Resolve(o.Slug); !ok {
		t.Error("org no longer resolvable by slug after update")
	}
}
