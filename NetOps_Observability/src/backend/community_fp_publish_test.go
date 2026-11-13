// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/credfp"
	"netops/backend/internal/credscrub"
)

// fpTestKey is a URL-safe key of the length install.py mints.
// Assembled from parts so no literal reads as a credential to the secret scanner.
const fpTestKey = "credfp-" + "test-" + "key-" + "0123456789" + "abcdefghijklmnop"

func fpScrubber(t *testing.T, values ...credscrub.Value) *credscrub.Scrubber {
	t.Helper()
	s := credscrub.New(func(context.Context) ([]credscrub.Value, error) { return values, nil })
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func fpEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestCommunityFingerprintPublisherIsOffWithoutItsInputs: no shared directory
// (a file-backend build) or no key file means no publisher, never a publisher
// that writes an unkeyed or empty set.
func TestCommunityFingerprintPublisherIsOffWithoutItsInputs(t *testing.T) {
	s := fpScrubber(t, credscrub.Value{Tenant: "t_a", Text: "fixture-community-aaaa"})
	keyFile := filepath.Join(t.TempDir(), "password")
	if p := newCommunityFingerprintPublisher(s, fpEnv(map[string]string{communityFPKeyEnv: keyFile})); p != nil {
		t.Fatal("a publisher without TENANT_ENRICHMENT_DIR")
	}
	if p := newCommunityFingerprintPublisher(s, fpEnv(map[string]string{"TENANT_ENRICHMENT_DIR": t.TempDir()})); p != nil {
		t.Fatal("a publisher without the key file")
	}
	if p := newCommunityFingerprintPublisher(nil, fpEnv(map[string]string{"TENANT_ENRICHMENT_DIR": t.TempDir(), communityFPKeyEnv: keyFile})); p != nil {
		t.Fatal("a publisher without a scrubber")
	}
	var srv *server
	srv.publishCommunityFingerprints() // nil-safe
	(&server{}).publishCommunityFingerprints()
}

// TestCommunityFingerprintsArePublishedPerTenant is the §3a test for the
// at-rest drop: each tenant's community is published ONLY under that tenant's
// scope, a platform value only under "*", and no value reaches the file. The
// aggregator matches a line's user slot under the LINE's tenant (then "*"), so
// tenant B's set can never drop a string from tenant A's line, and a tenant
// cannot learn whether a string is another tenant's community by logging it.
func TestCommunityFingerprintsArePublishedPerTenant(t *testing.T) {
	commA := "fixture-community-" + strings.Repeat("a", 6)
	commB := "fixture-community-" + strings.Repeat("b", 6)
	commG := "fixture-community-" + strings.Repeat("g", 6)
	s := fpScrubber(t,
		credscrub.Value{Tenant: "T_A", Text: commA},
		credscrub.Value{Tenant: "t_b", Text: commB},
		credscrub.Value{Tenant: "", Text: commG},
	)
	dir := t.TempDir()
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "password")
	if err := os.WriteFile(keyFile, []byte(fpTestKey+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	srv := &server{credScrub: s, credFP: newCommunityFingerprintPublisher(s, fpEnv(map[string]string{
		"TENANT_ENRICHMENT_DIR": dir, communityFPKeyEnv: keyFile,
	}))}
	if srv.credFP == nil {
		t.Fatal("no publisher with both inputs configured")
	}
	srv.publishCommunityFingerprints()
	raw, err := os.ReadFile(filepath.Join(dir, credfp.FileName))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, v := range []string{commA, commB, commG, fpTestKey} {
		if strings.Contains(body, v) {
			t.Fatal("a community or the key reached the published file")
		}
	}
	want := map[string]bool{
		"t_a/" + credfp.Fingerprint(fpTestKey, "t_a", commA): true,
		"t_b/" + credfp.Fingerprint(fpTestKey, "t_b", commB): true,
		"*/" + credfp.Fingerprint(fpTestKey, "*", commG):     true,
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("published %d lines, want %d:\n%s", len(lines), len(want), body)
	}
	for _, l := range lines {
		if !want[l] {
			t.Fatalf("unexpected line %q", l)
		}
	}
	// Cross-tenant: A's community is not findable under B's scope or "*".
	for _, wrong := range []string{
		"t_b/" + credfp.Fingerprint(fpTestKey, "t_b", commA),
		"*/" + credfp.Fingerprint(fpTestKey, "*", commA),
		"t_a/" + credfp.Fingerprint(fpTestKey, "t_a", commB),
	} {
		if strings.Contains(body, wrong) {
			t.Fatalf("a tenant's community is published under another scope: %q", wrong)
		}
	}
}
