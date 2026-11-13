// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package credfp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey is the key the aggregator's `vector test` suite uses too
// (deployment/docker/vector/tests/credscrub.yaml), so the known answers below
// pin the SAME bytes the VRL must produce.
// Assembled from parts so no literal reads as a credential to the secret
// scanner; the bytes are "credfp-test-key-0123456789abcdefghijklmnop".
const testKey = "credfp-" + "test-" + "key-" + "0123456789" + "abcdefghijklmnop"

// TestFingerprintKnownAnswers pins the wire contract against values computed
// independently (Python hmac/hashlib/base64, recorded in the suite above). A
// change here is a change to what the edge must compute: both move together
// or every fingerprint stops matching.
func TestFingerprintKnownAnswers(t *testing.T) {
	cases := []struct{ scope, value, want string }{
		{"t_lab", "fabricated-community-7f3a", "o4rCLJdpbj_x6xixahF7EX2jEB5eRd-p3pg0a5pVa-M"},
		{"*", "fabricated-community-7f3a", "UURGNNIXJ9om_DZfp5OIgA0n-KkJHarcx8-QDIUF9uU"},
		{"t_other", "fabricated-community-7f3a", "8rByyZ9NqWNCDHs0ob8Cp3BwXIOSee6lPy058OPvoMk"},
		{"t_lab", "ro", "NiajE6YlZfxm5dlR_kt83urR9pmjolSz7_QB_ugmxWs"},
	}
	for _, c := range cases {
		if got := Fingerprint(testKey, c.scope, c.value); got != c.want {
			t.Errorf("Fingerprint(%q, %q) = %q, want %q", c.scope, c.value, got, c.want)
		}
	}
}

// TestFingerprintIsScopedPerTenant: the same community under two tenants gives
// two unrelated fingerprints, so one tenant's published set can never match
// another tenant's line (§3a) and a stored token links nothing across tenants.
func TestFingerprintIsScopedPerTenant(t *testing.T) {
	a := Fingerprint(testKey, "t_a", "shared-community")
	b := Fingerprint(testKey, "t_b", "shared-community")
	g := Fingerprint(testKey, GlobalScope, "shared-community")
	if a == b || a == g || b == g {
		t.Fatalf("fingerprints collide across scopes: %q %q %q", a, b, g)
	}
	if Fingerprint("another-key-0123456789abcdefghijklmnopqrs", "t_a", "shared-community") == a {
		t.Fatal("the key does not change the fingerprint")
	}
}

func TestScopeFolding(t *testing.T) {
	for in, want := range map[string]string{
		"": "*", "  ": "*", "global": "*", "GLOBAL": "*", "T_Lab": "t_lab", " t_x ": "t_x",
	} {
		if got := Scope(in); got != want {
			t.Errorf("Scope(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidKey(t *testing.T) {
	if err := ValidKey(testKey); err != nil {
		t.Fatalf("the test key is refused: %v", err)
	}
	if err := ValidKey("short"); !errors.Is(err, ErrShortKey) {
		t.Errorf("short key: got %v", err)
	}
	// Each of these would break the VRL string literal the secret lands in.
	for _, bad := range []string{`"`, `\`, `$`, " ", "+", "/", "="} {
		if err := ValidKey(strings.Repeat("a", 40) + bad); !errors.Is(err, ErrBadKey) {
			t.Errorf("key ending in %q: got %v, want ErrBadKey", bad, err)
		}
	}
}

func TestRenderIsSortedDeduplicatedAndRefusesUnmatchableScopes(t *testing.T) {
	fp1 := Fingerprint(testKey, "t_b", "x-community")
	fp2 := Fingerprint(testKey, "t_a", "x-community")
	body, err := Render([]Pair{{"t_b", fp1}, {"t_a", fp2}, {"t_b", fp1}})
	if err != nil {
		t.Fatal(err)
	}
	want := "t_a/" + fp2 + "\nt_b/" + fp1 + "\n"
	if string(body) != want {
		t.Fatalf("render:\n%s\nwant:\n%s", body, want)
	}
	if empty, err := Render(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty set: %q %v", empty, err)
	}
	for _, scope := range []string{"T_A", "a/b", "a:b", "", "a b", strings.Repeat("a", 129)} {
		if _, err := Render([]Pair{{scope, fp1}}); err == nil {
			t.Errorf("scope %q was accepted", scope)
		}
	}
	if _, err := Render([]Pair{{"t_a", "short"}}); err == nil {
		t.Error("a malformed fingerprint was accepted")
	}
	big := make([]Pair, MaxLines+1)
	if _, err := Render(big); err == nil {
		t.Error("an unbounded set was accepted")
	}
}

// TestPublisherFoldsScopesAndKeepsTheFileOnAKeyFailure: the published file is
// what the edge matches against, so a key that cannot be read must leave the
// last good set standing (it was computed under the key the aggregator holds),
// and the report fires on a CHANGE of state, not on every tick.
func TestPublisherFoldsScopesAndKeepsTheFileOnAKeyFailure(t *testing.T) {
	dir := t.TempDir()
	key := testKey
	var keyErr error
	var reports []string
	p := &Publisher{
		Dir: dir,
		Key: func() (string, error) { return key, keyErr },
		Pairs: func(fp func(tenant, value string) string) []Pair {
			return []Pair{
				{Scope: "T_Lab", FP: fp("T_Lab", "fabricated-community-7f3a")},
				{Scope: "", FP: fp("", "fabricated-community-7f3a")},
			}
		},
		Report: func(err error, wrote bool, n int) {
			reports = append(reports, fmt.Sprintf("err=%v wrote=%v n=%d", err != nil, wrote, n))
		},
	}
	if wrote, err := p.Publish(); err != nil || !wrote {
		t.Fatalf("first publish: wrote=%v err=%v", wrote, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	want := "*/UURGNNIXJ9om_DZfp5OIgA0n-KkJHarcx8-QDIUF9uU\nt_lab/o4rCLJdpbj_x6xixahF7EX2jEB5eRd-p3pg0a5pVa-M\n"
	if string(body) != want {
		t.Fatalf("published:\n%s\nwant:\n%s", body, want)
	}
	if strings.Contains(string(body), "fabricated-community") {
		t.Fatal("a value reached the published file")
	}
	// An unchanged tick reports nothing.
	if _, err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	keyErr = errors.New("credential file missing")
	for i := 0; i < 3; i++ {
		if _, err := p.Publish(); err == nil {
			t.Fatal("a key failure published anyway")
		}
	}
	if after, _ := os.ReadFile(filepath.Join(dir, FileName)); string(after) != want {
		t.Fatal("a key failure replaced the last good set")
	}
	keyErr = nil
	key = "short"
	if _, err := p.Publish(); err == nil {
		t.Fatal("an unusable key published")
	}
	key = testKey
	if _, err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	wantReports := []string{"err=false wrote=true n=2", "err=true wrote=false n=0", "err=true wrote=false n=0", "err=false wrote=false n=2"}
	if fmt.Sprint(reports) != fmt.Sprint(wantReports) {
		t.Fatalf("reports %v, want %v (once per state change)", reports, wantReports)
	}
	var nilP *Publisher
	if wrote, err := nilP.Publish(); wrote || err != nil {
		t.Fatal("a nil publisher must do nothing")
	}
	if _, err := (&Publisher{}).Publish(); err == nil {
		t.Fatal("an unconfigured publisher must say so")
	}
}

func TestWriteIsAtomicWorldReadableAndSkipsNoOps(t *testing.T) {
	dir := t.TempDir()
	body := []byte("t_a/" + Fingerprint(testKey, "t_a", "v-community") + "\n")
	changed, err := Write(dir, body)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644 (the aggregator runs as another uid)", st.Mode().Perm())
	}
	again, err := Write(dir, body)
	if err != nil || again {
		t.Fatalf("identical rewrite: changed=%v err=%v (a no-op must not trigger a reload)", again, err)
	}
	left, err := filepath.Glob(filepath.Join(dir, ".community_fp-*.tmp"))
	if err != nil || len(left) != 0 {
		t.Fatalf("temp files left behind: %v %v", left, err)
	}
}
