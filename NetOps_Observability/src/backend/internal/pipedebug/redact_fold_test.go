// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// redact_fold_test.go — the credential stripper must measure its offsets on the
// line it is going to slice.
//
// The defect this guards (3.9-04): stripBearer found its prefix in a
// strings.ToLower COPY and sliced the ORIGINAL. strings.ToLower is not length
// preserving, so a single U+023A, U+023E or invalid UTF-8 byte anywhere before
// the credential moved every later offset, and the token was written out
// unredacted. It lands in the session directory, and the support bundle
// deliberately does not redact again — so the token leaves the host.
//
// Every token below is fabricated. Nothing here is a real credential.

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// foldGrowers are the three inputs that make strings.ToLower produce a LONGER
// string than it was given.
var foldGrowers = []struct {
	name string
	pad  string // one unit of padding; each unit grows on lower-casing
}{
	{"U+023A", "Ⱥ"},           // two bytes in, three bytes out
	{"U+023E", "Ⱦ"},           // two bytes in, three bytes out
	{"invalid UTF-8", "\xff"}, // one byte in, three bytes out (U+FFFD)
}

// fabricated credentials — obviously fake, never a real secret.
const (
	fakeBearer = "FAKE-BEARER-0123456789"
	fakeAPIKey = "FAKE-APIKEY-abcdefghij"
	fakeAccess = "FAKE-ACCESSTOKEN-98765"
)

func TestBearerStrippingSurvivesLowercaseGrowthBeforeTheCredential(t *testing.T) {
	cases := []struct{ name, prefix, secret, tail string }{
		{"authorization bearer", "Authorization: Bearer ", fakeBearer, " upstream=api"},
		{"bare bearer", "bearer ", fakeBearer, " upstream=api"},
		{"x-api-key", "X-Api-Key: ", fakeAPIKey, " upstream=api"},
		{"access_token query", "GET /v1/x?access_token=", fakeAccess, "&y=1"},
	}
	for _, c := range cases {
		for _, g := range foldGrowers {
			t.Run(c.name+"/"+g.name, func(t *testing.T) {
				// Enough padding that the offset measured on a lower-cased copy
				// lands past the END of the credential rather than one byte in:
				// the whole token survives, which is what makes the leak plain.
				line := strings.Repeat(g.pad, 30) + " " + c.prefix + c.secret + c.tail
				got := RedactString(line)
				if strings.Contains(got, c.secret) {
					t.Fatalf("the credential reached the output\n  in : %q\n  out: %q", line, got)
				}
				if !strings.Contains(got, mark) {
					t.Fatalf("nothing was marked as redacted, so a reader is not told a credential was present\n  out: %q", got)
				}
			})
		}
	}
}

// The growth can also sit BETWEEN two credentials on one line: the first
// replacement must not shift the search for the second.
func TestEveryCredentialOnALineIsStrippedWhateverSitsBetweenThem(t *testing.T) {
	for _, g := range foldGrowers {
		t.Run(g.name, func(t *testing.T) {
			line := "Authorization: Bearer " + fakeBearer + " " +
				strings.Repeat(g.pad, 30) + " x-api-key: " + fakeAPIKey
			got := RedactString(line)
			for _, secret := range []string{fakeBearer, fakeAPIKey} {
				if strings.Contains(got, secret) {
					t.Fatalf("credential %q reached the output: %q", secret, got)
				}
			}
		})
	}
}

// stripBearer slices caller-supplied bytes. An offset from a lower-cased copy
// can also run PAST the end of the original, which panics instead of leaking.
func TestStripBearerNeverPanicsOnAdversarialBytes(t *testing.T) {
	for _, g := range foldGrowers {
		for n := 1; n <= 40; n++ {
			for _, tail := range []string{"", " ", "x", `"`} {
				line := strings.Repeat(g.pad, n) + "authorization: bearer " + fakeBearer + tail
				_ = stripBearer(line) // must not panic
				_ = RedactString(line)
			}
		}
	}
}

// THE PATH THAT MATTERS: a session line is redacted on the way to disk, and the
// bundle writer deliberately does not redact again. So a token that survives
// stripBearer leaves the host inside a support bundle.
func TestAGrownLineDoesNotCarryACredentialIntoTheSupportBundle(t *testing.T) {
	for _, g := range foldGrowers {
		t.Run(g.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "data", "debug")
			sess, err := NewSession(root, "trace", "", time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC), Manifest{Actor: "unit"})
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			msg := strings.Repeat(g.pad, 30) + " authorization: bearer " + fakeBearer + " done"
			if err := sess.Line(StageAPI, "info", msg, map[string]any{
				"header": strings.Repeat(g.pad, 30) + " X-Api-Key: " + fakeAPIKey,
				"tenant": "t_keepme",
			}); err != nil {
				t.Fatalf("Line: %v", err)
			}
			if err := sess.Close(time.Now()); err != nil {
				t.Fatalf("Close: %v", err)
			}

			onDisk, err := os.ReadFile(filepath.Join(sess.Dir(), "api.log")) // #nosec G304 -- test temp dir
			if err != nil {
				t.Fatalf("read session file: %v", err)
			}
			for _, secret := range []string{fakeBearer, fakeAPIKey} {
				if bytes.Contains(onDisk, []byte(secret)) {
					t.Errorf("credential %q reached the session file on disk", secret)
				}
			}

			var buf bytes.Buffer
			if _, err := WriteBundleTar(&buf, []string{sess.Dir()}, MaxBundleBytes); err != nil {
				t.Fatalf("WriteBundleTar: %v", err)
			}
			flat := tarFlatten(t, buf.Bytes())
			for _, secret := range []string{fakeBearer, fakeAPIKey} {
				if strings.Contains(flat, secret) {
					t.Errorf("credential %q reached the support bundle", secret)
				}
			}
			if !strings.Contains(flat, "t_keepme") {
				t.Error("the tenant id was redacted; design §5 keeps tenant ids for support")
			}
		})
	}
}

// tarFlatten concatenates every member of a tar archive so an assertion can ask
// whether a string appears ANYWHERE in the bundle.
func tarFlatten(t *testing.T, archive []byte) string {
	t.Helper()
	var b strings.Builder
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b.WriteString(h.Name + "\n")
		if _, err := io.Copy(&b, tr); err != nil { // #nosec G110 -- bounded test fixture
			t.Fatalf("tar copy: %v", err)
		}
	}
	return b.String()
}
