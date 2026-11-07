// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logredact

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type corpus struct {
	Secrets   []string                   `json:"secrets"`
	Cases     []struct{ In, Out string } `json:"cases"`
	Negatives []string                   `json:"negatives"`
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "log_redaction_corpus.json"))
	if err != nil {
		t.Fatalf("read shared corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse shared corpus: %v", err)
	}
	if len(c.Cases) == 0 || len(c.Secrets) == 0 || len(c.Negatives) == 0 {
		t.Fatal("shared corpus is empty — the test would prove nothing")
	}
	return c
}

func TestStringMatchesTheSharedCorpus(t *testing.T) {
	c := loadCorpus(t)
	for _, tc := range c.Cases {
		if got := String(tc.In); got != tc.Out {
			t.Errorf("String(%q)\n got %q\nwant %q", tc.In, got, tc.Out)
		}
	}
}

func TestNegativesPassThroughUnchanged(t *testing.T) {
	for _, s := range loadCorpus(t).Negatives {
		if got := String(s); got != s {
			t.Errorf("over-redacted %q → %q", s, got)
		}
	}
}

func TestNoSeededSecretSurvives(t *testing.T) {
	c := loadCorpus(t)
	for _, tc := range c.Cases {
		out := String(tc.In)
		for _, sec := range c.Secrets {
			if strings.Contains(out, sec) {
				t.Errorf("secret %q survived in %q", sec, out)
			}
		}
	}
}

func TestStringIsIdempotent(t *testing.T) {
	for _, tc := range loadCorpus(t).Cases {
		once := String(tc.In)
		if twice := String(once); twice != once {
			t.Errorf("not idempotent: %q → %q", once, twice)
		}
	}
}

func TestURLStripsUserinfoForDisplay(t *testing.T) {
	cases := map[string]string{
		"https://svc-api:pw@vmauth:8427": "https://vmauth:8427",
		"http://victoria:8428":           "http://victoria:8428",
		"https://tok@host/p?q=1":         "https://host/p?q=1",
		"kafka:9092":                     "kafka:9092", // no scheme: unchanged
		"http://u:p@[::1]:9200/x":        "http://[::1]:9200/x",
	}
	for in, want := range cases {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
	// Unparseable input must still not echo a credential.
	if got := URL("http://u:pw@ho st/%zz"); strings.Contains(got, "pw@") {
		t.Errorf("unparseable URL leaked: %q", got)
	}
}

func TestFieldsMasksSensitiveKeysAndValues(t *testing.T) {
	now := time.Now()
	in := map[string]any{
		"password":     "Sup3rS3cretPw",
		"db_token":     "tok-77QQ88zz",
		"max_tokens":   4096,
		"tokens":       "812",
		"url":          "https://svc:Sup3rS3cretPw@vmauth:8427",
		"err":          errors.New("dial https://svc:Sup3rS3cretPw@vmauth:8427: refused"),
		"nested":       map[string]any{"secret": "s3cr3tvalue", "ok": "fine"},
		"list":         []any{"x", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig123"},
		"strs":         []string{"a", "password=s3cr3tvalue"},
		"at":           now,
		"count":        3,
		"empty_secret": nil,
	}
	out := Fields(in)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range []string{"Sup3rS3cretPw", "tok-77QQ88zz", "s3cr3tvalue", "sig123"} {
		if bytes.Contains(b, []byte(sec)) {
			t.Errorf("secret %q survived: %s", sec, b)
		}
	}
	if out["max_tokens"] != 4096 || out["tokens"] != "812" || out["count"] != 3 || out["at"] != now {
		t.Errorf("non-secret fields changed: %v", out)
	}
	if out["nested"].(map[string]any)["ok"] != "fine" {
		t.Error("nested non-secret changed")
	}
	// The caller's map is never mutated.
	if in["password"] != "Sup3rS3cretPw" || in["nested"].(map[string]any)["secret"] != "s3cr3tvalue" {
		t.Error("Fields mutated its input")
	}
}

func TestFieldsReturnsTheSameMapWhenNothingIsSecret(t *testing.T) {
	in := map[string]any{"device": "leaf1", "count": 2}
	out := Fields(in)
	out["probe"] = true // same map object → visible through in
	if _, ok := in["probe"]; !ok {
		t.Error("Fields allocated a copy for clean input (hot-path cost)")
	}
}

func TestWriterRedactsAndReportsTheFullLength(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	line := []byte("push failed: https://svc:Sup3rS3cretPw@vmauth:8427\n")
	n, err := w.Write(line)
	if err != nil || n != len(line) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(line))
	}
	if strings.Contains(buf.String(), "Sup3rS3cretPw") {
		t.Errorf("writer leaked: %q", buf.String())
	}
	buf.Reset()
	clean := []byte("ordinary line\n")
	if n, _ := w.Write(clean); n != len(clean) || buf.String() != string(clean) {
		t.Errorf("clean line altered: %q", buf.String())
	}
}

func FuzzStringNeverLeaksAPassword(f *testing.F) {
	f.Add("https://u:p@h", "Sup3rS3cretPw")
	f.Add("password=", "abc123XYZ")
	f.Fuzz(func(t *testing.T, prefix, secret string) {
		if len(secret) < 6 || strings.ContainsAny(secret, " \t\r\n\"'&,;}/@:<>=\\") || secret == Mask {
			return
		}
		for _, in := range []string{
			"https://user:" + secret + "@host:1/p",
			prefix + " password=" + secret + " end",
			`{"token":"` + secret + `"}`,
		} {
			if out := String(in); strings.Contains(out, secret) {
				t.Fatalf("secret survived: in=%q out=%q", in, out)
			}
		}
	})
}

func BenchmarkStringCleanLine(b *testing.B) {
	s := "collectors: polled 42 interfaces on leaf1 in 120ms"
	for i := 0; i < b.N; i++ {
		_ = String(s)
	}
}
