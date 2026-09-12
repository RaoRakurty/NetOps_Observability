// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// env_docs_guard_test.go — the CLASS guard behind INVARIANTS standing gap #6.
//
// The gap: "documented env switches are unverified as a class — one was found
// lying (BUS_BRIDGE_URL, fixed 2026-07-22); nothing checks the rest." A
// documented switch nothing consumes is a lie told to whoever sets it: an
// operator flips it, the docs say it works, and nothing anywhere reads it.
//
// This guard closes the mechanically-checkable half of that class: every
// env-var-shaped token the OPERATOR DOCS present (inside backticks) must be
// consumed somewhere real — a Go read in the backend, or a reference in the
// stack's deployment configs / scripts / installer / sibling services. What it
// deliberately does NOT prove is per-switch BEHAVIOUR (that "off" really turns
// the feature off) — that stays with each feature's own tests, which is where
// the BUS_BRIDGE_URL class of lie is caught (bus_producer tests now pin it).
//
// Per the guard convention: a token that is documented but legitimately not
// consumed (e.g. docs describing a THIRD-party product's variable) gets an
// exemption WITH a reason. Never delete the guard.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// envDocsExempt lists documented UPPER_SNAKE tokens that are not switches this
// stack consumes, with the reason they are documented anyway.
var envDocsExempt = map[string]string{
	// Documented in TRACKER.md as MEASURED AND REJECTED: correlation's RSS
	// growth is pymalloc arena residency, not glibc arena fragmentation, so the
	// glibc knob cannot reach it (293.0 MB at default, 293.3 at 2, 293.0 at 1 —
	// 2026-08-19). It is named so nobody spends another afternoon on it, and
	// nothing consumes it ON PURPOSE. If that ever changes, wire it and delete
	// this entry.
	"MALLOC_ARENA_MAX": "documented as measured-and-rejected (tracker 156); deliberately not consumed",
	// A copy-paste PLACEHOLDER in device syslog/flow config instructions
	// ("Replace MONITOR_HOST with the host running the stack") — the operator
	// substitutes it on the device CLI; nothing in this stack reads it.
	"MONITOR_HOST": "device-config placeholder the operator substitutes, not an env switch",
	// ClickHouse's OWN exception name for error code 307 (a `max_bytes_to_read`
	// breach), quoted verbatim in tracker 207's chhttp-classification finding.
	// It is a third-party server's error identifier, not a switch anything sets;
	// the fix lands a lowercase `too_many_bytes` classification slug in
	// chhttp.go. When tracker 207 ships and its row is deleted, delete this
	// entry with it.
	"TOO_MANY_BYTES": "ClickHouse exception name (code 307) cited in tracker 207 — a third-party error identifier, not an env switch",
}

var upperSnakeRe = regexp.MustCompile(`[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+`)

// pathLikeSpan reports whether a backticked span is a file path rather than a
// switch. Evidence documents are named like TRACKER156_EVIDENCE_2026-08-19.md,
// and the UPPER_SNAKE regex happily extracts "TRACKER156_EVIDENCE_2026" out of
// one — which the guard then reports as an env switch nothing consumes. That is
// a false positive that every future dated evidence doc would reproduce, and a
// guard that cries wolf gets exempted into uselessness. A span containing a
// path separator or ending in a document/code extension is a filename.
func pathLikeSpan(span string) bool {
	inner := strings.Trim(span, "`")
	inner = strings.TrimSpace(inner)
	if strings.Contains(inner, "/") {
		return true
	}
	for _, ext := range []string{".md", ".go", ".py", ".yaml", ".yml", ".json", ".sh", ".sql"} {
		if strings.HasSuffix(inner, ext) {
			return true
		}
	}
	return false
}

// backtickSpans extracts the content of `...` spans and fenced code blocks,
// skipping spans that are file paths (see pathLikeSpan).
func backtickSpans(md string) []string {
	// fenced blocks
	fence := regexp.MustCompile("(?s)```.*?```")
	spans := fence.FindAllString(md, -1)
	md = fence.ReplaceAllString(md, "")
	inline := regexp.MustCompile("`[^`\n]+`")
	spans = append(spans, inline.FindAllString(md, -1)...)
	out := make([]string, 0, len(spans))
	for _, sp := range spans {
		if !pathLikeSpan(sp) {
			out = append(out, sp)
		}
	}
	return out
}

// TestPathLikeSpansAreNotEnvSwitches is the negative control for the filter
// above: it must skip filenames and must NOT skip real switches.
func TestPathLikeSpansAreNotEnvSwitches(t *testing.T) {
	for _, sp := range []string{
		"`docs/scale/TRACKER156_EVIDENCE_2026-08-19.md`",
		"`TRACKER156_EVIDENCE_2026-08-19.md`",
		"`scripts/lab/twin/ownership_runner.py`",
	} {
		if !pathLikeSpan(sp) {
			t.Errorf("%s should be treated as a path, not an env switch", sp)
		}
	}
	for _, sp := range []string{"`BUS_PARTITIONS`", "`CORR_WINDOW_BUFFER`", "`LOG_LEVEL=info`"} {
		if pathLikeSpan(sp) {
			t.Errorf("%s is a real switch and must still be checked", sp)
		}
	}
}

// collectDocumentedEnvTokens scans the operator docs (docs/*.md non-recursive —
// design/ and archive/ are engineering history, not operator promises) plus the
// top-level README for env-shaped tokens presented as code.
func collectDocumentedEnvTokens(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	files := []string{"../../README.md"}
	entries, err := os.ReadDir("../../docs")
	if err != nil {
		t.Fatalf("read docs dir: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			files = append(files, filepath.Join("../../docs", e.Name()))
		}
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, span := range backtickSpans(string(b)) {
			for _, loc := range upperSnakeRe.FindAllStringIndex(span, -1) {
				tok := span[loc[0]:loc[1]]
				if len(tok) < 6 {
					continue // too short to be an env switch (e.g. "SR_1")
				}
				// A partial or decorated match is not a documented switch:
				// `*_MEM_LIMIT` (family glob), `FEATURE_WIRELESS*` (prefix
				// glob), `QUICK_REFERENCE.md` (filename).
				if loc[0] > 0 && (span[loc[0]-1] == '_' || span[loc[0]-1] == '*') {
					continue
				}
				if loc[1] < len(span) && (span[loc[1]] == '*' || span[loc[1]] == '.') {
					continue
				}
				out[tok] = append(out[tok], filepath.Base(f))
			}
		}
	}
	return out
}

// collectConsumedTokens gathers every UPPER_SNAKE token that appears in the
// backend Go sources (string literals — env reads, config tables) or anywhere
// in the deployment configs, scripts, installer, tests, or sibling services.
func collectConsumedTokens(t *testing.T) map[string]bool {
	t.Helper()
	consumed := map[string]bool{}

	// Backend Go: any quoted exact token in non-test sources (env reads,
	// default tables, compose-var references).
	quoted := regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"`)
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		// _test.go files count: a documented TEST-gating var (DATABASE_URL_TEST)
		// is consumed exactly there, which is its documented purpose.
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return rerr
		}
		for _, m := range quoted.FindAllStringSubmatch(string(b), -1) {
			consumed[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend: %v", err)
	}

	// Stack surfaces: any raw occurrence counts as consumption (compose env
	// wiring, nginx/vector configs, installer, scripts, sibling services).
	for _, root := range []string{
		"../../deployment", "../../scripts", "../../tests",
		"../correlation", "../frontend/src", "../config", "../contracts",
	} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil // optional roots may be absent in stripped checkouts
			}
			if info.IsDir() {
				if info.Name() == "node_modules" || info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Size() > 2<<20 {
				return nil // skip binaries/bundles
			}
			b, rerr := os.ReadFile(filepath.Clean(path))
			if rerr != nil {
				return nil
			}
			for _, tok := range upperSnakeRe.FindAllString(string(b), -1) {
				consumed[tok] = true
			}
			return nil
		})
	}
	return consumed
}

func TestEveryDocumentedEnvSwitchIsConsumed(t *testing.T) {
	documented := collectDocumentedEnvTokens(t)
	if len(documented) == 0 {
		t.Fatal("no documented env tokens found — the guard would pass vacuously")
	}
	consumed := collectConsumedTokens(t)

	var missing []string
	for tok, files := range documented {
		if reason, ok := envDocsExempt[tok]; ok {
			if reason == "" {
				t.Errorf("%s is exempted with an empty reason — state why or delete the exemption", tok)
			}
			continue
		}
		if !consumed[tok] {
			missing = append(missing, tok+" (documented in "+strings.Join(uniqueStrings(files), ", ")+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf(`%d documented env token(s) are consumed by NOTHING in the stack:

  %s

  This is the gap-#6 class exactly: an operator can set a switch the docs
  present as real, and nothing anywhere reads it. Fix each one of three ways:
    1. wire it     — make the code actually consume it
    2. un-document — remove it from the docs (it is a lie today)
    3. exempt it   — add it to envDocsExempt with a reason, if it is genuinely
                     not this stack's switch`, len(missing), strings.Join(missing, "\n  "))
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
