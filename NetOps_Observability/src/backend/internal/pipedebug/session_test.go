// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestSession(t *testing.T, verb string) (*Session, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data", "debug")
	sess, err := NewSession(root, verb, "", time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC), Manifest{Actor: "unit"})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return sess, root
}

// A session can hold tenant telemetry and device output: 0700 on the directory
// and 0600 on every file is the isolation half of §3a, not a nicety.
func TestSessionDirectoryAndFilesArePrivate(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	if err := sess.Line(StageAPI, "info", "hello", nil); err != nil {
		t.Fatalf("Line: %v", err)
	}
	if err := sess.Close(time.Now()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	di, err := os.Stat(sess.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("session dir mode = %o, want 0700 (it may hold tenant telemetry)", di.Mode().Perm())
	}
	for _, name := range []string{"api.log", "manifest.json"} {
		fi, err := os.Stat(filepath.Join(sess.Dir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, fi.Mode().Perm())
		}
	}
}

func TestSessionDirNameIsSortableAndCarriesTheVerb(t *testing.T) {
	early := SessionDirName(time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC), "trace", "01j9abcdefghjkmnpqrstvwxyz")
	late := SessionDirName(time.Date(2026, 9, 4, 12, 5, 0, 0, time.UTC), "trace", "01j9abcdefghjkmnpqrstvwxyz")
	if early >= late {
		t.Error("session directory names do not sort chronologically — `bundle --last N` relies on it")
	}
	if !strings.Contains(early, "-trace-") {
		t.Errorf("session name %q does not carry the verb", early)
	}
}

func TestNewSessionRefusesAnInjectableVerbOrMarker(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	for _, bad := range []string{"../escape", "tr/ace", "."} {
		if _, err := NewSession(root, bad, "", now, Manifest{}); err == nil {
			t.Errorf("NewSession accepted verb %q — the value becomes a directory name", bad)
		}
	}
	if _, err := NewSession(root, "trace", "not-a-marker", now, Manifest{}); err == nil {
		t.Error("NewSession accepted a malformed marker")
	}
}

// THE §3 RULE: a module that was not observed gets ONE line saying why. An
// empty file reads as "nothing happened", which is the silent failure §10
// forbids.
func TestEveryModuleFileExistsAndIsNeverEmpty(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	if err := sess.Line(StageOpenSearch, "info", "found it", map[string]any{"index": "netops-syslog-x"}); err != nil {
		t.Fatal(err)
	}
	if err := sess.EnsureAllModules(func(st Stage) string { return "no collector for " + string(st) }); err != nil {
		t.Fatalf("EnsureAllModules: %v", err)
	}
	if err := sess.Close(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, st := range Stages {
		path := filepath.Join(sess.Dir(), st.LogFile())
		data, err := os.ReadFile(path) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatalf("%s: %v", st.LogFile(), err)
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			t.Errorf("%s is EMPTY — an unobserved module must say so, not look silent", st.LogFile())
		}
		if st != StageOpenSearch {
			if !strings.Contains(string(data), string(VerdictNotObservable)) {
				t.Errorf("%s does not carry the not_observable verdict", st.LogFile())
			}
			if !strings.Contains(string(data), "no collector for "+string(st)) {
				t.Errorf("%s does not carry the caller's reason", st.LogFile())
			}
		}
		// Line-oriented JSON so jq/grep work (design §3).
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Errorf("%s: line is not JSON: %v", st.LogFile(), err)
			}
		}
	}
}

func TestNotObservableRequiresAReason(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	if err := sess.NotObservable(StageKafka, "   "); err == nil {
		t.Error("NotObservable accepted an empty reason — 'not observable' with no cause is the same silent failure as an empty file")
	}
}

func TestFirstLineOfEachModuleFileStatesHowTheLinesWereObtained(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	if err := sess.Header(StageParser, "parser", "docker exec vector-aggregator vector tap", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := sess.Line(StageParser, "info", "an event", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sess.Dir(), "parser.log")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(string(data), "\n", 2)[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["kind"] != "header" || first["how"] != "docker exec vector-aggregator vector tap" || first["window"] != "30s" {
		t.Errorf("header line does not state module/window/how: %v", first)
	}
}

// Redaction happens at WRITE time, so `bundle` can never be the step that
// forgot (design §5).
func TestSessionLinesAreRedactedOnTheWayToDisk(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	if err := sess.Line(StageAPI, "info", "snmp-server community s3cr3t-community RO", map[string]any{
		"header": "Authorization: Bearer eyJhbGciOi.SECRET.sig",
		"tenant": "t_abc123",
	}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sess.Dir(), "api.log")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if strings.Contains(body, "s3cr3t-community") {
		t.Error("an SNMP community reached the session file")
	}
	if strings.Contains(body, "eyJhbGciOi.SECRET.sig") {
		t.Error("a bearer token reached the session file")
	}
	if !strings.Contains(body, "t_abc123") {
		t.Error("the tenant id was redacted — support needs it (design §5 keeps tenant ids)")
	}
}

func TestManifestRecordsProvenanceAndWarnings(t *testing.T) {
	sess, _ := newTestSession(t, "trace")
	sess.Warn("the tap on %s failed", "syslog_in")
	if err := sess.SetMarker("01j9abcdefghjkmnpqrstvwxyz"); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(time.Date(2026, 9, 4, 11, 9, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sess.Dir(), "manifest.json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var man Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		t.Fatal(err)
	}
	if man.Verb != "trace" || man.Actor != "unit" || man.Marker != "01j9abcdefghjkmnpqrstvwxyz" {
		t.Errorf("manifest lost provenance: %+v", man)
	}
	if man.Redaction == "" {
		t.Error("the manifest does not say which redaction pass ran")
	}
	if len(man.Warnings) != 1 || !strings.Contains(man.Warnings[0], "syslog_in") {
		t.Errorf("a degraded run does not say so on its face: %+v", man.Warnings)
	}
	if man.Finished.IsZero() {
		t.Error("the manifest carries no finish time")
	}
}

func TestListSessionsIsNewestFirst(t *testing.T) {
	root := filepath.Join(t.TempDir(), "debug")
	for _, h := range []int{11, 13, 12} {
		if _, err := NewSession(root, "trace", "", time.Date(2026, 9, 4, h, 0, 0, 0, time.UTC), Manifest{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListSessions(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !strings.Contains(got[0], "T1300Z") {
		t.Errorf("ListSessions is not newest-first: %v", got)
	}
}
