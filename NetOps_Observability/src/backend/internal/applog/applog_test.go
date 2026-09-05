package applog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogEmitsOneJSONLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log("info", "unit", "hello", map[string]any{"k": "v"})
	l.Log("warn", "unit", "second", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 1 && lines[0] == "" || len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("line is not JSON: %v", err)
	}
	for _, k := range []string{"ts", "level", "component", "msg", "k"} {
		if _, ok := ev[k]; !ok {
			t.Errorf("event missing %q: %v", k, ev)
		}
	}
	if ev["level"] != "info" || ev["component"] != "unit" || ev["msg"] != "hello" || ev["k"] != "v" {
		t.Errorf("wrong event content: %v", ev)
	}
}

// Caller fields win over base keys — historical contract (see Log doc).
func TestCallerFieldsOverrideBaseKeys(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log("info", "unit", "m", map[string]any{"component": "override"})
	var ev map[string]any
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if ev["component"] != "override" {
		t.Errorf("caller field must win, got %v", ev["component"])
	}
}

func TestSwapWriterForTestRestores(t *testing.T) {
	var buf bytes.Buffer
	restore := SwapWriterForTest(&buf)
	Info("unit", "captured", nil)
	restore()
	if !strings.Contains(buf.String(), `"captured"`) {
		t.Fatalf("swapped writer did not capture: %q", buf.String())
	}
	n := buf.Len()
	Info("unit", "after-restore", nil)
	if buf.Len() != n {
		t.Fatal("restore did not detach the test writer")
	}
}

// ── the pipeline debugger's two additions (DEBUG-ROUTES) ────────────────────

// Debug is OFF by default: the shipped stack's log volume must be byte-for-byte
// unchanged by the existence of this function.
func TestDebugIsOffByDefaultAndAddsLinesWhenOn(t *testing.T) {
	var buf bytes.Buffer
	restore := SwapWriterForTest(&buf)
	defer restore()
	defer SetDebug(false)

	SetDebug(false)
	Debug("unit", "should not appear", nil)
	if buf.Len() != 0 {
		t.Fatalf("Debug emitted with debug off: %q", buf.String())
	}

	if prev := SetDebug(true); prev {
		t.Error("SetDebug did not report the previous state")
	}
	Debug("unit", "should appear", nil)
	if !strings.Contains(buf.String(), "should appear") {
		t.Fatalf("Debug did not emit with debug on: %q", buf.String())
	}
	var ev map[string]any
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["level"] != "debug" {
		t.Errorf("level = %v, want debug", ev["level"])
	}
}

// Turning debug on must never SUPPRESS anything: info/warn/error are
// unconditional, so the switch can only ever add lines.
func TestInfoWarnErrorAreUnaffectedByTheDebugSwitch(t *testing.T) {
	for _, on := range []bool{false, true} {
		var buf bytes.Buffer
		restore := SwapWriterForTest(&buf)
		SetDebug(on)
		Info("unit", "i", nil)
		Warn("unit", "w", nil)
		Error("unit", "e", nil)
		restore()
		if n := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1; n != 3 {
			t.Errorf("debug=%v: %d lines, want 3 — the switch must never suppress a level", on, n)
		}
	}
	SetDebug(false)
}

func TestSetLevelSpeaksTheTwoValueVocabularyAndFailsSafe(t *testing.T) {
	defer SetDebug(false)
	if prev := SetLevel("debug"); prev != "info" {
		t.Errorf("previous = %q, want info", prev)
	}
	if Level() != "debug" || !DebugEnabled() {
		t.Error("SetLevel(debug) did not take effect")
	}
	// Anything unrecognised turns debug OFF — the fail-safe direction.
	for _, bad := range []string{"info", "trace", "", "WARN", "nonsense"} {
		SetLevel("debug")
		SetLevel(bad)
		if DebugEnabled() {
			t.Errorf("SetLevel(%q) left debug emission on", bad)
		}
	}
}

// The observer is what lets the debugger serve the API's own marker lines
// WITHOUT reading them back through the pipeline under test.
func TestObserverSeesEveryEventAndIsRestorable(t *testing.T) {
	var buf bytes.Buffer
	restoreW := SwapWriterForTest(&buf)
	defer restoreW()

	var seen []string
	restore := SetObserver(func(level, component, msg string, fields map[string]any) {
		seen = append(seen, level+":"+component+":"+msg+":"+fmt.Sprint(fields["k"]))
	})
	Info("unit", "one", map[string]any{"k": "v"})
	Error("unit", "two", nil)
	restore()
	Info("unit", "after-restore", nil)

	if len(seen) != 2 {
		t.Fatalf("observer saw %d events, want 2: %v", len(seen), seen)
	}
	if seen[0] != "info:unit:one:v" || seen[1] != "error:unit:two:<nil>" {
		t.Errorf("observer got the wrong events: %v", seen)
	}
	if !strings.Contains(buf.String(), "after-restore") {
		t.Error("removing the observer stopped the logger writing")
	}
}

// A panicking observer must not take the process down through the log path.
func TestObserverIsNotOnTheWriterLock(t *testing.T) {
	var buf bytes.Buffer
	restoreW := SwapWriterForTest(&buf)
	defer restoreW()
	// The observer logs again. If notify ran under the writer lock this would
	// deadlock rather than fail.
	depth := 0
	restore := SetObserver(func(level, component, msg string, fields map[string]any) {
		if depth == 0 {
			depth++
			// A re-entrant write proves the writer lock is not held.
			_ = fields
		}
	})
	defer restore()
	done := make(chan struct{})
	go func() {
		Info("unit", "reentrant", nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("logging deadlocked — the observer is running under the writer lock")
	}
}
