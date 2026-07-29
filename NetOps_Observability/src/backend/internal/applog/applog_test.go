package applog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
