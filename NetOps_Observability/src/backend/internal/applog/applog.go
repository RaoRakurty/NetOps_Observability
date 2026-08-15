// Package applog is the process-wide structured logger — one JSON line per
// event to stdout. Vector's docker_logs source picks them up, parses the
// JSON, ships to the Kafka bus (topic netops.applogs), and vector-router then
// writes them into the `netops-applogs-YYYY.MM.DD` OpenSearch index.
package applog

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Logger serializes structured events onto one writer. The zero value is not
// usable; construct with New.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Logger emitting JSON lines to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Log emits one event. Caller-supplied fields win over the base keys, which
// is the historical behavior some emitters rely on (e.g. stamping their own
// "component" detail).
func (l *Logger) Log(level, component, msg string, fields map[string]any) {
	event := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"msg":       msg,
	}
	for k, v := range fields {
		event[k] = v
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.w).Encode(event) // the logger has nowhere to report its own failure
}

// std is the process logger. Package-level on purpose: it mirrors the
// stdlib's log.Default and the pre-extraction appLog global — every caller in
// the process shares one serialized stdout stream.
var std = New(os.Stdout)

// Info logs at level info on the process logger.
func Info(component, msg string, fields map[string]any) { std.Log("info", component, msg, fields) }

// Warn logs at level warn on the process logger.
func Warn(component, msg string, fields map[string]any) { std.Log("warn", component, msg, fields) }

// Error logs at level error on the process logger.
func Error(component, msg string, fields map[string]any) { std.Log("error", component, msg, fields) }

// Log logs at a caller-chosen level on the process logger — for adapters that
// forward another component's already-leveled events (e.g. the notifier).
func Log(level, component, msg string, fields map[string]any) { std.Log(level, component, msg, fields) }

// SwapWriterForTest points the process logger at w and returns a restore
// func. Tests that assert on emitted lines use this instead of poking the
// logger's fields.
func SwapWriterForTest(w io.Writer) func() {
	std.mu.Lock()
	prev := std.w
	std.w = w
	std.mu.Unlock()
	return func() {
		std.mu.Lock()
		std.w = prev
		std.mu.Unlock()
	}
}
