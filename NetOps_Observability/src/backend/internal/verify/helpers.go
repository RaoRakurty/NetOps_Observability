// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package verify

// helpers.go — small pure helpers this package needs, duplicated from package
// main (secEnvDuration from device_ssh.go, envInt from report_pipeline.go,
// hostOnly from health_score.go) rather than shared through a common package:
// CLAUDE.md §2 forbids a "utils" dumping ground outright, and the VERIFY_* env
// knobs these read are genuinely this package's own.

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// secEnvDuration reads an integer-seconds env knob, clamped to [lo, hi].
func secEnvDuration(key string, def, lo, hi int) time.Duration {
	v := def
	if s := strings.TrimSpace(os.Getenv(key)); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			v = n
		}
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v) * time.Second
}

// envInt reads a positive integer env knob, falling back to def.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// hostOnly strips a trailing :port from an address, if present.
func hostOnly(dst string) string {
	if i := strings.LastIndex(dst, ":"); i > 0 {
		return dst[:i]
	}
	return dst
}
