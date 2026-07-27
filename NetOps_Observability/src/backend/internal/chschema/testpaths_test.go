package chschema

// testpaths_test.go — locate repo files without hardcoding a directory depth.
//
// These guards compare the Go DDL against deployment/docker/clickhouse/init.sql.
// They used to reach it with a fixed "../../" that was correct only while this
// code lived in src/backend; the 2026-07-27 extraction moved it two levels
// deeper and every one of them failed on a missing file. A fixed depth is a
// silent tripwire for the NEXT move too, so resolve the root by walking up for
// a marker instead.

import (
	"os"
	"path/filepath"
	"testing"
)

// repoFile returns an absolute path to a file given RELATIVE TO THE PROJECT
// ROOT (the directory holding deployment/ and src/).
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "deployment", "docker")); err == nil {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate the project root from %s — no ancestor has deployment/docker", dir)
	return ""
}
