package dem

import (
	"encoding/json"
	"os"
	"strings"
)

// writeFile is the tests' direct disk write (the store itself goes through the
// platform kv seam, which resolves to the same path in the default file build).
func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

// sprintfWire renders a work item the way the transport does (JSON), so the
// "carries nothing extra" assertion tests the bytes that actually leave.
func sprintfWire(w WireTarget) string {
	b, err := json.Marshal(w)
	if err != nil {
		return ""
	}
	return string(b)
}

func contains(hay, needle string) bool { return strings.Contains(hay, needle) }
