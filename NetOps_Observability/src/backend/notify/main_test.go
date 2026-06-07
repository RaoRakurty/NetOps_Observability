package notify

import (
	"os"
	"testing"
)

// TestMain allows private/loopback targets for the package's tests, which post
// to httptest servers on 127.0.0.1. In production the SSRF guard (safehttp,
// SR-015) blocks those addresses for tenant-configurable webhook/ITSM URLs;
// here we opt in so the senders can reach the local test servers.
func TestMain(m *testing.M) {
	os.Setenv("SSRF_ALLOW_PRIVATE", "true")
	os.Exit(m.Run())
}
