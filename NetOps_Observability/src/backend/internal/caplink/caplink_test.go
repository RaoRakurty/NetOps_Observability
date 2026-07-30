package caplink

// In-package contract pins. The end-to-end suites (log masking through the
// real middleware, the view handlers' authorization) live in main with the
// wiring; these pin the crypto contract at the package boundary.

import (
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTripAndTenantBinding(t *testing.T) {
	tok := SignReport("s3cret", "exec-1", "acme", time.Hour)
	execID, tenant, err := VerifyReport("s3cret", tok)
	if err != nil || execID != "exec-1" || tenant != "acme" {
		t.Fatalf("round trip: %q %q %v", execID, tenant, err)
	}
	if _, _, err := VerifyReport("wrong-secret", tok); err == nil {
		t.Fatal("wrong secret must not verify")
	}
	// The domain label keeps report and export capabilities from cross-validating.
	if _, _, err := VerifyExport("s3cret", tok); err == nil {
		t.Fatal("a report token must not authorize an export view")
	}
}

func TestVerifyRejectsExpiredAndMalformed(t *testing.T) {
	stale := SignExport("s3cret", "exec-2", "acme", -time.Hour)
	if _, _, err := VerifyExport("s3cret", stale); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token must be refused: %v", err)
	}
	for _, bad := range []string{"", "a.b", "not-base64!!.x.y.z"} {
		if _, _, err := VerifyReport("s3cret", bad); err == nil {
			t.Fatalf("malformed token %q verified", bad)
		}
	}
	// Tampering with the tenant segment must break the signature.
	tok := SignReport("s3cret", "exec-1", "acme", time.Hour)
	parts := strings.Split(tok, ".")
	parts[1] = parts[0] // swap in a different valid base64 blob
	if _, _, err := VerifyReport("s3cret", strings.Join(parts, ".")); err == nil {
		t.Fatal("tenant-tampered token verified")
	}
}

func TestClampExportTTL(t *testing.T) {
	if ClampExportTTL(time.Minute) != 5*time.Minute || ClampExportTTL(time.Hour) != 15*time.Minute {
		t.Fatal("TTL clamp bounds broken")
	}
	if ClampExportTTL(10*time.Minute) != 10*time.Minute {
		t.Fatal("in-range TTL must pass through")
	}
}

func TestMaskTokenPathKeepsSafeSegments(t *testing.T) {
	rules := []PathRule{{Prefix: "/api/w/", Keep: 1}}
	if got := MaskTokenPath("/api/w/provider/tok-123", rules); got != "/api/w/provider/"+MaskedTokenSegment {
		t.Fatalf("mask = %q", got)
	}
	if got := MaskTokenPath("/api/other/x", rules); got != "/api/other/x" {
		t.Fatalf("non-token path touched: %q", got)
	}
}
