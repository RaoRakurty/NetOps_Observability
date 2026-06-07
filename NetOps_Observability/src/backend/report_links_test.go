package main

import (
	"strings"
	"testing"
	"time"
)

func TestReportLinkSignVerify(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "test-link-secret")

	tok := signReportLink("exec-123", "acme", time.Hour)
	got, gotTenant, err := verifyReportLink(tok)
	if err != nil || got != "exec-123" || gotTenant != "acme" {
		t.Fatalf("round-trip: got %q tenant=%q err=%v", got, gotTenant, err)
	}

	// Tampering with the execution id must fail the signature.
	parts := strings.Split(tok, ".")
	forged := "ZXhlYy05OTk" + "." + parts[1] + "." + parts[2] + "." + parts[3] // b64("exec-999")
	if _, _, err := verifyReportLink(forged); err == nil {
		t.Fatal("forged execution id must fail verification")
	}

	// SR-018: swapping the tenant segment must fail the signature.
	tenantSwap := parts[0] + "." + "b3RoZXI" + "." + parts[2] + "." + parts[3] // b64("other")
	if _, _, err := verifyReportLink(tenantSwap); err == nil {
		t.Fatal("forged tenant must fail verification")
	}

	// A flipped signature byte must fail.
	bad := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3][:len(parts[3])-1] + "X"
	if _, _, err := verifyReportLink(bad); err == nil {
		t.Fatal("tampered signature must fail")
	}

	// Malformed tokens.
	for _, m := range []string{"", "a.b", "a.b.c", "not-a-token"} {
		if _, _, err := verifyReportLink(m); err == nil {
			t.Errorf("malformed token %q should fail", m)
		}
	}
}

func TestReportLinkExpiry(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "test-link-secret")
	expired := signReportLink("exec-1", "acme", -time.Minute) // already expired
	if _, _, err := verifyReportLink(expired); err == nil {
		t.Fatal("expired link must be rejected")
	}
}

func TestReportViewLink(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "s")
	t.Setenv("REPORT_PUBLIC_BASE_URL", "https://opsis.example.com/")
	u := reportViewLink("exec-1", "acme", "html")
	if !strings.HasPrefix(u, "https://opsis.example.com/api/reports/view/") {
		t.Fatalf("link base wrong: %s", u)
	}
	if strings.Contains(u, "?format") {
		t.Fatalf("html should not carry a format query: %s", u)
	}
	x := reportViewLink("exec-1", "acme", "xlsx")
	if !strings.HasSuffix(x, "?format=xlsx") {
		t.Fatalf("xlsx link should carry format: %s", x)
	}
}
