package main

import (
	"strings"
	"testing"
	"time"
)

func TestReportLinkSignVerify(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "test-link-secret")

	tok := signReportLink("exec-123", time.Hour)
	got, err := verifyReportLink(tok)
	if err != nil || got != "exec-123" {
		t.Fatalf("round-trip: got %q err=%v", got, err)
	}

	// Tampering with the execution id must fail the signature.
	parts := strings.Split(tok, ".")
	forged := "ZXhlYy05OTk" + "." + parts[1] + "." + parts[2] // b64("exec-999")
	if _, err := verifyReportLink(forged); err == nil {
		t.Fatal("forged execution id must fail verification")
	}

	// A flipped signature byte must fail.
	bad := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "X"
	if _, err := verifyReportLink(bad); err == nil {
		t.Fatal("tampered signature must fail")
	}

	// Malformed tokens.
	for _, m := range []string{"", "a.b", "a.b.c.d", "not-a-token"} {
		if _, err := verifyReportLink(m); err == nil {
			t.Errorf("malformed token %q should fail", m)
		}
	}
}

func TestReportLinkExpiry(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "test-link-secret")
	expired := signReportLink("exec-1", -time.Minute) // already expired
	if _, err := verifyReportLink(expired); err == nil {
		t.Fatal("expired link must be rejected")
	}
}

func TestReportViewLink(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "s")
	t.Setenv("REPORT_PUBLIC_BASE_URL", "https://netra.example.com/")
	u := reportViewLink("exec-1", "html")
	if !strings.HasPrefix(u, "https://netra.example.com/api/reports/view/") {
		t.Fatalf("link base wrong: %s", u)
	}
	if strings.Contains(u, "?format") {
		t.Fatalf("html should not carry a format query: %s", u)
	}
	x := reportViewLink("exec-1", "xlsx")
	if !strings.HasSuffix(x, "?format=xlsx") {
		t.Fatalf("xlsx link should carry format: %s", x)
	}
}
