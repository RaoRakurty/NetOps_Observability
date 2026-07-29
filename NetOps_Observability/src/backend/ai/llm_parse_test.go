package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Validate that each provider's response shape is extracted correctly (the part
// most likely to break when a provider tweaks its API), using real-shaped bodies.
func TestParseOpenAI(t *testing.T) {
	body := `{"id":"x","choices":[{"message":{"role":"assistant","content":"Create inventory in NetBox."},"finish_reason":"stop"}],"model":"gpt-4o-mini"}`
	got, err := parseOpenAI([]byte(body))
	if err != nil || got != "Create inventory in NetBox." {
		t.Fatalf("parseOpenAI = %q, err=%v", got, err)
	}
	if _, err := parseOpenAI([]byte(`{"choices":[]}`)); err == nil {
		t.Error("empty choices must error")
	}
	if _, err := parseOpenAI([]byte(`not json`)); err == nil {
		t.Error("malformed must error")
	}
}

func TestParseGemini(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Open "},{"text":"NetBox."}]}}]}`
	got, err := parseGemini([]byte(body))
	if err != nil || got != "Open NetBox." {
		t.Fatalf("parseGemini = %q, err=%v", got, err)
	}
	if _, err := parseGemini([]byte(`{"candidates":[]}`)); err == nil {
		t.Error("no candidates must error")
	}
}

func TestParseAnthropic(t *testing.T) {
	body := `{"content":[{"type":"text","text":"NetBox is the source of truth."},{"type":"tool_use","id":"t"}],"role":"assistant"}`
	got, err := parseAnthropic([]byte(body))
	if err != nil || got != "NetBox is the source of truth." {
		t.Fatalf("parseAnthropic = %q, err=%v", got, err)
	}
	if _, err := parseAnthropic([]byte(`{"content":[]}`)); err == nil {
		t.Error("no text blocks must error")
	}
}

// providerDo returns the body on 2xx and, on non-2xx, an error WITHOUT leaking the
// provider body to the caller (SR-022). Exercised against a local server.
func TestProviderDoSuccessAndRedaction(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer ok.Close()
	rb, err := ProviderDo(context.Background(), ok.URL, nil, []byte(`{}`), "test")
	if err != nil || string(rb) != `{"hello":"world"}` {
		t.Fatalf("2xx: rb=%q err=%v", rb, err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"secret-org-id leaked here"}}`))
	}))
	defer bad.Close()
	_, err = ProviderDo(context.Background(), bad.URL, nil, []byte(`{}`), "test")
	if err == nil {
		t.Fatal("non-2xx must return an error")
	}
	if strings.Contains(err.Error(), "secret-org-id") {
		t.Error("provider error body must NOT leak into the returned error (SR-022)")
	}
}
