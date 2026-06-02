package reports

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHTMLRenderer(t *testing.T) {
	r, err := NewHTMLRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	if r.Format() != "html" {
		t.Fatalf("format = %q", r.Format())
	}
	vm := ViewModel{
		ReportName:  "Weekly Stack Health",
		Kind:        "health_summary",
		GeneratedAt: time.Date(2026, 6, 2, 7, 0, 0, 0, time.UTC),
		Severity:    "info",
		Summary:     "All systems nominal",
		Description: "Generated for the executive team",
		Sections: []Section{
			{Title: "Devices", Rows: [][]string{{"core-rtr-1", "10.0.0.1"}, {"core-rtr-2", "10.0.0.2"}}},
			{Title: "Notes", Note: "No active alerts in the last 24h."},
		},
	}
	art, err := r.Render(context.Background(), vm)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if art.Format != "html" || !strings.HasPrefix(art.ContentType, "text/html") {
		t.Fatalf("artifact format=%q ctype=%q", art.Format, art.ContentType)
	}
	if art.Summary != "All systems nominal" {
		t.Fatalf("summary = %q", art.Summary)
	}
	html := string(art.Bytes)

	// Content present.
	for _, want := range []string{
		"Weekly Stack Health", "health_summary", "All systems nominal",
		"Generated for the executive team", "core-rtr-1", "10.0.0.2",
		"No active alerts in the last 24h.", "2026-06-02 07:00 UTC",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}

	// Inline-CSS, email-safe: no external assets / scripts that email clients strip.
	if !strings.Contains(html, "style=") {
		t.Errorf("expected inline styles")
	}
	for _, bad := range []string{"<script", "<link", "http://", "https://", "url("} {
		if strings.Contains(html, bad) {
			t.Errorf("HTML must avoid external/scriptable %q (email-safe)", bad)
		}
	}
}

func TestHTMLRendererEscapesData(t *testing.T) {
	r, _ := NewHTMLRenderer()
	vm := ViewModel{
		ReportName: "X",
		Summary:    `<script>alert(1)</script>`,
		Sections:   []Section{{Title: "T", Rows: [][]string{{`<b>bad</b>`}}}},
	}
	art, err := r.Render(context.Background(), vm)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	html := string(art.Bytes)
	// Report data must be escaped, never emitted as live markup.
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<b>bad</b>") {
		t.Fatalf("report data was not HTML-escaped (injection risk)")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag in output")
	}
}

func TestHTMLRendererEmptyDefaults(t *testing.T) {
	r, _ := NewHTMLRenderer()
	// No summary -> falls back to report name; zero GeneratedAt -> filled.
	art, err := r.Render(context.Background(), ViewModel{ReportName: "Fallback Report"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if art.Summary != "Fallback Report" {
		t.Fatalf("summary fallback = %q", art.Summary)
	}
	if !strings.Contains(string(art.Bytes), "Fallback Report") {
		t.Fatalf("missing report name")
	}
}
