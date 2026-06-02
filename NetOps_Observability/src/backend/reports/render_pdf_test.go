package reports

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestPDFRendererDisabled(t *testing.T) {
	if NewPDFRenderer(nil, "") != nil {
		t.Fatal("expected nil renderer with no html and no url")
	}
	html, _ := NewHTMLRenderer()
	if NewPDFRenderer(html, "") != nil {
		t.Fatal("expected nil renderer when sidecar url is empty (PDF disabled)")
	}
	if NewPDFRenderer(html, "http://example/convert").Format() != "pdf" {
		t.Fatal("configured renderer should report pdf")
	}
}

// TestPDFRendererLive renders against a real gotenberg sidecar. Gated on
// REPORT_PDF_SIDECAR_TEST_URL (e.g. a throwaway gotenberg container's
// /forms/chromium/convert/html endpoint).
func TestPDFRendererLive(t *testing.T) {
	url := os.Getenv("REPORT_PDF_SIDECAR_TEST_URL")
	if url == "" {
		t.Skip("set REPORT_PDF_SIDECAR_TEST_URL to run the live PDF render test")
	}
	html, err := NewHTMLRenderer()
	if err != nil {
		t.Fatalf("html renderer: %v", err)
	}
	r := NewPDFRenderer(html, url)
	if r == nil {
		t.Fatal("renderer is nil")
	}
	vm := ViewModel{
		ReportName:  "PDF Test",
		GeneratedAt: time.Date(2026, 6, 2, 7, 0, 0, 0, time.UTC),
		Summary:     "all good",
		Sections:    []Section{{Title: "Devices", Header: []string{"Name", "Address"}, Rows: [][]string{{"core-rtr-1", "10.0.0.1"}}}},
	}
	art, err := r.Render(context.Background(), vm)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if art.Format != "pdf" || art.ContentType != "application/pdf" {
		t.Fatalf("artifact meta: format=%q ctype=%q", art.Format, art.ContentType)
	}
	if !bytes.HasPrefix(art.Bytes, []byte("%PDF")) {
		t.Fatalf("output is not a PDF (missing %%PDF magic)")
	}
	if len(art.Bytes) < 500 {
		t.Fatalf("suspiciously small PDF: %d bytes", len(art.Bytes))
	}
}
