// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestPDFRendererDisabled(t *testing.T) {
	if NewPDFRenderer(nil, "", nil) != nil {
		t.Fatal("expected nil renderer with no html and no url")
	}
	html, _ := NewHTMLRenderer()
	if NewPDFRenderer(html, "", nil) != nil {
		t.Fatal("expected nil renderer when sidecar url is empty (PDF disabled)")
	}
	if NewPDFRenderer(html, "http://example/convert", nil).Format() != "pdf" {
		t.Fatal("configured renderer should report pdf")
	}
}

// countingTransport wraps a RoundTripper and counts the requests that ride it.
type countingTransport struct {
	base  http.RoundTripper
	calls int
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	return c.base.RoundTrip(req)
}

// The renderer must use the INJECTED client (main wires the hardened mesh
// transport — backendHTTPClient — through this seam; SEC-0xx gotenberg TLS).
// A renderer that quietly builds its own client would bypass mesh-CA trust.
func TestPDFRendererUsesInjectedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("%PDF-1.7 fake"))
	}))
	defer srv.Close()
	html, err := NewHTMLRenderer()
	if err != nil {
		t.Fatal(err)
	}
	ct := &countingTransport{base: http.DefaultTransport}
	client := &http.Client{Timeout: 10 * time.Second, Transport: ct}
	r := NewPDFRenderer(html, srv.URL, client)
	if r == nil {
		t.Fatal("renderer is nil")
	}
	art, err := r.Render(context.Background(), ViewModel{ReportName: "t", GeneratedAt: time.Now()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if ct.calls == 0 {
		t.Fatal("the injected client was not used — the renderer built its own transport")
	}
	if !bytes.HasPrefix(art.Bytes, []byte("%PDF")) {
		t.Fatalf("unexpected artifact bytes: %q", art.Bytes)
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
	r := NewPDFRenderer(html, url, nil)
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
