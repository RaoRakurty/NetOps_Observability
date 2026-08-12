package reports

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// render_pdf.go — the PDF renderer as a SIDECAR seam. PDF generation needs a
// headless browser, which is far outside the backend's stdlib-only budget, so it
// runs as a separate container (Gotenberg / headless-Chromium). This renderer
// produces the HTML view, then POSTs it to that sidecar over HTTP and returns the
// PDF bytes — keeping the Go binary dependency-free.
//
// NewPDFRenderer returns nil when no sidecar URL is configured, so PDF is simply
// an unavailable format (the pipeline skips it) rather than an error.
type pdfRenderer struct {
	html   Renderer
	url    string
	client *http.Client
}

// NewPDFRenderer wires the PDF seam. sidecarURL is the full convert endpoint
// (e.g. http://gotenberg:3000/forms/chromium/convert/html). Empty => disabled.
//
// client is the transport seam (SEC gotenberg TLS): on mesh-TLS deployments the
// caller MUST inject the hardened backend client (main wires
// backendHTTPClient), which verifies the sidecar's SVID against the mesh CA
// and presents the api's SVID. Gotenberg 8 serves TLS but performs no
// client-certificate verification, so the hop is server-verified TLS (not
// mTLS) — the SVID is presented regardless via the shared transport. nil =>
// a plain default client (plaintext fresh-install baseline); this package
// deliberately has NO TLS knobs of its own — trust rides the injected client.
func NewPDFRenderer(html Renderer, sidecarURL string, client *http.Client) Renderer {
	if strings.TrimSpace(sidecarURL) == "" || html == nil {
		return nil
	}
	if client == nil {
		client = defaultSidecarClient()
	}
	return &pdfRenderer{html: html, url: sidecarURL, client: client}
}

func (p *pdfRenderer) Format() string { return "pdf" }

func (p *pdfRenderer) Render(ctx context.Context, vm ViewModel) (Artifact, error) {
	htmlArt, err := p.html.Render(ctx, vm)
	if err != nil {
		return Artifact{}, err
	}
	// Gotenberg's Chromium route takes a multipart form with an index.html file.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("files", "index.html")
	if err != nil {
		return Artifact{}, err
	}
	if _, err := fw.Write(htmlArt.Bytes); err != nil {
		return Artifact{}, err
	}
	if err := mw.Close(); err != nil {
		return Artifact{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, &body)
	if err != nil {
		return Artifact{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := p.client.Do(req)
	if err != nil {
		return Artifact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Artifact{}, fmt.Errorf("pdf sidecar returned %d", resp.StatusCode)
	}
	pdf, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
	if err != nil {
		return Artifact{}, err
	}
	summary := vm.Summary
	if summary == "" {
		summary = vm.ReportName
	}
	return Artifact{Format: "pdf", ContentType: "application/pdf", Bytes: pdf, Summary: summary}, nil
}
