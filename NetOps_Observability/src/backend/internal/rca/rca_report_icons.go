package rca

// rca_report_icons.go — the cloud glyphs the RCA report's path-causality SVG
// draws above cloud hops.
//
// Licence audit D5 (2026-09-04): these used to be the providers' OFFICIAL marks
// (the AWS Architecture Icons "AWS Cloud logo", the Azure Public Service Icon
// and the Google Cloud four-colour symbol), vendored and go:embed'd into the
// shipped binary. They were trademark files carried under a terms-of-use
// posture rather than a licence, and the terms did not travel with the binary
// that embedded them, so the owner decided to remove them and draw our own.
//
// What is embedded now is ORIGINAL Correlix artwork (cloudicons/README.md):
// one cloud silhouette, identical across all three files, distinguished ONLY by
// a plain letter tag — AWS / AZ / GCP — a nominative textual reference, not a
// stylised wordmark. No provider colour appears; the glyph strokes in
// currentColor. They stay embedded so the exported document is self-contained
// (Gotenberg renders it with no network).

import (
	"embed"
	"encoding/base64"
	"strings"
	"sync"
)

//go:embed cloudicons/*.svg
var cloudIconFiles embed.FS

// cloudIconProviders are the providers we have drawn a tagged glyph for. A
// provider outside this set has NO glyph on purpose — rca_report_html.go then
// renders its name as text, which is honest, rather than borrowing another
// provider's mark.
var cloudIconProviders = []string{"aws", "azure", "gcp"}

var cloudIconURIOnce sync.Once
var cloudIconURIs map[string]string

// CloudIconDataURI returns a data: URI for the Correlix cloud glyph of a
// provider we have drawn (aws, azure, gcp), or "" — callers fall back to a text
// label, never to another provider's mark.
func CloudIconDataURI(provider string) string {
	cloudIconURIOnce.Do(func() {
		cloudIconURIs = map[string]string{}
		for _, name := range cloudIconProviders {
			b, err := cloudIconFiles.ReadFile("cloudicons/" + name + ".svg")
			if err != nil {
				continue // embed guarantees presence; stay safe, fall back to text
			}
			cloudIconURIs[name] = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(b)
		}
	})
	return cloudIconURIs[strings.ToLower(strings.TrimSpace(provider))]
}
