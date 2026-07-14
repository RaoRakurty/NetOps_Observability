package main

// rca_report_icons.go — the OFFICIAL cloud-provider marks the RCA report's
// path-causality SVG draws above cloud hops. Vendored from the providers'
// official icon packages (source + terms in cloudicons/README.md) and rendered
// as-is per those terms; embedded so the exported document stays fully
// self-contained (Gotenberg renders it with no network).

import (
	"embed"
	"encoding/base64"
	"strings"
	"sync"
)

//go:embed cloudicons/*.svg
var cloudIconFiles embed.FS

var cloudIconURIOnce sync.Once
var cloudIconURIs map[string]string

// cloudIconDataURI returns a data: URI for the official mark of a provider we
// have vendored (aws, azure), or "" — callers fall back to a text label, never
// to an unofficial approximation.
func cloudIconDataURI(provider string) string {
	cloudIconURIOnce.Do(func() {
		cloudIconURIs = map[string]string{}
		for _, name := range []string{"aws", "azure"} {
			b, err := cloudIconFiles.ReadFile("cloudicons/" + name + ".svg")
			if err != nil {
				continue // embed guarantees presence; stay safe, fall back to text
			}
			cloudIconURIs[name] = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(b)
		}
	})
	return cloudIconURIs[strings.ToLower(strings.TrimSpace(provider))]
}
