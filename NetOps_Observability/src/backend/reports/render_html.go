package reports

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"time"
)

//go:embed templates/report.tmpl.html
var templatesFS embed.FS

// htmlRenderer formats a ViewModel into a responsive, inline-CSS HTML document
// usable as both an email body and a standalone downloadable artifact. It uses
// html/template (stdlib), which auto-escapes all interpolated values, so report
// data can never inject markup. The PDF sidecar (later phase) will implement the
// same Renderer interface by POSTing this HTML to a headless-Chromium service.
type htmlRenderer struct {
	tmpl *template.Template
}

// NewHTMLRenderer parses the embedded template once at startup.
func NewHTMLRenderer() (Renderer, error) {
	t, err := template.New("report.tmpl.html").Funcs(template.FuncMap{
		"fmtTime": func(tm time.Time) string { return tm.UTC().Format("2006-01-02 15:04 MST") },
		// odd drives zebra striping in the section tables (1-based visual rows).
		"odd": func(i int) bool { return i%2 == 1 },
	}).ParseFS(templatesFS, "templates/report.tmpl.html")
	if err != nil {
		return nil, err
	}
	return &htmlRenderer{tmpl: t}, nil
}

func (r *htmlRenderer) Format() string { return "html" }

func (r *htmlRenderer) Render(_ context.Context, vm ViewModel) (Artifact, error) {
	if vm.GeneratedAt.IsZero() {
		vm.GeneratedAt = time.Now().UTC()
	}
	var buf bytes.Buffer
	if err := r.tmpl.Execute(&buf, vm); err != nil {
		return Artifact{}, err
	}
	summary := vm.Summary
	if summary == "" {
		summary = vm.ReportName
	}
	return Artifact{
		Format:      "html",
		ContentType: "text/html; charset=utf-8",
		Bytes:       buf.Bytes(),
		Summary:     summary,
	}, nil
}
