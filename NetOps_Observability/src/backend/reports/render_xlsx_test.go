package reports

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestXLSXRenderer(t *testing.T) {
	r := NewXLSXRenderer()
	if r.Format() != "xlsx" {
		t.Fatalf("format = %q", r.Format())
	}
	vm := ViewModel{
		ReportName:  "Weekly Health",
		GeneratedAt: time.Date(2026, 6, 2, 7, 0, 0, 0, time.UTC),
		Summary:     "all good",
		Sections: []Section{
			{Title: "Devices", Header: []string{"Name", "Address"}, Rows: [][]string{{"core-rtr-1", "10.0.0.1"}, {"core-rtr-2", "10.0.0.2"}}},
			{Title: "Notes", Note: "line one\nline two"},
		},
	}
	art, err := r.Render(context.Background(), vm)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if art.Format != "xlsx" || !strings.Contains(art.ContentType, "spreadsheetml") {
		t.Fatalf("artifact meta: %+v", art.ContentType)
	}

	// Must be a valid zip with the OOXML parts.
	zr, err := zip.NewReader(bytes.NewReader(art.Bytes), int64(len(art.Bytes)))
	if err != nil {
		t.Fatalf("artifact is not a valid zip: %v", err)
	}
	want := map[string]bool{
		"[Content_Types].xml": false, "_rels/.rels": false,
		"xl/workbook.xml": false, "xl/_rels/workbook.xml.rels": false,
		"xl/styles.xml": false, "xl/worksheets/sheet1.xml": false,
	}
	var sheet string
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing OOXML part %s", name)
		}
	}
	for _, cell := range []string{"Weekly Health", "Devices", "Name", "Address", "core-rtr-1", "10.0.0.2", "line one", "line two"} {
		if !strings.Contains(sheet, cell) {
			t.Errorf("sheet missing cell %q", cell)
		}
	}
}

func TestXLSXEscaping(t *testing.T) {
	r := NewXLSXRenderer()
	vm := ViewModel{ReportName: "x", Sections: []Section{{Title: "T", Rows: [][]string{{`a<b>&"c`}}}}}
	art, err := r.Render(context.Background(), vm)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(art.Bytes), int64(len(art.Bytes)))
	var sheet string
	for _, f := range zr.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	if strings.Contains(sheet, "a<b>&") {
		t.Fatalf("cell value not XML-escaped (would corrupt the workbook)")
	}
	if !strings.Contains(sheet, "a&lt;b&gt;&amp;") {
		t.Fatalf("expected escaped entities in sheet")
	}
}

func TestColName(t *testing.T) {
	cases := map[int]string{0: "A", 1: "B", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA"}
	for i, want := range cases {
		if got := colName(i); got != want {
			t.Errorf("colName(%d) = %s, want %s", i, got, want)
		}
	}
}
