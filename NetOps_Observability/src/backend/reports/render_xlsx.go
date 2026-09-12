// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// render_xlsx.go — an in-process Excel (.xlsx) renderer built from the stdlib
// only (archive/zip + hand-written OOXML SpreadsheetML). No third-party module
// (excelize et al. are not on the allowlist). It emits a minimal but valid
// workbook: one worksheet using inline strings (so no sharedStrings part is
// needed) and a styles part with a bold font for section titles + table headers.
//
// The ViewModel is the same dataset HTML/PDF render from, so the spreadsheet
// carries real cells (filterable/sortable in Excel), not a pasted text blob.
type xlsxRenderer struct{}

// NewXLSXRenderer returns the in-process Excel renderer.
func NewXLSXRenderer() Renderer { return xlsxRenderer{} }

func (xlsxRenderer) Format() string { return "xlsx" }

type xlCell struct {
	val  string
	bold bool
}

func (xlsxRenderer) Render(_ context.Context, vm ViewModel) (Artifact, error) {
	rows := sheetRows(vm)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := []struct {
		name, body string
	}{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"xl/workbook.xml", workbookXML},
		{"xl/_rels/workbook.xml.rels", workbookRelsXML},
		{"xl/styles.xml", stylesXML},
		{"xl/worksheets/sheet1.xml", sheetXML(rows)},
	}
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return Artifact{}, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return Artifact{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return Artifact{}, err
	}
	summary := vm.Summary
	if summary == "" {
		summary = vm.ReportName
	}
	return Artifact{
		Format:      "xlsx",
		ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		Bytes:       buf.Bytes(),
		Summary:     summary,
	}, nil
}

// sheetRows lays the ViewModel out as worksheet rows: a title, the generated-at
// line, then each section (bold title, optional bold header row, data rows, or a
// note), separated by blank rows.
func sheetRows(vm ViewModel) [][]xlCell {
	var rows [][]xlCell
	rows = append(rows, []xlCell{{val: vm.ReportName, bold: true}})
	rows = append(rows, []xlCell{{val: "Generated " + vm.GeneratedAt.UTC().Format("2006-01-02 15:04 MST")}})
	if vm.Summary != "" {
		rows = append(rows, []xlCell{{val: vm.Summary}})
	}
	rows = append(rows, nil) // blank
	for _, s := range vm.Sections {
		rows = append(rows, []xlCell{{val: s.Title, bold: true}})
		if len(s.Header) > 0 {
			hr := make([]xlCell, len(s.Header))
			for i, h := range s.Header {
				hr[i] = xlCell{val: h, bold: true}
			}
			rows = append(rows, hr)
		}
		for _, r := range s.Rows {
			cr := make([]xlCell, len(r))
			for i, v := range r {
				cr[i] = xlCell{val: v}
			}
			rows = append(rows, cr)
		}
		if s.Note != "" {
			// A multi-line note becomes one row per line, single column.
			for _, line := range strings.Split(s.Note, "\n") {
				rows = append(rows, []xlCell{{val: line}})
			}
		}
		rows = append(rows, nil) // blank between sections
	}
	return rows
}

func sheetXML(rows [][]xlCell) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for ri, row := range rows {
		rn := ri + 1
		fmt.Fprintf(&b, `<row r="%d">`, rn)
		for ci, c := range row {
			ref := colName(ci) + fmt.Sprint(rn)
			style := "0"
			if c.bold {
				style = "1"
			}
			fmt.Fprintf(&b, `<c r="%s" s="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`,
				ref, style, xmlEscape(c.val))
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

// colName converts a 0-based column index to an Excel column name (A, B, ... Z, AA).
func colName(i int) string {
	name := ""
	for i >= 0 {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
	}
	return name
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func xmlEscape(s string) string { return xmlEscaper.Replace(s) }

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
	`</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const workbookXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
	`<sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets></workbook>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`</Relationships>`

// stylesXML: cellXfs[0] = normal, cellXfs[1] = bold (fontId 1).
const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
	`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
	`<fills count="1"><fill><patternFill patternType="none"/></fill></fills>` +
	`<borders count="1"><border/></borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="2">` +
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +
	`</cellXfs></styleSheet>`
