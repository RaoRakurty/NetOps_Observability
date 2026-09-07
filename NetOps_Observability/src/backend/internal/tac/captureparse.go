// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// captureparse.go — reading a customer's own command list out of a file.
//
// The owner's rule (2026-09-06): "Review the commands not needed, instead give
// an option to upload their own list of commands in certain data formats." Five
// formats, because those are what a NOC actually has a runbook in:
//
//	txt   one command per line, `#` comments
//	csv   command[,note], an optional header row
//	json  {"name": "...", "commands": ["…"]}  (or [{"command","note"}])
//	yaml  the same shape, read by this package's own minimal YAML reader
//	docx  every paragraph and every table cell, in document order
//
// STDLIB ONLY, INCLUDING DOCX (CLAUDE.md §6). A .docx is a zip of XML, so it is
// `archive/zip` plus `encoding/xml` and nothing else. We read `word/document.xml`
// and take the text of each `w:p` paragraph — a table cell contains paragraphs,
// so walking paragraphs covers tables without a second traversal and without a
// word-processing model.
//
// ZERO TRUST (§3). An uploaded file is hostile input from the first byte:
//   - the body is bounded BEFORE it is read (the handler's MaxBytesReader);
//   - the zip is bounded again on the DECOMPRESSED side, so a zip bomb cannot
//     turn a 1 MiB upload into gigabytes of XML;
//   - a command longer than MaxCaptureCommandBytes is refused, not truncated —
//     truncating would run a command the customer did not write;
//   - the file's own `name` is clamped and never used as a path;
//   - and NOTHING here decides what may run. Every line still goes through the
//     same TemplateValidator the review step and the collector use.

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CaptureFormat is a supported upload format. Closed enum: an extension outside
// it is refused by name rather than guessed at.
type CaptureFormat string

const (
	FormatTXT  CaptureFormat = "txt"
	FormatCSV  CaptureFormat = "csv"
	FormatJSON CaptureFormat = "json"
	FormatYAML CaptureFormat = "yaml"
	FormatDOCX CaptureFormat = "docx"
)

// CaptureFormats are the formats the upload control names on screen, in the
// order it names them. Exported so the UI and this parser cannot disagree.
var CaptureFormats = []CaptureFormat{FormatTXT, FormatCSV, FormatJSON, FormatYAML, FormatDOCX}

// Upload errors. Each is a sentence an operator can act on; none of them is
// "invalid file".
var (
	// ErrCaptureFormat is an extension this parser does not read.
	ErrCaptureFormat = errors.New("tac: that file type is not one Correlix reads")
	// ErrCaptureEmpty is a file that parsed cleanly and held no command.
	ErrCaptureEmpty = errors.New("tac: that file holds no commands")
	// ErrCaptureTooMany is a file over MaxCaptureCommands.
	ErrCaptureTooMany = fmt.Errorf("tac: a capture may hold at most %d commands", MaxCaptureCommands)
	// ErrCaptureLineTooLong is one command over MaxCaptureCommandBytes.
	ErrCaptureLineTooLong = fmt.Errorf("tac: one command may be at most %d characters", MaxCaptureCommandBytes)
	// ErrCaptureUnreadable is a file whose own structure could not be read.
	ErrCaptureUnreadable = errors.New("tac: that file could not be read")
)

// CaptureFormatOf resolves a filename to a format. The extension is the ONLY
// signal used: sniffing content would mean guessing, and a guess that reads a
// customer's spreadsheet as a command list is worse than a refusal.
func CaptureFormatOf(filename string) (CaptureFormat, bool) {
	name := strings.ToLower(strings.TrimSpace(filename))
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	dot := strings.LastIndex(name, ".")
	if dot < 0 {
		return "", false
	}
	switch name[dot+1:] {
	case "txt", "text", "list", "cmd", "commands":
		return FormatTXT, true
	case "csv":
		return FormatCSV, true
	case "json":
		return FormatJSON, true
	case "yaml", "yml":
		return FormatYAML, true
	case "docx":
		return FormatDOCX, true
	default:
		return "", false
	}
}

// ParsedCapture is what a file yielded, before any policy check. It is NOT a
// capture yet: nothing has been validated, and the caller must run the
// TemplateValidator over it before it may exist.
type ParsedCapture struct {
	Format   CaptureFormat
	Name     string
	Commands []CaptureCommand
}

// ParseCapture reads an uploaded file into commands.
//
// It applies the SHAPE bounds (count, line length) and nothing else: what a
// command may DO is the policy's decision, made once, in the validator.
func ParseCapture(filename string, data []byte) (ParsedCapture, error) {
	format, ok := CaptureFormatOf(filename)
	if !ok {
		return ParsedCapture{}, ErrCaptureFormat
	}
	var (
		out ParsedCapture
		err error
	)
	out.Format = format
	switch format {
	case FormatTXT:
		out.Commands, err = parseCaptureTXT(data)
	case FormatCSV:
		out.Commands, err = parseCaptureCSV(data)
	case FormatJSON:
		out.Name, out.Commands, err = parseCaptureJSON(data)
	case FormatYAML:
		out.Name, out.Commands, err = parseCaptureYAML(data)
	case FormatDOCX:
		out.Commands, err = parseCaptureDOCX(data)
	default:
		return ParsedCapture{}, ErrCaptureFormat
	}
	if err != nil {
		return ParsedCapture{}, err
	}
	if err := boundCaptureCommands(out.Commands); err != nil {
		return ParsedCapture{}, err
	}
	if len(out.Commands) == 0 {
		return ParsedCapture{}, ErrCaptureEmpty
	}
	if out.Name == "" {
		out.Name = captureNameFromFile(filename)
	}
	out.Name = clip(out.Name, MaxCaptureNameBytes)
	return out, nil
}

// boundCaptureCommands applies the two shape bounds. A file over either is
// REFUSED whole: silently keeping the first 500 lines of a 900-line runbook
// would run a set the customer never wrote.
func boundCaptureCommands(cmds []CaptureCommand) error {
	if len(cmds) > MaxCaptureCommands {
		return ErrCaptureTooMany
	}
	for _, c := range cmds {
		if len(c.Command) > MaxCaptureCommandBytes {
			return ErrCaptureLineTooLong
		}
	}
	return nil
}

// captureNameFromFile is the fallback name: the file's own basename without its
// extension, through the same clamp every other name goes through.
func captureNameFromFile(filename string) string {
	name := strings.TrimSpace(filename)
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	if dot := strings.LastIndex(name, "."); dot > 0 {
		name = name[:dot]
	}
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name))
	if name == "" {
		return "Uploaded capture"
	}
	return name
}

// ── txt ─────────────────────────────────────────────────────────────────────

// parseCaptureTXT reads one command per line. A blank line is skipped; a line
// whose first non-space character is `#` is a comment. Line numbers are the
// FILE's, because that is what the operator's editor shows them.
func parseCaptureTXT(data []byte) ([]CaptureCommand, error) {
	out := make([]CaptureCommand, 0, 32)
	for i, raw := range splitCaptureLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, CaptureCommand{Command: line, Line: i + 1})
	}
	return out, nil
}

// splitCaptureLines splits on \n and drops a trailing \r, so a file written on
// Windows reads the same as one written on Linux.
func splitCaptureLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

// ── csv ─────────────────────────────────────────────────────────────────────

// parseCaptureCSV reads `command[,note]`. A header row naming the columns is
// recognised and skipped; `#` comments are honoured the way the txt reader
// honours them, so one exported spreadsheet and one hand-written file behave
// alike.
func parseCaptureCSV(data []byte) ([]CaptureCommand, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // a note is optional; a ragged file is not an error
	r.TrimLeadingSpace = true
	r.Comment = '#'
	out := make([]CaptureCommand, 0, 32)
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
		}
		line, _ := r.FieldPos(0)
		if len(rec) == 0 {
			continue
		}
		cmd := strings.TrimSpace(rec[0])
		if cmd == "" {
			continue
		}
		if len(out) == 0 && isCaptureCSVHeader(cmd) {
			continue
		}
		note := ""
		if len(rec) > 1 {
			note = clip(strings.TrimSpace(rec[1]), maxTemplateTextBytes)
		}
		out = append(out, CaptureCommand{Command: cmd, Note: note, Line: line})
	}
	return out, nil
}

// isCaptureCSVHeader recognises the one header a command list plausibly has.
// It is a closed list rather than a heuristic: dropping a row because it
// "looked like" a header would drop a command.
func isCaptureCSVHeader(first string) bool {
	switch strings.ToLower(strings.TrimSpace(first)) {
	case "command", "commands", "cmd":
		return true
	}
	return false
}

// ── json ────────────────────────────────────────────────────────────────────

// captureJSONWire is the documented json shape. `commands` is deliberately
// json.RawMessage: it accepts a list of strings and a list of objects, which are
// the two things people actually write, and it rejects everything else by name.
type captureJSONWire struct {
	Name     string            `json:"name"`
	Commands []json.RawMessage `json:"commands"`
}

func parseCaptureJSON(data []byte) (string, []CaptureCommand, error) {
	var in captureJSONWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
	}
	out := make([]CaptureCommand, 0, len(in.Commands))
	for i, raw := range in.Commands {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			if c := strings.TrimSpace(s); c != "" {
				out = append(out, CaptureCommand{Command: c, Line: i + 1})
			}
			continue
		}
		var obj struct {
			Command string `json:"command"`
			Note    string `json:"note"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return "", nil, fmt.Errorf("%w: command %d is neither a string nor {\"command\":…}", ErrCaptureUnreadable, i+1)
		}
		if c := strings.TrimSpace(obj.Command); c != "" {
			out = append(out, CaptureCommand{
				Command: c, Note: clip(strings.TrimSpace(obj.Note), maxTemplateTextBytes), Line: i + 1,
			})
		}
	}
	return strings.TrimSpace(in.Name), out, nil
}

// ── yaml ────────────────────────────────────────────────────────────────────

// parseCaptureYAML reads the same shape through this package's own minimal YAML
// reader (yamlmin.go) — the one the catalogue is already loaded with. No new
// dependency, and a customer's file is held to the same subset the product's own
// files are.
func parseCaptureYAML(data []byte) (string, []CaptureCommand, error) {
	root, err := parseYAML(string(data))
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
	}
	if !root.isMap() {
		return "", nil, fmt.Errorf("%w: the file must be a mapping with a `commands:` list", ErrCaptureUnreadable)
	}
	if err := yonly(root, "capture", "name", "commands"); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
	}
	name, err := ystr(root, "name")
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
	}
	// `commands:` may be a list of plain strings OR a list of {command, note}
	// mappings — both are shapes people write, and ylist accepts only the
	// second, so the node is read directly here.
	node := root.m["commands"]
	if node == nil || !node.isList() {
		return "", nil, fmt.Errorf("%w: the file must carry a `commands:` list", ErrCaptureUnreadable)
	}
	items := node.list
	out := make([]CaptureCommand, 0, len(items))
	for i, it := range items {
		switch {
		case it.isScalar():
			if c := strings.TrimSpace(it.str); c != "" {
				out = append(out, CaptureCommand{Command: c, Line: it.line})
			}
		case it.isMap():
			if err := yonly(it, "command", "command", "note"); err != nil {
				return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, err)
			}
			cmd, cerr := ystr(it, "command")
			if cerr != nil {
				return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, cerr)
			}
			note, nerr := ystr(it, "note")
			if nerr != nil {
				return "", nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, nerr)
			}
			if c := strings.TrimSpace(cmd); c != "" {
				out = append(out, CaptureCommand{
					Command: c, Note: clip(strings.TrimSpace(note), maxTemplateTextBytes), Line: it.line,
				})
			}
		default:
			return "", nil, fmt.Errorf("%w: command %d is neither text nor a mapping", ErrCaptureUnreadable, i+1)
		}
	}
	return strings.TrimSpace(name), out, nil
}

// ── docx ────────────────────────────────────────────────────────────────────

// maxDocxXMLBytes bounds the DECOMPRESSED document part. A zip's declared sizes
// are attacker-controlled, so the guard is on what we actually read, not on what
// the header claims: io.LimitReader is the bound, and hitting it is a refusal.
const maxDocxXMLBytes int64 = 8 << 20

// docxDocumentPart is where Word keeps the body. Correlix reads that part and no
// other: headers, footnotes, comments and embedded objects are not a command
// list, and reading them would turn a stray note into something we run.
const docxDocumentPart = "word/document.xml"

// parseCaptureDOCX reads every paragraph of a Word document in document order.
//
// The XML model, and why paragraph-walking is the whole algorithm: a `w:p`
// paragraph holds `w:r` runs which hold `w:t` text; Word splits one visible line
// across several runs whenever formatting changes, so the paragraph's text is
// the concatenation of its `w:t` values. A table cell (`w:tc`) CONTAINS
// paragraphs, so one table row of commands arrives as one paragraph per cell —
// which is exactly one command per row for a single-column table, and one per
// cell for a wider one. There is no second traversal and no table model.
func parseCaptureDOCX(data []byte) ([]CaptureCommand, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: it is not a Word (.docx) file", ErrCaptureUnreadable)
	}
	var part *zip.File
	for _, f := range zr.File {
		if f.Name == docxDocumentPart {
			part = f
			break
		}
	}
	if part == nil {
		return nil, fmt.Errorf("%w: the Word file carries no %s", ErrCaptureUnreadable, docxDocumentPart)
	}
	rc, oerr := part.Open()
	if oerr != nil {
		return nil, fmt.Errorf("%w: %v", ErrCaptureUnreadable, oerr)
	}
	defer rc.Close()
	return docxParagraphCommands(io.LimitReader(rc, maxDocxXMLBytes))
}

// docxParagraphCommands streams the document part and yields one command per
// non-empty paragraph. It is a token walk rather than a struct decode because a
// `w:p` can nest inside a `w:tc` inside another `w:p`, and a nesting depth
// counter is both simpler and stricter than a shape the decoder would have to
// guess at.
func docxParagraphCommands(r io.Reader) ([]CaptureCommand, error) {
	dec := xml.NewDecoder(r)
	out := make([]CaptureCommand, 0, 32)
	var (
		depth int               // how many w:p elements are open
		text  strings.Builder   // the innermost open paragraph's text
		stack []strings.Builder // the outer paragraphs' text, if any
		index int
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: the Word document's XML could not be read", ErrCaptureUnreadable)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "p" {
				stack = append(stack, text)
				text = strings.Builder{}
				depth++
			}
			// A tab inside a run is a column break in a table row written as a
			// single paragraph; it separates words, never joins them.
			if depth > 0 && (t.Name.Local == "tab" || t.Name.Local == "br") {
				text.WriteString(" ")
			}
		case xml.CharData:
			if depth > 0 {
				text.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local != "p" || depth == 0 {
				continue
			}
			line := normaliseDocxLine(text.String())
			index++
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, CaptureCommand{Command: line, Line: index})
			}
			text = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			depth--
		}
	}
	return out, nil
}

// normaliseDocxLine collapses the whitespace Word scatters through a paragraph
// (non-breaking spaces, run boundaries, soft breaks) into single spaces, so
// `show   ip  bgp` from a formatted document is the same command as the one
// somebody typed into a text file.
func normaliseDocxLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, " ", " ")), " ")
}
