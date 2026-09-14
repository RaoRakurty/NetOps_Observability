// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// redactstream_trailing_test.go — the OTHER half of the stream's newline
// fidelity (review 3.5-15).
//
// 3.5-15 was filed as "an over-long line reaches the bundle split by newlines
// the device never printed", and that half is fixed: the pieces of a >64 KiB
// line are written back to back. The finding's second sentence — "the file's
// header claims byte-identity with the buffered pass" — was still not true, in
// the opposite direction and on output that is not pathological at all.
//
// EVERY device output ends with a newline. The buffered pass keeps it:
// strings.Split("a\n", "\n") is ["a", ""], so the join puts the separator back.
// The stream dropped it — Close returns early on an empty buffer — so every
// streamed spill file in a TAC bundle ended one byte short of the same output
// rendered in memory, and `cc.Bytes` (red.Written()) under-counted by one.
//
// The equivalence test could not catch it: its corpus is joined with "\n"
// BETWEEN the lines and therefore never ends with one — the same shape of blind
// spot as the io.Copy-from-a-strings.Reader that hid the first half.

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// streamed runs s through a RedactingWriter in fixed-size chunks, the way a
// network read delivers it.
func streamed(t *testing.T, s string, chunk int) (string, int64) {
	t.Helper()
	var got bytes.Buffer
	w := NewRedactingWriter(&got)
	for i := 0; i < len(s); i += chunk {
		end := i + chunk
		if end > len(s) {
			end = len(s)
		}
		if _, err := io.WriteString(w, s[i:end]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return got.String(), w.Written()
}

// The case a device actually produces: output that ends with a newline.
func TestAStreamedOutputKeepsItsTrailingNewline(t *testing.T) {
	const in = "interface GigabitEthernet0/0/0\n description transit to isp-a\n"
	for _, chunk := range []int{1, 7, 64, 100000} {
		got, written := streamed(t, in, chunk)
		if want := RedactOutput(in); got != want {
			t.Errorf("chunk %d: the stream dropped the device's final newline\n got: %q\nwant: %q",
				chunk, got, want)
		}
		if written != int64(len(got)) {
			t.Errorf("chunk %d: Written() says %d, %d bytes were written", chunk, written, len(got))
		}
	}
}

// The equivalence property, re-run over the package corpus WITH the trailing
// newline the original omitted.
func TestRedactingWriterMatchesTheBufferedPassOnOutputThatEndsWithANewline(t *testing.T) {
	text := strings.Join(redactCorpus, "\n") + "\n"
	want := RedactOutput(text)
	for _, chunk := range []int{1, 2, 3, 7, 13, 64, 512, 100000} {
		got, _ := streamed(t, text, chunk)
		if got != want {
			t.Fatalf("chunk %d: the streamed redaction differs from the buffered one at the end\n got: %q\nwant: %q",
				chunk, got[max(0, len(got)-60):], want[max(0, len(want)-60):])
		}
	}
}

// ...and every other end-of-stream shape agrees with the buffered pass too,
// including the ones where the buffered pass does NOT end with a newline: a
// stream that stops mid-line (the over-long flush case) and an unterminated PEM
// block, whose trailing line is dropped with the rest of the key body.
func TestTheStreamAndTheBufferedPassAgreeOnEveryEndOfStream(t *testing.T) {
	long := strings.Repeat("a", maxRedactLineBytes+7)
	for name, in := range map[string]string{
		"nothing at all":                   "",
		"one bare newline":                 "\n",
		"a line with no newline":           "hostname core1",
		"a line with a newline":            "hostname core1\n",
		"two lines, no final break":        "hostname core1\nusername admin privilege 15 password 7 070C285F4D06",
		"a blank final line":               "hostname core1\n\n",
		"an unterminated key block":        "hostname core1\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n",
		"a terminated key block":           "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n",
		"an over-long final line":          "first\n" + long,
		"an over-long line then a newline": "first\n" + long + "\n",
	} {
		for _, chunk := range []int{1, 13, 32 << 10} {
			got, written := streamed(t, in, chunk)
			if want := RedactOutput(in); got != want {
				t.Errorf("%s (chunk %d):\n got: %q\nwant: %q", name, chunk, tailOf(got), tailOf(want))
			}
			if written != int64(len(got)) {
				t.Errorf("%s (chunk %d): Written() says %d, %d bytes were written",
					name, chunk, written, len(got))
			}
		}
	}
}

func tailOf(s string) string {
	if len(s) <= 80 {
		return s
	}
	return "…" + s[len(s)-80:]
}
