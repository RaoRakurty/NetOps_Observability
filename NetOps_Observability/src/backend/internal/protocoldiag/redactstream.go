// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// redactstream.go — the STREAMING half of the redactor.
//
// RedactOutput (redact.go) takes a whole string. That is the right shape for a
// `show ip ospf neighbor`, whose output is kilobytes, and the wrong shape for
// the one command every vendor's TAC asks for first: `show tech-support` is tens
// of megabytes and minutes long, and holding it in memory to redact it — twice,
// once raw and once redacted — is exactly the unbounded allocation CLAUDE.md §9
// exists to refuse.
//
// So the same rules run over a STREAM. The redactor is already a line scanner
// with one bit of state (inside a PEM private-key block or not), which is what
// makes this possible at all: a RedactingWriter buffers the current partial
// line, applies the identical per-line rules the buffered path applies, and
// carries the PEM state across Write boundaries. The output of
// `io.Copy(NewRedactingWriter(w), r)` is byte-identical to
// `RedactOutput(readAll(r))` — a test asserts that on the package's own corpus,
// because two redactors that could disagree would be worse than one.
//
// The identity holds at the END of the stream as well as inside it: output that
// ends with a newline keeps it, and output that stops mid-line does not gain one
// (see Close).
//
// FAIL CLOSED. A line longer than maxRedactLineBytes cannot be held forever, so
// it is flushed in pieces — but a piece is emitted only AFTER the rules have run
// over it, and a PEM body is never emitted at all. An unterminated PEM block at
// Close redacts through to the end, exactly as redactText does. Those pieces are
// written BACK TO BACK: they are one device line, and the only reason they
// arrived separately is this writer's own memory bound, so a separator between
// them would be a break the device never printed (review 3.5-15). The one
// difference that remains on such a line is that the per-line rules see each
// piece separately, which is why the bound is far larger than any line a device
// actually prints.

import (
	"bytes"
	"errors"
	"io"
)

// maxRedactLineBytes bounds the partial line a RedactingWriter holds. Device
// output is line-oriented; a "line" longer than this is a device streaming
// without newlines, and the writer degrades to redacting fixed-size chunks
// rather than growing without bound.
//
// It is deliberately larger than any real CLI line (the longest thing a router
// prints on one line is a route-target list or a base64 certificate blob) so the
// degradation never happens on real output.
const maxRedactLineBytes = 64 << 10

// ErrRedactStreamClosed is returned by Write after Close.
var ErrRedactStreamClosed = errors.New("protocoldiag: write to a closed redacting writer")

// RedactingWriter applies the redaction pass to a stream, line by line, and
// writes the redacted bytes on to the underlying writer.
//
// It is NOT safe for concurrent use: one collection writes one command's output
// through one writer, in order, which is the only way output is produced.
type RedactingWriter struct {
	w   io.Writer
	red *redactor

	line       bytes.Buffer
	inKeyBlock bool
	// pendingSep reports that the text written so far ENDS A LINE, so the next
	// write needs the separator before it. It is false before the first line
	// (nothing to separate) and, crucially, false after a PARTIAL flush of an
	// over-long line: those pieces are one logical line and must be written
	// back to back. A plain "have we written anything" flag put a newline
	// between every 64 KiB piece, so a device line longer than the bound
	// reached the bundle split at an arbitrary offset the device never printed
	// (review 3.5-15). Same join semantics strings.Join gives redactText.
	pendingSep bool
	closed     bool
	// n counts the REDACTED bytes actually written, which is what the caller
	// records as the command's size.
	n int64
}

// NewRedactingWriter builds a streaming redactor over w. Close MUST be called:
// it flushes the final partial line and closes an unterminated PEM block.
func NewRedactingWriter(w io.Writer) *RedactingWriter {
	return &RedactingWriter{w: w, red: newRedactor()}
}

// Written reports how many REDACTED bytes have reached the underlying writer.
func (rw *RedactingWriter) Written() int64 { return rw.n }

// Write implements io.Writer.
func (rw *RedactingWriter) Write(p []byte) (int, error) {
	if rw.closed {
		return 0, ErrRedactStreamClosed
	}
	consumed := 0
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			rw.line.Write(p)
			consumed += len(p)
			// A pathologically long line is flushed in pieces rather than held.
			// The rules have run over the piece before it is emitted, so a
			// secret cannot escape by being on a very long line — only a secret
			// SPLIT ACROSS two pieces could, which is why the bound is far
			// larger than any line a device actually prints.
			if rw.line.Len() >= maxRedactLineBytes {
				if err := rw.emit(rw.line.String(), false); err != nil {
					return consumed, err
				}
				rw.line.Reset()
			}
			return consumed, nil
		}
		rw.line.Write(p[:i])
		if err := rw.emit(rw.line.String(), true); err != nil {
			return consumed, err
		}
		rw.line.Reset()
		p = p[i+1:]
		consumed += i + 1
	}
	return consumed, nil
}

// Close flushes the trailing partial line and releases the writer.
//
// A STREAM THAT ENDED EXACTLY AT A NEWLINE still has one line to emit, and it is
// the empty one after that newline. The buffered pass has it too —
// strings.Split("a\n", "\n") is ["a", ""], so the join puts the separator back —
// and device output essentially always ends this way, so dropping it made every
// streamed spill file one byte shorter than the same output rendered in memory,
// contradicting this file's byte-identity claim (review 3.5-15, the half the
// first fix did not cover). It goes through emit like any other line, which is
// what keeps the PEM cases right: inside an unterminated key block that final
// line is dropped with the rest of the body, exactly as redactText drops it.
//
// pendingSep is the discriminator, and it is precise: it is true only after a
// COMPLETE line, false before the first one and false after a partial flush of
// an over-long line (whose logical line never ended, so the buffered pass has no
// empty element for it either).
func (rw *RedactingWriter) Close() error {
	if rw.closed {
		return nil
	}
	rw.closed = true
	if rw.line.Len() == 0 {
		if !rw.pendingSep {
			return nil
		}
		return rw.emit("", true)
	}
	err := rw.emit(rw.line.String(), true)
	rw.line.Reset()
	return err
}

// emit applies redactText's per-line logic to one line and writes the result.
// complete says the line ended at a newline (or at EOF); a partial flush neither
// enters nor leaves the PEM state machine, because a marker split across two
// flushes is not a marker either way.
//
// It mirrors redactText exactly, including the three outcomes: a body line
// inside a key block is DROPPED, a BEGIN marker emits the marker line and then
// the mark that stands for the whole body, and everything else is the per-line
// rules.
func (rw *RedactingWriter) emit(line string, complete bool) error {
	if rw.inKeyBlock {
		if complete && rw.red.pemEnd.MatchString(line) {
			rw.inKeyBlock = false
			return rw.writeLine(line, true) // keep the END marker
		}
		return nil // body line: dropped; the mark was emitted at BEGIN
	}
	if complete && rw.red.pemBegin.MatchString(line) && !rw.red.pemOneLine.MatchString(line) {
		rw.inKeyBlock = true
		if err := rw.writeLine(line, true); err != nil {
			return err
		}
		return rw.writeLine(redactionMark, true)
	}
	return rw.writeLine(rw.red.redactLine(line), complete)
}

// writeLine writes one redacted piece with the separator semantics
// strings.Join("\n") gives the buffered path.
//
// endsLine says this piece completes a logical line. A PARTIAL flush does not,
// and the next piece is therefore written straight after it: the two are one
// device line, and the only reason they arrived separately is this writer's own
// memory bound.
func (rw *RedactingWriter) writeLine(s string, endsLine bool) error {
	if rw.pendingSep {
		if err := rw.raw([]byte{'\n'}); err != nil {
			return err
		}
	}
	rw.pendingSep = endsLine
	return rw.raw([]byte(s))
}

func (rw *RedactingWriter) raw(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	written, err := rw.w.Write(b)
	rw.n += int64(written)
	if err != nil {
		return err
	}
	if written != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

var _ io.WriteCloser = (*RedactingWriter)(nil)
