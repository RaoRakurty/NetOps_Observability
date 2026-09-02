package configstore

import (
	"fmt"
	"strings"
)

// diff.go — a BOUNDED unified diff between two configuration versions.
//
// Every bound here exists because both inputs are attacker-influenced in the
// only sense that matters: they are whatever a device sent us. A 200k-line
// config diffed against another 200k-line config with a naive O(n·m) algorithm
// is a multi-gigabyte allocation inside an HTTP handler (§9).
//
//	MaxDiffLines    caps EACH SIDE's line count; beyond it the inputs are
//	                truncated and the result is marked truncated.
//	maxEditDistance caps Myers' D. Two configs that differ by more edits than
//	                this are not usefully "diffed" for a human anyway, so the
//	                algorithm degrades HONESTLY to a whole-block replace and the
//	                result is marked truncated — never a wrong diff, and never an
//	                unbounded one.
//	MaxDiffOutput   caps the rendered hunk lines.
const (
	// MaxDiffLines bounds each side of a diff.
	MaxDiffLines = 20000
	// MaxDiffOutput bounds the rendered unified-diff line count.
	MaxDiffOutput = 4000
	// maxEditDistance bounds Myers' D (trace memory ≈ D²/2 ints).
	maxEditDistance = 512
	// diffContext is the unified-diff context radius.
	diffContext = 3
)

// DiffResult is one comparison. Added/Removed are counted on the UNREDACTED
// normalized text (so a rotated password is a real change), while Unified is
// rendered through the redaction rules (so no secret leaves the module).
type DiffResult struct {
	Added     int
	Removed   int
	Unified   string
	Truncated bool
}

// opKind is one edit-script entry kind.
type opKind int

const (
	opEqual opKind = iota
	opDel
	opAdd
)

type diffOp struct {
	kind opKind
	line string
}

// Diff compares two NORMALIZED configurations and renders a bounded, redacted
// unified diff. `v` selects the redaction dialect.
func Diff(v Vendor, from, to string) DiffResult {
	a, truncA := splitBounded(from)
	b, truncB := splitBounded(to)
	ops, truncD := myers(a, b)
	res := DiffResult{Truncated: truncA || truncB || truncD}
	for _, op := range ops {
		switch op.kind {
		case opAdd:
			res.Added++
		case opDel:
			res.Removed++
		case opEqual:
		}
	}
	res.Unified, truncD = renderUnified(v, ops)
	res.Truncated = res.Truncated || truncD
	return res
}

// splitBounded splits a config into at most MaxDiffLines lines.
func splitBounded(s string) ([]string, bool) {
	if s == "" {
		return nil, false
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) > MaxDiffLines {
		return lines[:MaxDiffLines], true
	}
	return lines, false
}

// myers computes an edit script with a bounded D. On exceeding the bound it
// returns the honest degradation: delete everything, then add everything, with
// truncated=true — a caller is told the diff is a block replace rather than
// being handed a plausible-looking wrong one.
func myers(a, b []string) ([]diffOp, bool) {
	// Trim the common prefix/suffix first: in the common case (a handful of
	// changed lines in a 3000-line config) this reduces D to near zero.
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	sufA, sufB := len(a), len(b)
	for sufA > pre && sufB > pre && a[sufA-1] == b[sufB-1] {
		sufA--
		sufB--
	}
	midA, midB := a[pre:sufA], b[pre:sufB]

	ops := make([]diffOp, 0, len(a)+len(b))
	for i := 0; i < pre; i++ {
		ops = append(ops, diffOp{opEqual, a[i]})
	}
	mid, trunc := myersCore(midA, midB)
	ops = append(ops, mid...)
	for i := sufA; i < len(a); i++ {
		ops = append(ops, diffOp{opEqual, a[i]})
	}
	return ops, trunc
}

// myersCore is the O((N+M)·D) greedy algorithm with a D cap and a stored trace
// for backtracking.
func myersCore(a, b []string) ([]diffOp, bool) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, false
	}
	if n == 0 || m == 0 {
		return blockReplace(a, b), false
	}
	maxD := n + m
	if maxD > maxEditDistance {
		maxD = maxEditDistance
	}
	offset := maxD
	v := make([]int, 2*maxD+2)
	trace := make([][]int, 0, maxD+1)
	for d := 0; d <= maxD; d++ {
		snapshot := make([]int, len(v))
		copy(snapshot, v)
		trace = append(trace, snapshot)
		for k := -d; k <= d; k += 2 {
			idx := k + offset
			if idx < 0 || idx+1 >= len(v) {
				continue
			}
			var x int
			if k == -d || (k != d && v[idx-1] < v[idx+1]) {
				x = v[idx+1]
			} else {
				x = v[idx-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[idx] = x
			if x >= n && y >= m {
				return backtrack(a, b, trace, d, offset), false
			}
		}
	}
	// D bound exceeded — degrade honestly.
	return blockReplace(a, b), true
}

// backtrack walks the stored traces back to an edit script.
func backtrack(a, b []string, trace [][]int, d, offset int) []diffOp {
	ops := []diffOp{}
	x, y := len(a), len(b)
	for dd := d; dd > 0; dd-- {
		v := trace[dd]
		k := x - y
		idx := k + offset
		var prevK int
		if k == -dd || (k != dd && idx-1 >= 0 && idx+1 < len(v) && v[idx-1] < v[idx+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		pIdx := prevK + offset
		if pIdx < 0 || pIdx >= len(v) {
			break
		}
		prevX := v[pIdx]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			ops = append(ops, diffOp{opEqual, a[x]})
		}
		if x > prevX {
			x--
			ops = append(ops, diffOp{opDel, a[x]})
		} else if y > prevY {
			y--
			ops = append(ops, diffOp{opAdd, b[y]})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		ops = append(ops, diffOp{opEqual, a[x]})
	}
	for x > 0 {
		x--
		ops = append(ops, diffOp{opDel, a[x]})
	}
	for y > 0 {
		y--
		ops = append(ops, diffOp{opAdd, b[y]})
	}
	// backtrack produced the script in reverse.
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops
}

// blockReplace is the honest degradation: every old line removed, every new line
// added.
func blockReplace(a, b []string) []diffOp {
	ops := make([]diffOp, 0, len(a)+len(b))
	for _, ln := range a {
		ops = append(ops, diffOp{opDel, ln})
	}
	for _, ln := range b {
		ops = append(ops, diffOp{opAdd, ln})
	}
	return ops
}

// renderUnified renders the edit script as a context-bounded unified diff with
// every emitted line pushed through the redaction rules. Returns truncated=true
// when MaxDiffOutput cut the rendering short.
func renderUnified(v Vendor, ops []diffOp) (string, bool) {
	// Mark which equal lines are within `diffContext` of a change.
	keep := make([]bool, len(ops))
	for i, op := range ops {
		if op.kind == opEqual {
			continue
		}
		lo, hi := i-diffContext, i+diffContext
		if lo < 0 {
			lo = 0
		}
		if hi >= len(ops) {
			hi = len(ops) - 1
		}
		for j := lo; j <= hi; j++ {
			keep[j] = true
		}
	}
	var b strings.Builder
	emitted, truncated, gap := 0, false, false
	for i, op := range ops {
		if !keep[i] {
			gap = true
			continue
		}
		if emitted >= MaxDiffOutput {
			truncated = true
			break
		}
		if gap {
			b.WriteString("@@\n")
			emitted++
			gap = false
		}
		var prefix string
		switch op.kind {
		case opAdd:
			prefix = "+"
		case opDel:
			prefix = "-"
		case opEqual:
			prefix = " "
		}
		b.WriteString(prefix)
		b.WriteString(RedactLine(v, op.line))
		b.WriteString("\n")
		emitted++
	}
	if truncated {
		b.WriteString(fmt.Sprintf("@@ diff truncated at %d lines @@\n", MaxDiffOutput))
	}
	return b.String(), truncated
}
