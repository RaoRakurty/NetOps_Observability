// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package storagemeter

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// walk.go — the ONE store this process measures with a syscall instead of by
// asking a server: its own data directory.
//
// It is a `du`-equivalent, with three deliberate differences from `du` stated
// here so nobody has to infer them from a number:
//
//   - APPARENT size (os.Lstat's Size), not allocated blocks. A sparse file
//     counts as its logical length. The reading's detail says so.
//   - Symlinks are NOT followed and count as the link itself, so a link into
//     another store cannot be double-counted here and there.
//   - An unreadable subtree does not abort the walk and does not silently
//     shrink the total either: it is skipped and the error is returned, so the
//     caller renders "not measured" rather than a number that is quietly low.

// errTooManyEntries stops a walk that has become a denial of service against
// this process. Surfaced as a "not measured" reason, never as a partial total.
var errTooManyEntries = errors.New("the data directory holds more entries than this probe will walk, so no total was measured")

// maxWalkEntries bounds one walk (§9: bounded everything). The api's data root
// holds a device shard directory that grows with the estate; a walk that could
// run unbounded is a walk that can be made to.
const maxWalkEntries = 2_000_000

// WalkDir measures a directory tree and returns the total plus the per-CHILD
// breakdown (one Component per immediate child of root). Bound to Deps.Dir by
// the integrator.
func WalkDir(ctx context.Context, root string) (int64, []Component, error) {
	root = strings.TrimRight(filepath.Clean(root), string(os.PathSeparator))
	if root == "" {
		root = string(os.PathSeparator)
	}
	byChild := map[string]int64{}
	var total int64
	var seen int
	var walkErr error
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			// Record the first refusal and keep going: a partial total is not
			// reported as a measurement, but the walk should not stop on one
			// unreadable directory when the caller wants the reason.
			if walkErr == nil {
				walkErr = err
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		seen++
		if seen > maxWalkEntries {
			return errTooManyEntries
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			if walkErr == nil {
				walkErr = ierr
			}
			return nil
		}
		size := info.Size()
		total += size
		byChild[childOf(root, path)] += size
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if walkErr != nil {
		return 0, nil, walkErr
	}
	comps := make([]Component, 0, len(byChild))
	for name, b := range byChild {
		comps = append(comps, Component{Name: name, BytesOnDisk: b})
	}
	return total, comps, nil
}

// childOf names the immediate child of root that `path` lives under, so the
// breakdown is one line per top-level directory rather than one per file.
func childOf(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	if i := strings.IndexRune(rel, os.PathSeparator); i > 0 {
		return rel[:i] + "/"
	}
	return rel
}
