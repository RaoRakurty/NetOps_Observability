// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// store_unreadable.go — the ONE place this package decides what an unreadable
// register file means, shared by the three file-backed registers here
// (promotions, report revisions, action items).
//
// The defect it closes: each register called platformdb.Load and treated ANY
// error as "nothing stored yet". A file that existed but could not be read —
// a permissions change, an I/O error, bytes that are not the expected JSON —
// started the register EMPTY with nothing logged, and the next save then
// renamed a temp file over the original. Every tenant's promoted cases, every
// immutable revision record, every remediation item: gone, silently. The
// directory stays writable in that state, so the atomic rename succeeds.
//
// These three registers hold DURABLE OPERATOR EVIDENCE — an audited manual
// promotion, an integrity-stamped generation record, an accountable action
// item. None of it is derivable from anything else, so the answer here is to
// REFUSE writes rather than let one succeed over contents we never read. The
// repair is an operator act: fix the file's permissions, or remove it
// deliberately, and the api picks it up on the next start.

import (
	"errors"
	"fmt"
	"io/fs"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// ErrStoreUnreadable is returned by every write of a register whose file exists
// but could not be read or parsed at start-up. It is a REFUSAL, not a failure of
// the write itself: the file's real contents were never established, so a save
// would not update the file, it would REPLACE it with whatever this process
// happens to hold, which after such a load is nothing at all.
var ErrStoreUnreadable = errors.New("rca: the stored register could not be read at start-up, so writes are refused until it is repaired or removed")

// loadRegister reads one register's persisted bytes. THREE outcomes, never two:
//   - (nil, nil)   nothing stored — no path, an absent file, or an empty one.
//     This is the normal first-boot state and starts an empty register.
//   - (nil, err)   the file EXISTS and could not be read. Logged here, and the
//     caller records it so every write is refused.
//   - (bytes, nil) loaded.
func loadRegister(path, what string) ([]byte, error) {
	if path == "" {
		return nil, nil // memory-only (tests)
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent. Logging this would train operators to ignore the
		// line, which is how the real failure below gets missed.
		return nil, nil
	case err != nil:
		applog.Error("rca", "stored "+what+" could not be read; the register starts EMPTY and every write is refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return nil, fmt.Errorf("rca: the %s file could not be read: %w", what, err)
	case len(b) == 0:
		return nil, nil // present but empty: nothing stored, nothing broken
	}
	return b, nil
}

// unparsedRegister records a register whose bytes we read but could not decode.
// The contents are just as unknown as an I/O failure's, so it is the same
// refusal — a register that "starts empty" here would be overwriting a file
// full of rows somebody wrote.
func unparsedRegister(what string, err error) error {
	applog.Error("rca", "stored "+what+" could not be parsed; the register starts EMPTY and every write is refused until the file is repaired or removed",
		map[string]any{"err": err.Error()})
	return fmt.Errorf("rca: the %s file could not be parsed: %w", what, err)
}

// refuseUnreadable is the guard every saveLocked opens with. nil when the load
// was clean; otherwise the sentinel wrapped with the cause, so a caller can test
// errors.Is(err, ErrStoreUnreadable) and still read why.
func refuseUnreadable(unreadable error) error {
	if unreadable == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStoreUnreadable, unreadable)
}
