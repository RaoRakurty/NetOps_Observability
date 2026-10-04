// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// ledger_hash.go — the decision ledger's tool fingerprints (tracker 337 N-A6).
// The ledger stores what a tool was asked and what it read as SHA-256 hashes
// only; these two functions define the canonical bytes that are hashed, so a
// re-run of the same tool with the same arguments can be compared against the
// ledger without the ledger ever holding the values.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// HashToolArgs is SHA-256 (lowercase hex) of the arguments' canonical JSON —
// encoding/json writes map keys sorted, so equal maps hash equally. A nil map
// hashes as an empty object.
func HashToolArgs(args ToolArgs) string {
	if args == nil {
		args = ToolArgs{}
	}
	b, err := json.Marshal(args)
	if err != nil {
		return "" // a map of strings always encodes; "" is "no proof", never a wrong one
	}
	return sha256Hex(b)
}

// toolResultFingerprint is the hashed view of a result: everything the tool
// returned that the answer could have used — items, the truncation flag, notes
// and signals — in a fixed field order. It mirrors ToolResult field for field
// and is built by CONVERSION, so a field added to ToolResult is a compile error
// here until someone decides whether the ledger hashes it.
type toolResultFingerprint struct {
	Items     []EvidenceItem `json:"items"`
	Truncated bool           `json:"truncated"`
	Notes     []string       `json:"notes"`
	Signals   []string       `json:"signals"`
}

// HashToolResult is SHA-256 (lowercase hex) of the result's canonical JSON.
func HashToolResult(res ToolResult) string {
	fp := toolResultFingerprint(res)
	if fp.Items == nil {
		fp.Items = []EvidenceItem{}
	}
	if fp.Notes == nil {
		fp.Notes = []string{}
	}
	if fp.Signals == nil {
		fp.Signals = []string{}
	}
	b, err := json.Marshal(fp)
	if err != nil {
		return "" // strings, bools and string structs always encode
	}
	return sha256Hex(b)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
