// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package evalsplit is the held-out split of Iris's eval corpora (tracker 337
// N-H3, commercial review item 13).
//
// An eval score only means something on cases the system was not tuned on. The
// model fallback's few-shot library is built from the same corpus that scores
// it, so a high score could simply be memory. This package decides, without
// any human choice, which cases stay out of every tuning source:
//
//	source "field"      → always held out. A case labelled by an operator is the
//	                      only evidence the system was not authored against.
//	source "lab"        → always DEV. A regression case written from a failure
//	                      seen in the owner's own lab and deliberately fixed
//	                      against (owner decision D7, 2026-11-09): it was tuned
//	                      on by construction, so it can never measure
//	                      generalisation, and it must never be held out.
//	source "synthetic"  → held out when SHA-256 of
//	                      "correlix.evalsplit.v1\x00<corpus>\x00<group>", read
//	                      as a big-endian uint64 from its first 8 bytes, modulo
//	                      100, is below HeldOutPercent.
//
// The hash depends only on the corpus name and the case's group, so adding,
// removing or reordering other cases never moves a case. There is deliberately
// no per-case override: an override would let a failing case be moved into the
// dev set. The group is the case id, except that cases which must stay together
// (the turns of one conversation) share one.
//
// Stdlib only; test code in several packages depends on it.
package evalsplit

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Source says where a case came from.
type Source string

// Case sources (closed).
const (
	SourceSynthetic Source = "synthetic"
	SourceField     Source = "field"
	SourceLab       Source = "lab"
)

// Split is the partition a case belongs to.
type Split string

// Splits (closed).
const (
	Dev     Split = "dev"
	HeldOut Split = "heldout"
)

// HeldOutPercent is the share of synthetic cases held out. Changing it moves
// cases between the splits, which contaminates the held-out set: a case that was
// dev has been tuned on. TestAssignVectorsArePinned fails on a change.
const HeldOutPercent = 20

// minTextWords is the shortest text FindLeaksInText looks for. A shorter phrase
// ("show bgp peers") can legitimately occur in a free-form source as a fragment.
const minTextWords = 4

// ParseSource reads a case's source field. Absent means synthetic, because
// every case authored so far is; anything unknown is refused so a misspelt
// "feild" cannot quietly put a field case in the dev set.
func ParseSource(s string) (Source, error) {
	switch Source(s) {
	case "", SourceSynthetic:
		return SourceSynthetic, nil
	case SourceField:
		return SourceField, nil
	case SourceLab:
		return SourceLab, nil
	}
	return "", fmt.Errorf("evalsplit: unknown source %q (want %q, %q or %q)", s, SourceSynthetic, SourceField, SourceLab)
}

// ValidSplit reports whether s is a known split. Used by report writers.
func ValidSplit(s string) bool {
	return Split(s) == Dev || Split(s) == HeldOut
}

// Assign returns the split of a case. It is a pure function of its arguments.
// An unrecognised source is held out: the safe direction is that a case of
// unknown origin never reaches a tuning source.
func Assign(corpus, group string, src Source) Split {
	if src == SourceLab {
		return Dev // fixed against by construction: never a held-out measure
	}
	if src != SourceSynthetic {
		return HeldOut
	}
	sum := sha256.Sum256([]byte("correlix.evalsplit.v1\x00" + corpus + "\x00" + group))
	if binary.BigEndian.Uint64(sum[:8])%100 < HeldOutPercent {
		return HeldOut
	}
	return Dev
}

// Case is one held-out case as the leak checks see it.
type Case struct {
	// ID is the case id. Texts are its question and paraphrases.
	ID    string
	Texts []string
}

// Tuning is one entry of a source the system is tuned from, such as a few-shot
// example.
type Tuning struct {
	// Where names the source, for the failure message.
	Where string
	// ID is the entry's own case id, when it has one.
	ID string
	// Text is the entry's phrasing.
	Text string
}

// Leak is one held-out case found in a tuning source.
type Leak struct {
	CaseID string
	Where  string
	Reason string
}

func (l Leak) String() string {
	return fmt.Sprintf("held-out case %s leaked into %s: %s", l.CaseID, l.Where, l.Reason)
}

// Normalize folds text for comparison: lower case, every run of anything but a
// letter or digit becomes one space. Rewording is not detected, but punctuation
// and case changes do not hide a copy.
func Normalize(s string) string {
	var b strings.Builder
	pending := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if pending && b.Len() > 0 {
				b.WriteByte(' ')
			}
			pending = false
			b.WriteRune(r)
			continue
		}
		pending = true
	}
	return b.String()
}

// FindLeaks reports every held-out case present in the tuning entries, by id or
// by the same normalized text. Short texts count: an entry that IS a held-out
// question is a leak however short it is.
func FindLeaks(heldOut []Case, tuning []Tuning) []Leak {
	byID := make(map[string]bool, len(heldOut))
	byText := map[string]string{}
	for _, c := range heldOut {
		byID[c.ID] = true
		for _, t := range c.Texts {
			if n := Normalize(t); n != "" {
				byText[n] = c.ID
			}
		}
	}
	var out []Leak
	for _, e := range tuning {
		if e.ID != "" && byID[e.ID] {
			out = append(out, Leak{CaseID: e.ID, Where: e.Where, Reason: "same case id"})
		}
		if id, ok := byText[Normalize(e.Text)]; ok {
			out = append(out, Leak{CaseID: id, Where: e.Where, Reason: fmt.Sprintf("same text as %q", e.Text)})
		}
	}
	sortLeaks(out)
	return out
}

// FindLeaksInText reports held-out cases named inside a free-form source (a
// prompt, a catalog file, code): the case id as a whole token, or one of its
// texts of at least minTextWords words as a whole-word run.
func FindLeaksInText(heldOut []Case, where, text string) []Leak {
	norm := " " + Normalize(text) + " "
	var out []Leak
	for _, c := range heldOut {
		if n := Normalize(c.ID); n != "" && strings.Contains(norm, " "+n+" ") {
			out = append(out, Leak{CaseID: c.ID, Where: where, Reason: "names the case id"})
		}
		for _, t := range c.Texts {
			n := Normalize(t)
			if len(strings.Fields(n)) >= minTextWords && strings.Contains(norm, " "+n+" ") {
				out = append(out, Leak{CaseID: c.ID, Where: where, Reason: fmt.Sprintf("contains %q", t)})
			}
		}
	}
	sortLeaks(out)
	return out
}

// Recorded separates leaks into those not recorded yet and the recorded entries
// that no longer occur. known is keyed "<case id>|<where>". It exists for
// contamination that predates the split and is written down rather than hidden:
// a new leak fails, and so does a stale entry, so the record can only shrink.
func Recorded(leaks []Leak, known map[string]string) (unrecorded []Leak, stale []string) {
	seen := map[string]bool{}
	for _, l := range leaks {
		k := l.CaseID + "|" + l.Where
		seen[k] = true
		if _, ok := known[k]; !ok {
			unrecorded = append(unrecorded, l)
		}
	}
	for k := range known {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	return unrecorded, stale
}

func sortLeaks(ls []Leak) {
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].CaseID != ls[j].CaseID {
			return ls[i].CaseID < ls[j].CaseID
		}
		if ls[i].Where != ls[j].Where {
			return ls[i].Where < ls[j].Where
		}
		return ls[i].Reason < ls[j].Reason
	})
}
