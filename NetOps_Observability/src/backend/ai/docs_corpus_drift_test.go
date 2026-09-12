// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs_corpus_drift_test.go — the embedded AI corpus (docs_corpus/) is a mirror
// of docs-portal/docs, maintained ONLY by scripts/sync-docs-corpus.sh. This test
// fails CI whenever they diverge, so a docs edit can never silently leave the
// assistant answering from stale pages (and a corpus edit can never fork from
// the portal). Skipped when the portal isn't checked out (isolated backend
// builds still compile and test against the embedded copy).

const syncHint = "run scripts/sync-docs-corpus.sh and commit the result"

func TestDocsCorpusMatchesPortal(t *testing.T) {
	portal := filepath.Join("..", "..", "..", "docs-portal", "docs")
	if _, err := os.Stat(portal); err != nil {
		t.Skipf("docs-portal not present (%v) — drift check runs in the full repo / CI", err)
	}

	// Every portal page must byte-match its embedded twin.
	portalPages := map[string]bool{}
	err := filepath.WalkDir(portal, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		rel, err := filepath.Rel(portal, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		portalPages[rel] = true
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := docsCorpusFS.ReadFile("docs_corpus/" + rel)
		if err != nil {
			t.Errorf("portal page %s missing from the embedded corpus — %s", rel, syncHint)
			return nil
		}
		if !bytes.Equal(want, got) {
			t.Errorf("embedded corpus is STALE for %s — %s", rel, syncHint)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs-portal: %v", err)
	}
	if len(portalPages) == 0 {
		t.Fatal("docs-portal/docs contains no markdown — unexpected")
	}

	// No orphans: every embedded page must still exist in the portal.
	err = fs.WalkDir(docsCorpusFS, "docs_corpus", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		rel := strings.TrimPrefix(path, "docs_corpus/")
		if !portalPages[rel] {
			t.Errorf("embedded corpus has orphan page %s (deleted from the portal) — %s", rel, syncHint)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking embedded corpus: %v", err)
	}
}
