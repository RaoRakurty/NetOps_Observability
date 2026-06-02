package main

import (
	"context"
	"testing"

	"netops/backend/reports"
)

func TestKVArtifactStore(t *testing.T) {
	withBackend(t, newMemKV()) // no file I/O; same contract as the pg backend
	ctx := context.Background()
	st := newKVArtifactStore()

	art := reports.Artifact{
		Format:      "html",
		ContentType: "text/html; charset=utf-8",
		Bytes:       []byte("<html><body>Weekly report</body></html>"),
		Summary:     "Weekly report",
	}
	ref, err := st.Save(ctx, "exec-1", art)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if ref.Key != "exec-1" || ref.Format != "html" || ref.SizeBytes != len(art.Bytes) {
		t.Fatalf("ref not populated: %+v", ref)
	}
	if ref.SHA256 == "" {
		t.Fatalf("missing content hash")
	}

	got, err := st.Load(ctx, ref)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got.Bytes) != string(art.Bytes) {
		t.Fatalf("round-trip mismatch: %q", string(got.Bytes))
	}
	if got.ContentType != art.ContentType || got.Format != "html" {
		t.Fatalf("metadata not restored from ref: %+v", got)
	}

	// Delete tombstones the artifact (best-effort on the kv backend).
	if err := st.Delete(ctx, ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if after, _ := st.Load(ctx, ref); len(after.Bytes) != 0 {
		t.Fatalf("expected empty artifact after delete, got %d bytes", len(after.Bytes))
	}
}
