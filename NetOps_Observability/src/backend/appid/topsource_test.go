package appid

import "testing"

// TopSource is the batch endpoint's provenance line: the strongest signal
// supporting the winning app — never a contradicting or losing source.
func TestVerdictTopSource(t *testing.T) {
	// agreeing coarse catalog + authoritative cloud tag → provenance is the tag
	// (the strongest supporting source), never the weaker corroborator.
	v := Fuse([]Signal{
		{Source: SrcIPCatalog, App: "billing"},
		{Source: SrcCloudTag, App: "billing"},
	})
	if got := v.TopSource(); got != SrcCloudTag {
		t.Fatalf("TopSource = %q, want %q (verdict %+v)", got, SrcCloudTag, v)
	}

	// single medium source → that source
	v = Fuse([]Signal{{Source: SrcIPCatalog, App: "AWS S3"}})
	if got := v.TopSource(); got != SrcIPCatalog {
		t.Fatalf("TopSource = %q, want %q", got, SrcIPCatalog)
	}

	// unknown verdict → no provenance (never a fabricated source)
	v = Fuse(nil)
	if got := v.TopSource(); got != "" {
		t.Fatalf("unknown verdict TopSource = %q, want empty", got)
	}

	// weak-only (undetermined) verdict → no provenance either
	v = Fuse([]Signal{{Source: SrcPort, App: "HTTP"}})
	if got := v.TopSource(); got != "" {
		t.Fatalf("undetermined verdict TopSource = %q, want empty", got)
	}
}
