package ai

import (
	"context"
	"fmt"
)

// docs_tool.go — search_docs: the documentation corpus as a governed tool, so
// the agent loop grounds product/how-to answers the same way the P1 retrieval
// path does. The corpus is platform-global and tenant-free by construction
// (embedded markdown, compiled in — no tool can feed tenant data into it), so
// the tool needs no permission gate; results carry doc:<slug>#<anchor> citation
// ids the UI resolves to Help-drawer deep links, and the verifier already
// strips any doc id the model invents.

type docsSearchTool struct{ ix *DocsIndex }

func (t docsSearchTool) Name() string            { return "search_docs" }
func (t docsSearchTool) Module() string          { return "documentation" }
func (t docsSearchTool) Capability() Capability  { return CapRead }
func (t docsSearchTool) RequiredPerms() []string { return nil } // public product docs
func (t docsSearchTool) Freshness() Freshness    { return FreshnessConfig }
func (t docsSearchTool) Run(_ context.Context, _ Principal, args ToolArgs) (ToolResult, error) {
	query := args["query"]
	if query == "" {
		return ToolResult{}, fmt.Errorf("search_docs: query required")
	}
	hits := t.ix.Search(query, 3)
	if len(hits) == 0 {
		// Honesty floor (P1): no relevant documentation → say so, never invent.
		return ToolResult{Notes: []string{"The documentation does not cover this topic. State that plainly; do not invent steps, endpoints, or configuration keys."}}, nil
	}
	items := make([]EvidenceItem, 0, len(hits))
	for _, h := range hits {
		body := h.Chunk.Body
		if len(body) > 900 {
			body = body[:900] + " …"
		}
		items = append(items, EvidenceItem{
			CitationID: h.Chunk.ID,
			Kind:       "doc",
			Text:       h.Chunk.Breadcrumb + ": " + body,
			Href:       h.Chunk.Href,
		})
	}
	return ToolResult{Items: items}, nil
}

// AddDocsSearch registers the documentation search tool over the given index.
// Kept separate from Tools(ds) because the docs index is process-global (built
// once from embedded markdown) while the DataSource is per-request.
func (r *ToolRegistry) AddDocsSearch(ix *DocsIndex) {
	if ix == nil {
		return
	}
	r.add(docsSearchTool{ix: ix})
}
