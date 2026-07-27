package main

// openapi_handler.go — HTTP wiring for the OpenAPI document.
//
// The document itself is built by internal/openapi (pure, testable without a
// server). Only the routing/response half lives here, which is what §2 means by
// keeping the entrypoint package to wiring.

import (
	"net/http"

	"netops/backend/internal/openapi"
)

func (s *server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, openapi.Spec(version))
}
