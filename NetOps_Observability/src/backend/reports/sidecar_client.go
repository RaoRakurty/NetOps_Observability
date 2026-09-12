// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"net/http"
	"time"
)

// sidecar_client.go — the ONE place in this package permitted to construct an
// http.Client. TestGotenbergCallSitesHaveNoBareHTTPClient (root package) pins
// render_pdf.go free of client literals so the gotenberg path can never quietly
// regrow an ad-hoc client that bypasses the injected mesh transport (the
// 2026-08-05 mesh-client incident class). This default exists solely for the
// nil-injection case: the plaintext fresh-install baseline and tests.

// defaultSidecarClient returns the plain fallback client used when no client is
// injected into NewPDFRenderer. Bounded (§9: all IO has a timeout); no TLS
// configuration here by design — mesh trust arrives only via injection.
func defaultSidecarClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
