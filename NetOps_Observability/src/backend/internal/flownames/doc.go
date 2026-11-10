// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package flownames names what a flow record carries (tracker 387 PR 13):
// interfaces through netops.iface_names (names.go), the Logs page's sampled
// flow documents (annotate.go), and the flows Correlix's own pollers caused
// (platform.go). Names are only ever looked up by the flow ROW's own tenant,
// and a number nobody named stays a number.
package flownames
