// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "errors"

// ErrSignatureInvalid is returned by a WebhookHandler when authentication of an
// inbound request fails (bad shared secret / HMAC).
var ErrSignatureInvalid = errors.New("nms: webhook signature invalid")
