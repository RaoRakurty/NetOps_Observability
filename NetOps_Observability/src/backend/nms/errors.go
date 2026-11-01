// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"errors"
	"fmt"
)

// ErrSignatureInvalid is returned by a WebhookHandler when authentication of an
// inbound request fails (bad shared secret / HMAC).
var ErrSignatureInvalid = errors.New("nms: webhook signature invalid")

// ErrAuthFailed marks an error raised while authenticating to a controller
// (the cycle's login, or the re-login after a 401). RunPollSession wraps every
// such error with it (%w), so the runtime can tell "the controller refused us"
// from "the controller is down" without parsing text. A transport, timeout or
// 5xx failure during login keeps its own class: classifyPollError checks those
// first, so a result of auth_failed means the credential or the account.
var ErrAuthFailed = errors.New("nms: controller authentication failed")

// HTTPStatusError is a controller answer outside 2xx. Op names what was being
// done ("poll alarms", "vmanage auth"); the message is the one these call
// sites have always produced, so logs and run records read the same.
type HTTPStatusError struct {
	Op   string
	Code int
}

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("%s: status %d", e.Op, e.Code) }
