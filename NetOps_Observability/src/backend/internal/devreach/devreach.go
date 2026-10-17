// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package devreach decides whether a device is answering its collectors —
// the ONE liveness verdict every inventory surface renders (list, detail
// popup, monitoring page), so they can never disagree.
//
// The input is collector_target_up{collector,device} (1 = this collector's
// last poll of the device answered), which every polling collector emits per
// cycle and the DeviceUnreachable alert already reads. The device's
// last_seen is NOT liveness: it is stamped whenever discovery still lists the
// device, so a dead device stays "seen" (owner report 2026-10-10: the list said
// up while the popup said down, both reading last_seen with different
// thresholds).
package devreach

// Reachability verdicts.
const (
	Up      = "up"      // every collector polling it got an answer
	Down    = "down"    // no collector polling it got an answer
	Partial = "partial" // some collectors answered, some did not
	Unknown = "unknown" // no collector has polled it recently (or the store was unread)
)

// Fold turns per-device max/min of collector_target_up over the window into a
// verdict. A device absent from both maps is Unknown — never Down: "we have no
// recent poll" is not "the device is down".
func Fold(maxUp, minUp map[string]float64, device string) string {
	hi, okHi := maxUp[device]
	lo, okLo := minUp[device]
	switch {
	case !okHi && !okLo:
		return Unknown
	case hi < 1:
		return Down
	case okLo && lo < 1:
		return Partial
	default:
		return Up
	}
}
