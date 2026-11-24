// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

import "netops/backend/models"

// ApplyToDevice stamps a resolved device onto its inventory read (tracker
// 389): each fact a source reported takes the value that wins under the
// tenant's order — the SAME resolution Iris cites — and every disagreement is
// listed with the sentence Iris states. The device page and the inventory API
// therefore never show a value Iris would contradict.
//
// d is a read copy; nothing here is persisted (the stamped fields are cleared
// before any write).
func ApplyToDevice(d *models.Device, rs []Resolution, order []Class, customized bool) {
	d.SourceDisagreements = nil
	for _, r := range rs {
		switch r.Fact {
		case FactVendor:
			d.Vendor = r.Value
		case FactModel:
			d.Model = r.Value
		case FactSerial:
			d.SerialNumber = r.Value
		case FactSoftwareVersion:
			d.SoftwareVersion = r.Value
		}
		if !r.Disagreed() {
			continue
		}
		fd := models.FactDisagreement{
			Fact:   string(r.Fact),
			Label:  FactLabel(r.Fact),
			Value:  Clean(r.Value, MaxValueRunes),
			Source: SourceText(r.Winner),
			Text:   DisagreementText(r, order, customized),
		}
		for _, c := range r.Disagreements {
			fd.Others = append(fd.Others, models.FactClaim{Value: Clean(c.Value, MaxValueRunes), Source: SourceText(c)})
		}
		d.SourceDisagreements = append(d.SourceDisagreements, fd)
	}
}
