// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"io"

	audit_model "code.gitea.io/gitea/models/audit"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/translation"
	"code.gitea.io/gitea/modules/util/rotatingfilewriter"
)

var (
	rfw    *rotatingfilewriter.RotatingFileWriter
	locale translation.Locale
)

func initAuditFile() error {
	if setting.Audit.FileOptions == nil {
		return nil
	}

	initAuditFileLocale()

	opts := setting.Audit.FileOptions

	var err error
	rfw, err = rotatingfilewriter.Open(opts.FileName, &rotatingfilewriter.Options{
		Rotate:           opts.LogRotate,
		MaximumSize:      opts.MaxSize,
		RotateDaily:      opts.DailyRotate,
		KeepDays:         opts.MaxDays,
		Compress:         opts.Compress,
		CompressionLevel: opts.CompressionLevel,
	})
	return err
}

func initAuditFileLocale() {
	locale = translation.NewLocale("en-us")
}

func writeToFile(e *Event) error {
	if rfw == nil {
		return nil
	}
	return WriteEventAsJSON(rfw, e)
}

func (d *TypeDescriptor) MarshalJSON() ([]byte, error) {
	type out struct {
		Type        audit_model.ObjectType `json:"type"`
		ID          int64                  `json:"id"`
		DisplayName string                 `json:"display_name"`
	}

	return json.Marshal(out{
		Type:        d.Type,
		ID:          d.ID,
		DisplayName: d.DisplayName(),
	})
}

func (mc MessageContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(locale.TrString(mc.Action.LocaleKey(), mc.Values...))
}

func WriteEventAsJSON(w io.Writer, e *Event) error {
	return json.NewEncoder(w).Encode(e)
}
