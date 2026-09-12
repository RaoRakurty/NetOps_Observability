// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"netops/backend/internal/platformdb"
	"os"

	"netops/backend/reports"
)

// report_artifacts.go — Phase-1 ArtifactStore: persists rendered report artifacts
// through the process kv backend (a file on the file backend, an app_kv row on
// Postgres), keyed by execution id. It works on both backends, so artifacts are
// available whether or not Postgres is configured. A filesystem/S3/blob store can
// replace it behind reports.ArtifactStore with no change to the pipeline, which is
// the whole point of the abstraction (large HTML, and later PDF blobs, want a real
// object store + retention; this keeps that swap a one-file change).
type kvArtifactStore struct{}

func newKVArtifactStore() kvArtifactStore { return kvArtifactStore{} }

// artifactKey avoids '/' so the file backend writes a flat filename.
func artifactKey(execID string) string { return "report_artifact_" + execID }

func (kvArtifactStore) Save(_ context.Context, execID string, a reports.Artifact) (reports.ArtifactRef, error) {
	sum := sha256.Sum256(a.Bytes)
	ref := reports.ArtifactRef{
		Format:      a.Format,
		ContentType: a.ContentType,
		SizeBytes:   len(a.Bytes),
		SHA256:      hex.EncodeToString(sum[:]),
		Summary:     a.Summary,
		Key:         execID,
	}
	if err := platformdb.Save(artifactKey(execID), a.Bytes); err != nil {
		return reports.ArtifactRef{}, err
	}
	return ref, nil
}

func (kvArtifactStore) Load(_ context.Context, ref reports.ArtifactRef) (reports.Artifact, error) {
	b, err := platformdb.Load(artifactKey(ref.Key))
	if err != nil {
		return reports.Artifact{}, err
	}
	return reports.Artifact{
		Format:      ref.Format,
		ContentType: ref.ContentType,
		Bytes:       b,
		Summary:     ref.Summary,
	}, nil
}

func (kvArtifactStore) Delete(_ context.Context, ref reports.ArtifactRef) error {
	// The kv backend has no delete primitive; overwrite with an empty tombstone.
	// A real retention sweep (TTL + hard delete) belongs to the object-store
	// implementation in a later phase.
	err := platformdb.Save(artifactKey(ref.Key), []byte{})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

var _ reports.ArtifactStore = kvArtifactStore{}
