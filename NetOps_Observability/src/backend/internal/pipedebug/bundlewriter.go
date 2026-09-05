package pipedebug

// bundlewriter.go — the ONE session-bundle writer.
//
// WHY IT LIVES HERE rather than in the CLI. Two callers now package a session
// for support: `correlix-debug bundle` on the host, and the GUI's download
// button (GET /api/debug/sessions/{id}/bundle) inside the api container. A
// second implementation would be a second chance to forget the SHA256SUMS
// member, the README that states which redaction pass ran, or the 0600 file
// mode — so there is one, and both callers hand it an io.Writer.
//
// REDACTION is NOT applied here, deliberately: Session.Line runs the pass when
// each line is WRITTEN, so the directory on disk is already safe to share.
// Redacting again at bundle time would imply the on-disk session is not, which
// is the wrong thing for an operator to believe about a 0700 directory they may
// copy off the host by hand.
//
// COMPRESSION is the caller's business. The CLI shells out to `zstd` when the
// host has it; the api container has no zstd binary and does not shell out at
// all, so it wraps this in stdlib gzip. Both name the codec they used.

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BundleReadme is the archive's first member: what this is, which redaction
// pass ran, and how to verify it.
func BundleReadme(dirs []string) string {
	var b strings.Builder
	b.WriteString("CORRELIX PIPELINE DEBUG BUNDLE\n==============================\n\n")
	fmt.Fprintf(&b, "created  : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "sessions : %d\n", len(dirs))
	for _, d := range dirs {
		fmt.Fprintf(&b, "           %s\n", filepath.Base(d))
	}
	b.WriteString("\nREDACTION\n---------\n")
	b.WriteString(RedactionNote + "\n")
	b.WriteString("\nRedaction is applied when each line is WRITTEN, not when the bundle is built,\n")
	b.WriteString("so the session directory on disk is already safe to share. Tenant identifiers\n")
	b.WriteString("are deliberately RETAINED: support needs them to reason about isolation.\n")
	b.WriteString("\nVERIFY\n------\nsha256sum -c SHA256SUMS   (run inside the extracted directory)\n")
	return b.String()
}

// MaxBundleBytes bounds a bundle assembled IN MEMORY (the api's download path).
// A session is ten bounded log files; anything past this is a session that has
// been fed by something other than this debugger, and streaming it out of a
// 512 MiB api container is not a debug action worth taking.
const MaxBundleBytes = 32 << 20

// ErrBundleTooLarge is returned when the selected sessions exceed MaxBundleBytes.
// It is a NAMED refusal rather than a truncated archive: a bundle that silently
// dropped members would be evidence a reader could not trust.
type ErrBundleTooLarge struct {
	Bytes int64
	Limit int64
}

func (e ErrBundleTooLarge) Error() string {
	return fmt.Sprintf("the selected debug session holds %d bytes, over the %d-byte in-memory bundle limit — package it on the host with `correlix-debug bundle --session <dir>`, which streams to disk",
		e.Bytes, e.Limit)
}

// WriteBundleTar writes an uncompressed tar of every regular file in each
// session directory to w, and returns the SHA256SUMS text for its members.
//
// `limit` bounds the total member bytes read (0 = unbounded, the CLI's on-disk
// path). The sums are returned so the caller can also write them beside the
// archive; they are already INSIDE it, so a bundle that arrives without its
// sidecar is still verifiable.
func WriteBundleTar(w io.Writer, dirs []string, limit int64) (string, error) {
	tw := tar.NewWriter(w)
	var sums strings.Builder
	readme := BundleReadme(dirs)
	if err := writeTarBytes(tw, "BUNDLE-README.txt", []byte(readme)); err != nil {
		return "", err
	}
	fmt.Fprintf(&sums, "%s  %s\n", sha256Hex([]byte(readme)), "BUNDLE-README.txt")

	var total int64
	for _, dir := range dirs {
		base := filepath.Base(dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			// #nosec G304 -- dir came from ListSessions / a validated session id
			// under the operator's own debug root; name is a directory entry
			// this loop just read, never caller input.
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return "", err
			}
			total += int64(len(data))
			if limit > 0 && total > limit {
				return "", ErrBundleTooLarge{Bytes: total, Limit: limit}
			}
			member := filepath.Join(base, name)
			if err := writeTarBytes(tw, member, data); err != nil {
				return "", err
			}
			fmt.Fprintf(&sums, "%s  %s\n", sha256Hex(data), member)
		}
	}
	if err := writeTarBytes(tw, "SHA256SUMS", []byte(sums.String())); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	return sums.String(), nil
}

func writeTarBytes(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(data)),
		ModTime: time.Now().UTC(), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
