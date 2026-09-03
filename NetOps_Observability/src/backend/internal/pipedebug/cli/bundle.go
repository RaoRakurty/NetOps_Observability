package cli

// bundle.go — the `bundle` verb: package one or more sessions for support.
//
// COMPRESSION. The tar is built with the stdlib (archive/tar). zstd is NOT in
// the Go standard library and adding a module for it would need a CLAUDE.md §6
// allowlist amendment, so the bundle takes the SAME route make-installer.sh
// takes: it shells out to the `zstd` binary when one is present (argv list, no
// shell) and falls back to stdlib gzip otherwise. The chosen codec is printed
// and recorded in the file name, so nobody has to guess which they got.
//
// REDACTION. Session files are ALREADY redacted at write time (Session.Line
// runs the pass), so bundling cannot be the step that forgets. The manifest
// records which pass ran; the bundle re-states it in BUNDLE-README.txt.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/pipedebug"
)

// BundleOptions is the parsed `bundle` invocation.
type BundleOptions struct {
	Session string // one session directory
	Last    int    // or the last N sessions
	Root    string
	Out     string // output directory (default: Root)
}

// RunBundle packages the selected sessions and returns the exit code.
func RunBundle(ctx context.Context, opts BundleOptions, out io.Writer) (int, error) {
	dirs, err := selectSessions(opts)
	if err != nil {
		return 2, err
	}
	if len(dirs) == 0 {
		return 2, fmt.Errorf("no debug sessions found under %s", opts.Root)
	}
	// Where the artefact lands: --out wins; otherwise the debug root, unless the
	// operator pointed --session at a directory outside it (a session copied off
	// the host, say), in which case the session's own parent is the only
	// directory we know exists.
	outDir := opts.Out
	if outDir == "" {
		outDir = opts.Root
	}
	if !isDir(outDir) {
		outDir = filepath.Dir(dirs[0])
	}
	stamp := time.Now().UTC().Format("20060102T1504Z")
	tarPath := filepath.Join(outDir, "correlix-debug-"+stamp+".tar")

	sums, err := writeTar(tarPath, dirs)
	if err != nil {
		return 2, err
	}
	// SHA256SUMS goes INSIDE the archive as well as beside it, so a bundle that
	// arrives without its sidecar is still verifiable.
	if err := os.WriteFile(tarPath+".SHA256SUMS", []byte(sums), 0o600); err != nil {
		return 2, err
	}

	final, codec, err := compress(ctx, tarPath)
	if err != nil {
		return 2, err
	}
	digest, err := fileSHA256(final)
	if err != nil {
		return 2, err
	}
	if err := os.WriteFile(final+".sha256", []byte(digest+"  "+filepath.Base(final)+"\n"), 0o600); err != nil {
		return 2, err
	}
	fmt.Fprintf(out, "bundle : %s\ncodec  : %s\nsha256 : %s\nsessions: %d\n",
		final, codec, digest, len(dirs))
	return 0, nil
}

// isDir reports whether path is an existing directory. "absent" and "exists but
// is a file" are deliberately ONE answer here: both mean the same thing to the
// caller — this is not a usable output directory — and neither is a failure to
// report, because the fallback below is correct for both.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func selectSessions(opts BundleOptions) ([]string, error) {
	if s := strings.TrimSpace(opts.Session); s != "" {
		info, err := os.Stat(s)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a session directory", s)
		}
		return []string{s}, nil
	}
	all, err := pipedebug.ListSessions(opts.Root)
	if err != nil {
		return nil, err
	}
	n := opts.Last
	if n <= 0 {
		n = 1
	}
	if n > len(all) {
		n = len(all)
	}
	return all[:n], nil
}

// writeTar builds the tar and returns the SHA256SUMS text for its members.
func writeTar(path string, dirs []string) (string, error) {
	// #nosec G304 -- path is composed from the operator's own --root/--out and a
	// timestamp; the CLI runs as that operator on their own host.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // closed explicitly below on the success path
	tw := tar.NewWriter(f)

	var sums strings.Builder
	readme := bundleReadme(dirs)
	if err := writeTarBytes(tw, "BUNDLE-README.txt", []byte(readme)); err != nil {
		return "", err
	}
	fmt.Fprintf(&sums, "%s  %s\n", sha256Hex([]byte(readme)), "BUNDLE-README.txt")

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
			// #nosec G304 -- dir came from ListSessions/--session under the
			// operator's own debug root; name is a directory entry, not input.
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return "", err
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
	if err := f.Close(); err != nil {
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

// compress produces the final artifact, preferring zstd when the binary exists.
// It returns the path and the codec actually used — never a name that implies a
// codec that was not applied.
func compress(ctx context.Context, tarPath string) (string, string, error) {
	if zstd, err := exec.LookPath("zstd"); err == nil {
		final := tarPath + ".zst"
		// #nosec G204 -- zstd is resolved from PATH by LookPath and every
		// argument is a literal or a path this function composed. No shell.
		cmd := exec.CommandContext(ctx, zstd, "-q", "-T0", "-19", "-f", "-o", final, tarPath)
		var errBuf strings.Builder
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			return "", "", fmt.Errorf("zstd failed: %w (%s)", err, strings.TrimSpace(errBuf.String()))
		}
		if err := os.Remove(tarPath); err != nil {
			return "", "", err
		}
		return final, "zstd -19", nil
	}
	final := tarPath + ".gz"
	// #nosec G304 -- see writeTar.
	src, err := os.Open(tarPath)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = src.Close() }() // read-only handle; a close error is not actionable
	// #nosec G304 -- see writeTar.
	dst, err := os.OpenFile(final, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	zw := gzip.NewWriter(dst)
	if _, err := io.Copy(zw, src); err != nil {
		_ = dst.Close()
		return "", "", err
	}
	if err := zw.Close(); err != nil {
		_ = dst.Close()
		return "", "", err
	}
	if err := dst.Close(); err != nil {
		return "", "", err
	}
	if err := os.Remove(tarPath); err != nil {
		return "", "", err
	}
	return final, "gzip (zstd not installed on this host)", nil
}

func bundleReadme(dirs []string) string {
	var b strings.Builder
	b.WriteString("CORRELIX PIPELINE DEBUG BUNDLE\n==============================\n\n")
	fmt.Fprintf(&b, "created  : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "sessions : %d\n", len(dirs))
	for _, d := range dirs {
		fmt.Fprintf(&b, "           %s\n", filepath.Base(d))
	}
	b.WriteString("\nREDACTION\n---------\n")
	b.WriteString(pipedebug.RedactionNote + "\n")
	b.WriteString("\nRedaction is applied when each line is WRITTEN, not when the bundle is built,\n")
	b.WriteString("so the session directory on disk is already safe to share. Tenant identifiers\n")
	b.WriteString("are deliberately RETAINED: support needs them to reason about isolation.\n")
	b.WriteString("\nVERIFY\n------\nsha256sum -c SHA256SUMS   (run inside the extracted directory)\n")
	return b.String()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fileSHA256(path string) (string, error) {
	// #nosec G304 -- path is the artifact this function just wrote.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only handle; a close error is not actionable
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
