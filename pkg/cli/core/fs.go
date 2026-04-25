// Package core: filesystem helpers used by the configure subcommands.
package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CopyFileSecure copies src → dst, writing dst with the given mode and
// fsync'ing before close. Atomic-replace via .tmp + rename so a concurrent
// reader never sees a half-written file.
//
// If src and dst are the same file, this is a no-op (returns nil) -- useful
// for "configure add" idempotency.
func CopyFileSecure(src, dst string, mode os.FileMode) error {
	if absSrc, err := filepath.Abs(src); err == nil {
		if absDst, err := filepath.Abs(dst); err == nil && absSrc == absDst {
			return nil
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("ensure dest dir: %w", err)
	}

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open dest %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	// Belt-and-suspenders: explicitly chmod after close in case the umask
	// stripped bits during OpenFile (yes, this can happen).
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, dst, err)
	}
	return nil
}

// ExpandHome expands a leading "~/" in a path to the user's home directory.
// Other shell expansions ($VAR, *, etc.) are NOT performed -- this is
// deliberately conservative because operators often paste paths from docs
// and we don't want surprise expansion side effects.
func ExpandHome(p string) (string, error) {
	if len(p) < 2 || p[0] != '~' || p[1] != '/' {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand ~: %w", err)
	}
	return filepath.Join(home, p[2:]), nil
}
