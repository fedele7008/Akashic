package common

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
)

// Use fs.FS wrapper for context-aware file operations
type ctxFS struct {
	ctx    context.Context
	isDone bool
	under  fs.FS
}

func (c *ctxFS) check() error {
	select {
	case <-c.ctx.Done():
		c.isDone = true
		return c.ctx.Err()
	default:
		return nil
	}
}

func (c *ctxFS) Open(name string) (fs.File, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	f, err := c.under.Open(name)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (c *ctxFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if rdfs, ok := c.under.(fs.ReadDirFS); ok {
		return rdfs.ReadDir(name)
	}
	// fallback: Open + fs.ReadDirFile
	f, err := c.under.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := c.check(); err != nil {
		return nil, err
	}

	if rdf, ok := f.(fs.ReadDirFile); ok {
		return rdf.ReadDir(-1)
	}
	return nil, fs.ErrInvalid
}

func (c *ctxFS) Stat(name string) (fs.FileInfo, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if sfs, ok := c.under.(fs.StatFS); ok {
		return sfs.Stat(name)
	}
	f, err := c.under.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := c.check(); err != nil {
		return nil, err
	}
	return f.Stat()
}

func ExpandFileGlobsCtx(ctx context.Context, pattern string, opts ...doublestar.GlobOption) ([]string, error) {
	slashed := filepath.ToSlash(filepath.Clean(pattern))

	base, rel := doublestar.SplitPattern(slashed)
	under := os.DirFS(base)
	fsys := &ctxFS{ctx: ctx, under: under}

	seen := make(map[string]struct{})
	out := make([]string, 0, 64)

	err := doublestar.GlobWalk(fsys, rel, func(p string, d fs.DirEntry) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		full := filepath.Join(base, p)
		abs, err := filepath.Abs(full)
		if err != nil {
			return err
		}
		if _, dup := seen[abs]; !dup {
			seen[abs] = struct{}{}
			out = append(out, abs)
		}
		return nil
	}, opts...)
	// Check if GlobWalk ended due to context cancellation
	if fsys.isDone {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
