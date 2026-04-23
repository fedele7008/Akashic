package pki

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatcherLogger is a narrow logging interface so the watcher doesn't have to
// pull in pkg/logging (which would create a dependency cycle via the servers).
// Any *zap.SugaredLogger satisfies this; so does a test stub.
type WatcherLogger interface {
	Infof(template string, args ...any)
	Warnf(template string, args ...any)
	Errorf(template string, args ...any)
}

// Watcher runs a single goroutine that calls Reloader.Reload whenever the
// cert or key file on disk changes. It coalesces bursts of filesystem events
// within a debounce window to avoid reloading a half-rotated pair (new cert,
// old key) which would fail to parse.
//
// This is strictly an optimization over polling or POST /tls/reload; callers
// may skip Watcher entirely by setting AKASHIC_PKI_CERT_WATCHER_ENABLED=false.
type Watcher struct {
	reloaders []*Reloader
	fsw       *fsnotify.Watcher
	debounce  time.Duration
	logger    WatcherLogger

	mu    sync.Mutex
	timer *time.Timer
	dirty map[*Reloader]struct{}
}

// NewWatcher subscribes to every unique directory containing a reloader's
// cert or key file. The caller is responsible for running Watcher.Run in a
// goroutine and calling Close on shutdown.
//
// debounce should be long enough for Vault Agent to finish writing both the
// cert and the key (both writes come from the same template block but are
// sequential file operations). 500ms is a reasonable default.
func NewWatcher(reloaders []*Reloader, debounce time.Duration, logger WatcherLogger) (*Watcher, error) {
	if len(reloaders) == 0 {
		return nil, fmt.Errorf("pki.NewWatcher: no reloaders provided")
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}

	// Subscribe to the unique set of parent directories. fsnotify watches
	// directories, not individual files -- this is intentional because an
	// atomic replace via rename() triggers a CREATE event on the target
	// rather than a WRITE, and rename survives only at the directory level.
	dirs := map[string]struct{}{}
	for _, r := range reloaders {
		dirs[filepath.Dir(r.CertPath())] = struct{}{}
		dirs[filepath.Dir(r.KeyPath())] = struct{}{}
	}
	for d := range dirs {
		if err := fsw.Add(d); err != nil {
			fsw.Close()
			return nil, fmt.Errorf("watch dir %s: %w", d, err)
		}
	}

	return &Watcher{
		reloaders: reloaders,
		fsw:       fsw,
		debounce:  debounce,
		logger:    logger,
		dirty:     make(map[*Reloader]struct{}),
	}, nil
}

// Run blocks until ctx is cancelled or the fsnotify channel closes.
// It is safe to call exactly once per Watcher.
func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.onEvent(ev)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			if w.logger != nil {
				w.logger.Warnf("cert watcher fsnotify error: %v", err)
			}
		}
	}
}

// onEvent tags any reloader whose cert/key matches the event and restarts
// the debounce timer. We match on the basename AND directory so that two
// reloaders in the same directory with different filenames don't step on
// each other.
func (w *Watcher) onEvent(ev fsnotify.Event) {
	// Ignore events that don't indicate new content
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.reloaders {
		if pathsMatch(ev.Name, r.CertPath()) || pathsMatch(ev.Name, r.KeyPath()) {
			w.dirty[r] = struct{}{}
		}
	}
	if len(w.dirty) == 0 {
		return
	}
	// (Re)arm the debounce timer. The flush runs exactly once per quiet
	// window, even if we get 50 events in rapid succession.
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(w.debounce, w.flush)
}

func (w *Watcher) flush() {
	w.mu.Lock()
	toReload := make([]*Reloader, 0, len(w.dirty))
	for r := range w.dirty {
		toReload = append(toReload, r)
	}
	w.dirty = make(map[*Reloader]struct{})
	w.mu.Unlock()

	for _, r := range toReload {
		if err := r.Reload(); err != nil {
			// Transient -- e.g. Vault Agent wrote .crt but not .key yet.
			// The next event (on .key) will re-arm the timer and retry.
			if w.logger != nil {
				w.logger.Warnf("cert reload deferred for %s: %v", r.Name(), err)
			}
			continue
		}
		if w.logger != nil {
			w.logger.Infof("cert reloaded for %s", r.Name())
		}
	}
}

// Close stops watching and releases fsnotify resources. Idempotent.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.mu.Unlock()
	return w.fsw.Close()
}

// pathsMatch compares two paths, tolerating relative vs absolute forms that
// end in the same filename+dir. fsnotify generally emits cleaned paths, but
// macOS and Linux differ on whether they're absolute.
func pathsMatch(a, b string) bool {
	ca, err := filepath.Abs(a)
	if err != nil {
		ca = a
	}
	cb, err := filepath.Abs(b)
	if err != nil {
		cb = b
	}
	return filepath.Clean(ca) == filepath.Clean(cb)
}
