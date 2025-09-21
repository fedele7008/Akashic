package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type RollingFileWriter struct {
	FileWriter
	size       int64
	maxSize    int64
	maxBackups int
}

func (w *RollingFileWriter) suffixed(n int) string {
	return fmt.Sprintf("%s.%d", w.path, n)
}

func (w *RollingFileWriter) rotate() error {
	// close file if it is still open
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
	}

	// for larger suffix number being oldest, shift log files from n suffix to n+1.
	// if number of log file is at max, remove the oldest one.
	for i := w.maxBackups - 1; i >= 1; i-- {
		oldPath := w.suffixed(i)
		newPath := w.suffixed(i + 1)
		if _, err := os.Stat(oldPath); err == nil {
			_ = os.Remove(newPath)
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
		}
	}

	// finally shift most recent log file with no suffix to suffix of 1
	if _, err := os.Stat(w.path); err == nil {
		_ = os.Remove(w.suffixed(1))
		if err := os.Rename(w.path, w.suffixed(1)); err != nil {
			return err
		}
	}

	// create new log file with no suffix
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}
func (w *RollingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, ErrFileWriterNotInitialized
	}
	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err = w.file.Write(p)
	w.size += int64(n)
	return
}

func (w *RollingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func NewRollingFileWriter(path string, maxSizeMB, maxBackups int) (io.WriteCloser, error) {
	if maxSizeMB == 0 {
		// config not defined, use default value
		maxSizeMB = DefaultMaxSizeMB
	} else if maxSizeMB < 1 {
		// config is under lower bound, use lower bound
		maxSizeMB = 1
	}
	if maxBackups == 0 {
		// config not defined, use default value
		maxBackups = DefaultMaxBackups
	} else if maxBackups < 1 {
		// config is under lower bound, use lower bound
		maxBackups = 1
	}
	w := &RollingFileWriter{
		FileWriter: FileWriter{
			mu:   sync.Mutex{},
			path: path,
			file: nil,
		},
		size:       0,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	w.file = f

	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	}
	return w, nil
}
