package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

type TruncatedFileWriter struct {
	FileWriter
}

func (w *TruncatedFileWriter) Write(p []byte) (n int, err error) {
	return w.FileWriter.Write(p)
}

func (w *TruncatedFileWriter) Close() error {
	return w.FileWriter.Close()
}

func NewTruncatedFileWriter(path string) (io.WriteCloser, error) {
	w := &TruncatedFileWriter{
		FileWriter: FileWriter{
			mu:   sync.Mutex{},
			path: path,
			file: nil,
		},
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	w.file = f

	return w, nil
}
