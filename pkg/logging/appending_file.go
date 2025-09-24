package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

type AppendingFileWriter struct {
	FileWriter
}

func (w *AppendingFileWriter) Write(p []byte) (n int, err error) {
	return w.FileWriter.Write(p)
}

func (w *AppendingFileWriter) Close() error {
	return w.FileWriter.Close()
}

func NewAppendingFileWriter(path string) (io.WriteCloser, error) {
	w := &AppendingFileWriter{
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

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	w.file = f

	return w, nil
}
