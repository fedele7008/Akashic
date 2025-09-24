package logging

import (
	"errors"
	"os"
	"sync"
)

var ErrFileWriterNotInitialized = errors.New("file writer not initialized")

type FileWriter struct {
	mu   sync.Mutex
	path string
	file *os.File
}

func (w *FileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, ErrFileWriterNotInitialized
	}
	n, err = w.file.Write(p)
	return n, err
}

func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
