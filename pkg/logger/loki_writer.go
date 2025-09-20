package logger

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"sync"
	"time"
)

type LokiWriter struct {
	url         string
	user        string
	pass        string
	fixedLabels map[string]string

	batchSize        int
	batchFlushPeriod time.Duration
	retryMaxCount    int
	retryMinBackoff  time.Duration
	retryMaxBackoff  time.Duration
	compress         bool

	mu     sync.Mutex
	buf    map[string][][2]string // buf[streamKey] = [..., [timestamp, line], ...]
	timer  *time.Timer
	quit   chan struct{}
	wg     sync.WaitGroup
	client *http.Client
}

func parseLabelsKey(key string) map[string]string {
	out := map[string]string{}
	if key == "" {
		return out
	}
	parts := bytes.Split([]byte(key), []byte{'|'})
	for _, p := range parts {
		kv := bytes.SplitN(p, []byte{'='}, 2)
		if len(kv) == 2 {
			out[string(kv[0])] = string(kv[1])
		}
	}
	return out
}

func buildPayloadAndReset(mu *sync.Mutex, buf map[string][][2]string) map[string]any {
	mu.Lock()
	defer mu.Unlock()
	if len(buf) == 0 {
		return nil
	}

	type stream struct {
		Stream map[string]string `json:"stream"`
		Value  [][2]string       `json:"values"`
	}
	payload := make([]stream, 0, len(buf))
	for key, vals := range buf {
		label := parseLabelsKey(key)
		payload = append(payload, stream{
			Stream: label,
			Value:  vals,
		})
	}
	for k := range buf {
		delete(buf, k)
	}
	return map[string]any{"streams": payload}
}

func (w *LokiWriter) pushWithRetry(payload map[string]any) error {
	b, _ := json.Marshal(payload)
	body := io.Reader(bytes.NewReader(b))

	var gz *gzip.Writer
	var buf bytes.Buffer
	if w.compress {
		gz = gzip.NewWriter(&buf)
		_, _ = gz.Write(b)
		_ = gz.Close()
		body = &buf
	}

	req, _ := http.NewRequest("POST", w.url, body)
	req.Header.Set("Content-Type", "application/json")
	if w.compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if w.user != "" {
		req.SetBasicAuth(w.user, w.pass)
	}

	var err error
	backoff := w.retryMinBackoff
	for i := 0; i <= w.retryMaxCount; i++ {
		resp, doErr := w.client.Do(req)
		if doErr != nil && resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if doErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if doErr != nil {
			err = doErr
		} else {
			err = fmt.Errorf("loki push failed, status: %v", resp.Status)
		}
		time.Sleep(backoff)
		if backoff < w.retryMaxBackoff {
			backoff *= 2
			if backoff > w.retryMaxBackoff {
				backoff = w.retryMaxBackoff
			}
		}
	}
	return err
}

func (w *LokiWriter) flushAll() {
	payload := buildPayloadAndReset(&w.mu, w.buf)
	if payload == nil {
		return
	}
	err := w.pushWithRetry(payload)
	if err != nil {
		if _, err := fmt.Fprintf(os.Stderr, "LokiWriter flush error: %v\n", err); err != nil {
			return
		}
	}
}

func (w *LokiWriter) flushLoop() {
	defer w.wg.Done()
	for {
		select {
		case <-w.quit:
			w.flushAll()
			return
		case <-w.timer.C:
			w.flushAll()
			w.timer.Reset(w.batchFlushPeriod)
		}
	}
}

func NewLokiWriter(cfg *SinkConfig, fixedLabels map[string]string) (*LokiWriter, error) {
	if cfg.LokiURL == "" {
		return nil, fmt.Errorf("SinkConfig missing loki_url")
	}
	w := &LokiWriter{
		url:         cfg.LokiURL,
		user:        cfg.BasicAuthUser,
		pass:        cfg.BasicAuthPass,
		fixedLabels: fixedLabels,

		batchSize:        ifZero(cfg.BatchSize, DefaultBatchSize),
		batchFlushPeriod: time.Duration(ifZero(cfg.BatchFlushPeriodMs, DefaultBatchFlushPeriodMs)) * time.Millisecond,
		retryMaxCount:    ifZero(cfg.RetryMaxCount, DefaultRetryMaxCount),
		retryMinBackoff:  time.Duration(ifZero(cfg.RetryMinBackoffMs, DefaultRetryMinBackoffMs)) * time.Millisecond,
		retryMaxBackoff:  time.Duration(ifZero(cfg.RetryMaxBackoffMs, DefaultRetryMaxBackoffMs)) * time.Millisecond,
		compress:         cfg.Compress,

		mu:     sync.Mutex{},
		buf:    make(map[string][][2]string),
		timer:  nil,
		quit:   make(chan struct{}),
		client: &http.Client{Timeout: time.Duration(DefaultClientTimeoutSec) * time.Second},
	}
	w.timer = time.NewTimer(w.batchFlushPeriod)
	w.wg.Add(1)
	go w.flushLoop()
	return w, nil
}

func parseLevel(p []byte) string {
	var tmp map[string]string
	if err := json.Unmarshal(p, &tmp); err != nil {
		return ""
	}
	if val, ok := tmp["level"]; ok {
		return val
	}
	return ""
}

func labelsKey(m map[string]string) string {
	var b bytes.Buffer
	first := true
	for k, v := range m {
		if !first {
			b.WriteByte('|')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		first = false
	}
	return b.String()
}

func (w *LokiWriter) Write(p []byte) (n int, err error) {
	level := parseLevel(p)
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	line := string(bytes.TrimSpace(p))

	label := make(map[string]string, len(w.fixedLabels)+1)
	maps.Copy(label, w.fixedLabels)
	if level != "" {
		label["level"] = level
	}

	key := labelsKey(label)

	w.mu.Lock()
	w.buf[key] = append(w.buf[key], [2]string{ts, line})
	needFlush := len(w.buf[key]) >= w.batchSize
	w.mu.Unlock()

	if needFlush {
		w.flushAll()
		w.timer.Reset(w.batchFlushPeriod)
	}
	return len(p), nil
}

func (w *LokiWriter) Sync() error {
	return nil
}

func (w *LokiWriter) Close() error {
	close(w.quit)
	w.wg.Wait()
	return nil
}
