package logging

import (
	"akashic/akashic/pkg/common"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type LogLine [2]string // [timestamp, line]
type LogLists []LogLine
type StreamKey map[string]string

type LokiWriter struct {
	url         string
	user        string
	pass        string
	fixedLabels StaticLabel

	batchSize        int
	batchFlushPeriod time.Duration
	retryMaxCount    int
	retryMinBackoff  time.Duration
	retryMaxBackoff  time.Duration
	compress         bool

	mu      sync.Mutex
	buf     map[string]LogLists // buf[streamKeyStr] = [..., [timestamp, line], ...]
	timer   *time.Timer
	quit    chan struct{}
	flush   chan struct{}
	wg      sync.WaitGroup
	breaker *common.Breaker
	client  *http.Client
}

type stream struct {
	Stream StreamKey `json:"stream"`
	Value  LogLists  `json:"values"`
}

func buildPayloadAndReset(mu *sync.Mutex, buf map[string]LogLists) (map[string]any, error) {
	mu.Lock()
	defer mu.Unlock()
	if len(buf) == 0 {
		return nil, nil
	}

	payload := make([]stream, 0, len(buf))
	for key, vals := range buf {
		decodedMap, err := url.ParseQuery(key)
		if err != nil {
			return nil, err
		}
		label := make(StreamKey, len(decodedMap))
		for k, values := range decodedMap {
			if len(values) > 0 {
				// if multiple values exist, take very first one only
				label[k] = values[0]
			}
		}
		payload = append(payload, stream{
			Stream: label,
			Value:  vals,
		})
	}
	for k := range buf {
		delete(buf, k)
	}
	return map[string]any{"streams": payload}, nil
}

func (w *LokiWriter) pushWithRetry(payload map[string]any) error {
	b, _ := json.Marshal(payload)

	var errs []error
	backoff := w.retryMinBackoff

	for i := 0; i < w.retryMaxCount; i++ {
		body := io.Reader(bytes.NewReader(b))

		// compress if configured
		var gz *gzip.Writer
		var buf bytes.Buffer
		if w.compress {
			gz = gzip.NewWriter(&buf)
			if _, err := gz.Write(b); err != nil {
				errs = append(errs, fmt.Errorf("[attempt-%v] failed to compress logs: %w", i+1, err))
			}
			if err := gz.Close(); err != nil {
				errs = append(errs, fmt.Errorf("[attempt-%v] failed to close gzip writer: %w", i+1, err))
				break
			}
			body = &buf
		}

		// set request headers
		req, err := http.NewRequest("POST", w.url, body)
		if err != nil {
			errs = append(errs, fmt.Errorf("[attempt-%v] error creating request: %v", i+1, err))

			time.Sleep(backoff)
			if backoff < w.retryMaxBackoff {
				backoff *= 2
				if backoff > w.retryMaxBackoff {
					backoff = w.retryMaxBackoff
				}
			}

			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if w.compress {
			req.Header.Set("Content-Encoding", "gzip")
		}
		if w.user != "" {
			req.SetBasicAuth(w.user, w.pass)
		}

		// send request
		resp, doErr := w.client.Do(req)
		if doErr != nil && resp != nil && resp.Body != nil {
			if _, err = io.Copy(io.Discard, resp.Body); err != nil {
				errs = append(errs, fmt.Errorf("[attempt-%v] error reading response body: %w", i+1, err))
			}
			if err = resp.Body.Close(); err != nil {
				errs = append(errs, fmt.Errorf("[attempt-%v] error closing response body: %w", i+1, err))
				break
			}
		}

		// escape loop if success
		if doErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// report error occurred during http request
		if doErr != nil {
			errs = append(errs, fmt.Errorf("[attempt-%v] network error: %w", i+1, doErr))
		}
		time.Sleep(backoff)
		if backoff < w.retryMaxBackoff {
			backoff *= 2
			if backoff > w.retryMaxBackoff {
				backoff = w.retryMaxBackoff
			}
		}
	}
	return errors.Join(append([]error{errors.New("something went wrong while sending log entities to Loki")}, errs...)...)
}

func (w *LokiWriter) flushAll() {
	if !w.breaker.Allow() {
		return
	}
	payload, err := buildPayloadAndReset(&w.mu, w.buf)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "LokiWriter failed to build payload: %v\n", err)
	}
	if payload == nil {
		return
	}
	err = w.pushWithRetry(payload)
	if err != nil {
		w.breaker.OnFail()
		_, _ = fmt.Fprintf(os.Stderr, "LokiWriter flush error: %v\n", err)
	} else {
		w.breaker.OnSuccess()
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
		case <-w.flush:
			w.flushAll()
			w.timer.Reset(w.batchFlushPeriod)
		}
	}
}

func NewLokiWriter(cfg *SinkConfig, fixedLabels StaticLabel) (io.WriteCloser, error) {
	if cfg.LokiURL.GetOrDefault() == "" {
		return nil, fmt.Errorf("SinkConfig missing loki_url")
	}
	w := &LokiWriter{
		url:         cfg.LokiURL.GetOrDefault(),
		user:        cfg.BasicAuthUser.GetOrDefault(),
		pass:        cfg.BasicAuthPass.GetOrDefault(),
		fixedLabels: fixedLabels,

		batchSize:        ifZero(cfg.BatchSize.GetOrDefault(), DefaultBatchSize),
		batchFlushPeriod: time.Duration(ifZero(cfg.BatchFlushPeriodMs.GetOrDefault(), DefaultBatchFlushPeriodMs)) * time.Millisecond,
		retryMaxCount:    ifZero(cfg.RetryMaxCount.GetOrDefault(), DefaultRetryMaxCount),
		retryMinBackoff:  time.Duration(ifZero(cfg.RetryMinBackoffMs.GetOrDefault(), DefaultRetryMinBackoffMs)) * time.Millisecond,
		retryMaxBackoff:  time.Duration(ifZero(cfg.RetryMaxBackoffMs.GetOrDefault(), DefaultRetryMaxBackoffMs)) * time.Millisecond,
		compress:         cfg.Compress.IfValidGet(DefaultCompress),

		mu:      sync.Mutex{},
		buf:     make(map[string]LogLists),
		timer:   nil,
		quit:    make(chan struct{}),
		flush:   make(chan struct{}, 1),
		breaker: common.NewBreaker(cfg.BreakerMaxRetries.GetOrDefault(), time.Duration(cfg.BreakerCooldownMs.GetOrDefault())*time.Millisecond),
		client:  &http.Client{Timeout: time.Duration(cfg.ClientTimeoutMs.GetOrDefault()) * time.Millisecond},
	}
	w.timer = time.NewTimer(w.batchFlushPeriod)
	w.wg.Add(1)
	go w.flushLoop()
	return w, nil
}

func (w *LokiWriter) Write(p []byte) (n int, err error) {
	// deserialize json from log entity
	var jsonMap map[string]any
	if err = json.Unmarshal(p, &jsonMap); err != nil {
		return 0, fmt.Errorf("error unmarshalling json while loki write: %v", err)
	}

	// extract level string
	var level string
	switch jsonMap[DefaultLogLevelKey].(type) {
	case string:
		level = jsonMap[DefaultLogLevelKey].(string)
	default:
		_, err = fmt.Fprintf(os.Stderr, "invalid log level json type (expected string): %v", jsonMap[DefaultLogLevelKey])
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("invalid log level json type (expected string): %v", jsonMap[DefaultLogLevelKey])
	}
	if level == "" {
		return 0, errors.New("loki log level missing")
	}

	// create string of entire log entity (serialized json string)
	line := string(bytes.TrimSpace(p))

	// add log level to the key value
	label := make(StaticLabel, len(w.fixedLabels)+1)
	maps.Copy(label, w.fixedLabels)
	label[DefaultLogLevelKey] = level

	// serialize key labels
	urlEncoderBuf := url.Values{}
	for k, v := range label {
		urlEncoderBuf.Set(k, v)
	}
	key := urlEncoderBuf.Encode()

	// add to buffer
	w.mu.Lock()
	w.buf[key] = append(w.buf[key], LogLine{fmt.Sprintf("%d", time.Now().UnixNano()), line})
	needFlush := len(w.buf[key]) >= w.batchSize
	w.mu.Unlock()

	// flush if necessary
	if needFlush {
		select {
		case w.flush <- struct{}{}:
		default:
		}
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
