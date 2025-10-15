package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HttpClient struct {
	cliCtx     *CliContext
	baseURL    string
	httpClient *http.Client
	verbose    bool
}

func NewHttpClient(cliCtx *CliContext, baseURL string, tls *tls.Config) (*HttpClient, error) {
	if cliCtx == nil {
		return nil, fmt.Errorf("cli context is required")
	}
	transport := &http.Transport{}
	if tls != nil {
		transport.TLSClientConfig = tls
	}
	client := &HttpClient{
		cliCtx:  cliCtx,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		verbose: cliCtx.cfg.GetBool("verbose"),
	}
	return client, nil
}

func (c *HttpClient) logVerbose(format string, args ...any) {
	c.cliCtx.LogVerbose(format, args...)
}

// APIResponse represents the standard API response format
type APIResponse struct {
	Success bool
	Data    []byte
}

func (c *HttpClient) SendRequest(method, path string, body any) (*http.Response, []byte, error) {
	var reqBody io.Reader
	c.logVerbose("Request: %s %s", method, path)
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonBody)
		c.logVerbose("Body: %s", string(jsonBody))
	} else {
		c.logVerbose("Body: (none)")
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(c.cliCtx.ctx, method, url, reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	c.logVerbose("Response Status: %d", resp.StatusCode)
	c.logVerbose("Response Body: %s", string(respBody))

	return resp, respBody, nil
}
