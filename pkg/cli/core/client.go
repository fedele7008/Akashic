package core

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

// NewAkashicControlClient builds an HttpClient configured to talk to the
// Akashic control plane using a named profile (or the active one if name
// is empty). Verifies file permissions before reading -- catches loose
// chmods that would let other users read the private key.
//
// Returns the client + the resolved profile name (useful for log lines).
func NewAkashicControlClient(cliCtx *CliContext, profileName string) (*HttpClient, string, error) {
	cfg, err := LoadProfileConfig()
	if err != nil {
		return nil, "", err
	}
	prof, name, err := ResolveProfile(cfg, profileName)
	if err != nil {
		return nil, "", err
	}
	if err := VerifyProfilePerms(prof); err != nil {
		return nil, "", err
	}

	caPEM, err := os.ReadFile(prof.CACertPath)
	if err != nil {
		return nil, "", fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", fmt.Errorf("CA bundle %s contains no valid PEM certificates", prof.CACertPath)
	}
	cert, err := tls.LoadX509KeyPair(prof.ClientCertPath, prof.ClientKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load client keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	hc, err := NewHttpClient(cliCtx, prof.ControlURL, tlsCfg)
	if err != nil {
		return nil, "", err
	}
	return hc, name, nil
}

func (c *HttpClient) logVerbose(format string, args ...any) {
	c.cliCtx.LogVerbose(format, args...)
}

// APIResponse represents the standard API response format
type APIResponse struct {
	Success bool
	Data    []byte
}

func (c *HttpClient) buildRequest(method, path string, body any) (*http.Request, error) {
	var reqBody io.Reader
	c.logVerbose("Request: %s %s", method, path)
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonBody)
		c.logVerbose("Body: %s", string(jsonBody))
	} else {
		c.logVerbose("Body: (none)")
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(c.cliCtx.ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func (c *HttpClient) doRequest(req *http.Request) (*http.Response, []byte, error) {
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

func (c *HttpClient) SendRequest(method, path string, body any) (*http.Response, []byte, error) {
	req, err := c.buildRequest(method, path, body)
	if err != nil {
		return nil, nil, err
	}
	return c.doRequest(req)
}

func (c *HttpClient) SendRequestWithToken(method, path string, body any, token string) (*http.Response, []byte, error) {
	req, err := c.buildRequest(method, path, body)
	if err != nil {
		return nil, nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	return c.doRequest(req)
}
