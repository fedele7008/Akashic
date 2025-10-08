package akashiccli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the Akashic control API
type Client struct {
	baseURL    string
	httpClient *http.Client
	verbose    bool
}

// NewClient creates a new Akashic CLI client
func NewClient(baseURL string, verbose bool) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		verbose: verbose,
	}
}

// APIResponse represents the standard API response format
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// doRequest performs an HTTP request and returns the response
func (c *Client) doRequest(ctx context.Context, method, path string, body any) (*APIResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonData)

		if c.verbose {
			fmt.Printf("[DEBUG] Request: %s %s\n", method, path)
			fmt.Printf("[DEBUG] Body: %s\n", string(jsonData))
		}
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if c.verbose {
		fmt.Printf("[DEBUG] Response Status: %d\n", resp.StatusCode)
		fmt.Printf("[DEBUG] Response Body: %s\n", string(respBody))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v (body: %s)", err, string(respBody))
	}

	if !apiResp.Success {
		if apiResp.Error != nil {
			return nil, fmt.Errorf("API error [%s]: %s", apiResp.Error.Code, apiResp.Error.Message)
		}
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return &apiResp, nil
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string) (*APIResponse, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body any) (*APIResponse, error) {
	return c.doRequest(ctx, http.MethodPost, path, body)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body any) (*APIResponse, error) {
	return c.doRequest(ctx, http.MethodPut, path, body)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string) (*APIResponse, error) {
	return c.doRequest(ctx, http.MethodDelete, path, nil)
}
