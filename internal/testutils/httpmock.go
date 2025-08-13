//SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// MockHTTPClient provides a way to mock HTTP responses for testing
type MockHTTPClient struct {
	HTTPClient *http.Client
	transport  *MockTransport
}

// MockTransport implements http.RoundTripper for intercepting HTTP requests
type MockTransport struct {
	t         testing.TB
	responses map[string]MockResponse
	requests  []RecordedRequest
}

// MockResponse defines a mocked HTTP response
type MockResponse struct {
	StatusCode int
	Body       interface{} // Will be JSON marshaled if not string/[]byte
	Headers    map[string]string
	Error      error
}

// RecordedRequest stores information about requests made
type RecordedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// SetupMockHTTPClient creates a new mock HTTP client for testing
func SetupMockHTTPClient(t testing.TB) *MockHTTPClient {
	t.Helper()

	transport := &MockTransport{
		t:         t,
		responses: make(map[string]MockResponse),
		requests:  []RecordedRequest{},
	}

	mockClient := &MockHTTPClient{
		HTTPClient: &http.Client{
			Transport: transport,
		},
		transport: transport,
	}

	// No cleanup needed for mock HTTP client

	return mockClient
}

// SetResponse configures a mock response for a specific URL pattern
func (m *MockHTTPClient) SetResponse(urlPattern string, response MockResponse) {
	m.transport.responses[urlPattern] = response
}

// SetResponseForRequest configures a mock response for a specific method and URL
func (m *MockHTTPClient) SetResponseForRequest(method, urlPattern string, response MockResponse) {
	key := fmt.Sprintf("%s %s", method, urlPattern)
	m.transport.responses[key] = response
}

// GetRequests returns all recorded requests
func (m *MockHTTPClient) GetRequests() []RecordedRequest {
	return m.transport.requests
}

// GetRequestsTo returns all recorded requests to a specific URL pattern
func (m *MockHTTPClient) GetRequestsTo(urlPattern string) []RecordedRequest {
	var matches []RecordedRequest
	for _, req := range m.transport.requests {
		if strings.Contains(req.URL, urlPattern) {
			matches = append(matches, req)
		}
	}
	return matches
}

// AssertRequestMade asserts that a request was made to the given URL
func (m *MockHTTPClient) AssertRequestMade(t testing.TB, urlPattern string) {
	for _, req := range m.transport.requests {
		if strings.Contains(req.URL, urlPattern) {
			return
		}
	}
	t.Errorf("Expected request to %s but none was made", urlPattern)
}

// AssertNumberOfRequests asserts the total number of requests made
func (m *MockHTTPClient) AssertNumberOfRequests(t testing.TB, expected int) {
	actual := len(m.transport.requests)
	if actual != expected {
		t.Errorf("Expected %d requests but got %d", expected, actual)
	}
}

// RoundTrip implements the http.RoundTripper interface
func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Record the request
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for potential reuse
	}

	t.requests = append(t.requests, RecordedRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header.Clone(),
		Body:    bodyBytes,
	})

	// Find matching response
	response := t.findResponse(req)

	// Return error if configured
	if response.Error != nil {
		return nil, response.Error
	}

	// Build response body
	var responseBody []byte
	if response.Body != nil {
		switch v := response.Body.(type) {
		case string:
			responseBody = []byte(v)
		case []byte:
			responseBody = v
		case nil:
			responseBody = []byte{}
		default:
			// JSON marshal other types
			var err error
			responseBody, err = json.Marshal(v)
			if err != nil {
				t.t.Fatalf("Failed to marshal response body: %v", err)
			}
		}
	}

	// Create HTTP response
	httpResponse := &http.Response{
		StatusCode: response.StatusCode,
		Status:     fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)),
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
		Header:     make(http.Header),
		Request:    req,
	}

	// Set default content type if not specified
	if response.Headers != nil {
		for k, v := range response.Headers {
			httpResponse.Header.Set(k, v)
		}
	}
	if httpResponse.Header.Get("Content-Type") == "" {
		httpResponse.Header.Set("Content-Type", "application/json")
	}

	return httpResponse, nil
}

// findResponse finds the best matching response for a request
func (t *MockTransport) findResponse(req *http.Request) MockResponse {
	// First try method + URL match
	methodURLKey := fmt.Sprintf("%s %s", req.Method, req.URL.String())
	if resp, ok := t.responses[methodURLKey]; ok {
		return resp
	}

	// Then try just URL match
	if resp, ok := t.responses[req.URL.String()]; ok {
		return resp
	}

	// Try to match URL path without query params
	u, _ := url.Parse(req.URL.String())
	if u != nil {
		pathOnly := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		if resp, ok := t.responses[pathOnly]; ok {
			return resp
		}

		// Also try method + path
		methodPathKey := fmt.Sprintf("%s %s", req.Method, pathOnly)
		if resp, ok := t.responses[methodPathKey]; ok {
			return resp
		}
	}

	// Look for partial matches
	for pattern, resp := range t.responses {
		// Remove method prefix if present
		urlPattern := pattern
		if parts := strings.SplitN(pattern, " ", 2); len(parts) == 2 {
			if parts[0] == req.Method {
				urlPattern = parts[1]
			}
		}

		if strings.Contains(req.URL.String(), urlPattern) {
			return resp
		}
	}

	// Return 404 if no match found
	return MockResponse{
		StatusCode: http.StatusNotFound,
		Body:       "Mock response not configured for " + req.URL.String(),
	}
}
