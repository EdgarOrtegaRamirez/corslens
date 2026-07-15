// Package cors provides parsing and analysis of CORS headers.
package cors

import (
	"net/http"
	"strings"
)

// OriginPolicy represents the allowed origins configuration.
type OriginPolicy struct {
	AllowedOrigins   []string // Parsed from Access-Control-Allow-Origin
	IsWildcard       bool     // True if origin is "*"
	AllowsCredentials bool    // True if Access-Control-Allow-Credentials is "true"
}

// MethodPolicy represents allowed HTTP methods.
type MethodPolicy struct {
	AllowedMethods []string // Parsed from Access-Control-Allow-Methods
}

// HeaderPolicy represents allowed request/response headers.
type HeaderPolicy struct {
	AllowedHeaders   []string // From Access-Control-Allow-Headers
	ExposedHeaders   []string // From Access-Control-Expose-Headers
}

// MaxAgePolicy represents the cache duration for preflight responses.
type MaxAgePolicy struct {
	Duration int // in seconds
}

// CORSConfig is the complete parsed CORS configuration from response headers.
type CORSConfig struct {
	Origin      OriginPolicy
	Method      MethodPolicy
	Header      HeaderPolicy
	MaxAge      MaxAgePolicy
	RawHeaders  http.Header
	StatusCode  int
}

// ParseCORSHeaders extracts and parses CORS headers from an HTTP response.
func ParseCORSHeaders(resp *http.Response) *CORSConfig {
	cfg := &CORSConfig{
		RawHeaders: resp.Header,
		StatusCode: resp.StatusCode,
	}

	// Parse origin
	origin := resp.Header.Get("Access-Control-Allow-Origin")
	cfg.Origin.AllowedOrigins = []string{origin}
	cfg.Origin.IsWildcard = strings.EqualFold(origin, "*")
	cfg.Origin.AllowsCredentials = strings.EqualFold(
		resp.Header.Get("Access-Control-Allow-Credentials"), "true",
	)

	// Parse methods
	methods := resp.Header.Get("Access-Control-Allow-Methods")
	if methods != "" {
		cfg.Method.AllowedMethods = splitCSV(methods)
	}

	// Parse headers
	allowedH := resp.Header.Get("Access-Control-Allow-Headers")
	if allowedH != "" {
		cfg.Header.AllowedHeaders = splitCSV(allowedH)
	}
	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	if exposed != "" {
		cfg.Header.ExposedHeaders = splitCSV(exposed)
	}

	// Parse max-age
	cfg.parseMaxAge(resp.Header.Get("Access-Control-Max-Age"))

	return cfg
}

// ParseCORSHeadersFromMap parses CORS headers from a map (useful for testing).
func ParseCORSHeadersFromMap(headers map[string]string, statusCode int) *CORSConfig {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	resp := &http.Response{Header: h, StatusCode: statusCode}
	return ParseCORSHeaders(resp)
}

func (c *CORSConfig) parseMaxAge(raw string) {
	if raw == "" {
		return
	}
	var n int
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	c.MaxAge.Duration = n
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, strings.ToUpper(trimmed))
		}
	}
	return result
}
