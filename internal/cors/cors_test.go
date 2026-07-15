package cors

import (
	"testing"
)

func TestParseCORSHeadersFromMap(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		wantOrig   string
		wantWild   bool
		wantCred   bool
	}{
		{
			name:     "wildcard origin",
			headers:  map[string]string{"Access-Control-Allow-Origin": "*"},
			wantOrig: "*",
			wantWild: true,
		},
		{
			name:     "specific origin",
			headers:  map[string]string{"Access-Control-Allow-Origin": "https://example.com"},
			wantOrig: "https://example.com",
			wantWild: false,
		},
		{
			name:     "credentials",
			headers:  map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
			wantOrig: "*",
			wantWild: true,
			wantCred: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ParseCORSHeadersFromMap(tt.headers, tt.statusCode)

			if cfg.Origin.AllowedOrigins[0] != tt.wantOrig {
				t.Errorf("origin = %q, want %q", cfg.Origin.AllowedOrigins[0], tt.wantOrig)
			}
			if cfg.Origin.IsWildcard != tt.wantWild {
				t.Errorf("IsWildcard = %v, want %v", cfg.Origin.IsWildcard, tt.wantWild)
			}
			if cfg.Origin.AllowsCredentials != tt.wantCred {
				t.Errorf("AllowsCredentials = %v, want %v", cfg.Origin.AllowsCredentials, tt.wantCred)
			}
		})
	}
}

func TestMethodsParsing(t *testing.T) {
	cfg := ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
	}, 200)

	if len(cfg.Method.AllowedMethods) != 4 {
		t.Errorf("expected 4 methods, got %d: %v", len(cfg.Method.AllowedMethods), cfg.Method.AllowedMethods)
	}

	expected := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true}
	for _, m := range cfg.Method.AllowedMethods {
		if !expected[m] {
			t.Errorf("unexpected method: %s", m)
		}
	}
}

func TestHeadersParsing(t *testing.T) {
	cfg := ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Headers":  "Content-Type, Authorization",
		"Access-Control-Expose-Headers": "X-Request-Id, X-RateLimit-Remaining",
	}, 200)

	if len(cfg.Header.AllowedHeaders) != 2 {
		t.Errorf("expected 2 allowed headers, got %d", len(cfg.Header.AllowedHeaders))
	}
	if len(cfg.Header.ExposedHeaders) != 2 {
		t.Errorf("expected 2 exposed headers, got %d", len(cfg.Header.ExposedHeaders))
	}
}

func TestMaxAgeParsing(t *testing.T) {
	cfg := ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Max-Age": "3600",
	}, 200)

	if cfg.MaxAge.Duration != 3600 {
		t.Errorf("max-age = %d, want 3600", cfg.MaxAge.Duration)
	}
}

func TestNoCORSHeaders(t *testing.T) {
	cfg := ParseCORSHeadersFromMap(map[string]string{}, 200)

	if cfg.Origin.AllowedOrigins[0] != "" {
		t.Errorf("expected empty origin, got %q", cfg.Origin.AllowedOrigins[0])
	}
}
