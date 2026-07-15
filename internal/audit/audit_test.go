package audit

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/corslens/internal/cors"
)

func TestAuditWildCardWithCredentials(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	if len(result.Issues) == 0 {
		t.Fatal("expected issues for wildcard with credentials")
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Code == "WILDCARD_WITH_CREDENTIALS" {
			found = true
			if issue.Severity != SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected WILDCARD_WITH_CREDENTIALS issue")
	}
}

func TestAuditWildcardOrigin(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin": "*",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	found := false
	for _, issue := range result.Issues {
		if issue.Code == "WILDCARD_ORIGIN" {
			found = true
			if issue.Severity != SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected WILDCARD_ORIGIN issue")
	}
}

func TestAuditNoCORSHeaders(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
	if result.Grade != "F" {
		t.Errorf("expected grade F, got %s", result.Grade)
	}
}

func TestAuditGoodConfig(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin":      "https://example.com",
		"Access-Control-Allow-Methods":     "GET, POST",
		"Access-Control-Allow-Headers":     "Content-Type, Authorization",
		"Access-Control-Max-Age":           "86400",
		"Access-Control-Expose-Headers":    "X-Request-Id",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	if result.Score < 70 {
		t.Errorf("expected score >= 70 for good config, got %d", result.Score)
	}
	if result.Grade == "F" {
		t.Errorf("expected at least D grade for good config, got %s", result.Grade)
	}
}

func TestAuditOverlyPermissiveMethods(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin":      "https://example.com",
		"Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT, FETCH, PROPFIND",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	found := false
	for _, issue := range result.Issues {
		if issue.Code == "OVERLY_PERMISSIVE_METHODS" {
			found = true
			if issue.Severity != SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected OVERLY_PERMISSIVE_METHODS issue")
	}
}

func TestAuditWildcardHeaders(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin":      "https://example.com",
		"Access-Control-Allow-Headers":     "*",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	found := false
	for _, issue := range result.Issues {
		if issue.Code == "WILDCARD_HEADERS" {
			found = true
			if issue.Severity != SeverityHigh {
				t.Errorf("expected HIGH severity, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected WILDCARD_HEADERS issue")
	}
}

func TestAuditNoMaxAge(t *testing.T) {
	cfg := cors.ParseCORSHeadersFromMap(map[string]string{
		"Access-Control-Allow-Origin": "https://example.com",
	}, 200)

	result := AuditCORS("https://api.example.com", cfg)

	found := false
	for _, issue := range result.Issues {
		if issue.Code == "NO_MAX_AGE" {
			found = true
			if issue.Severity != SeverityLow {
				t.Errorf("expected LOW severity, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected NO_MAX_AGE issue")
	}
}

func TestScoreCalculation(t *testing.T) {
	tests := []struct {
		name   string
		headers map[string]string
		wantMin int
		wantMax int
	}{
		{
			name:   "perfect config",
			headers: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Methods":     "GET, POST",
				"Access-Control-Allow-Headers":     "Content-Type",
				"Access-Control-Max-Age":           "86400",
				"Access-Control-Expose-Headers":    "X-Request-Id",
			},
			wantMin: 80,
			wantMax: 100,
		},
		{
			name:   "wildcard origin",
			headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
			wantMin: 75,
			wantMax: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cors.ParseCORSHeadersFromMap(tt.headers, 200)
			result := AuditCORS("https://api.example.com", cfg)

			if result.Score < tt.wantMin || result.Score > tt.wantMax {
				t.Errorf("score = %d, want [%d, %d]", result.Score, tt.wantMin, tt.wantMax)
			}
		})
	}
}
