// Package audit provides CORS security analysis.
package audit

import (
	"fmt"
	"strings"

	"github.com/EdgarOrtegaRamirez/corslens/internal/cors"
)

// Severity represents the severity of a CORS issue.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Issue represents a CORS security issue found during analysis.
type Issue struct {
	Severity  Severity
	Code      string
	Message   string
	Suggestion string
}

// Result represents the complete audit result for a single URL.
type Result struct {
	URL        string
	StatusCode int
	Issues     []Issue
	Score      int // 0-100, 100 is perfectly secure
	Grade      string // A-F
	Config     *cors.CORSConfig
}

// AuditCORS analyzes a CORS configuration and returns issues.
func AuditCORS(url string, cfg *cors.CORSConfig) *Result {
	result := &Result{
		URL:        url,
		StatusCode: cfg.StatusCode,
		Issues:     []Issue{},
		Config:     cfg,
	}

	hasCORSHeaders := cfg.Origin.AllowedOrigins[0] != "" ||
		len(cfg.Method.AllowedMethods) > 0 ||
		len(cfg.Header.AllowedHeaders) > 0 ||
		len(cfg.Header.ExposedHeaders) > 0 ||
		cfg.MaxAge.Duration > 0

	if !hasCORSHeaders {
		result.Score = 0
		result.Grade = "F"
		result.Issues = append(result.Issues, Issue{
			Severity: SeverityCritical,
			Code:     "NO_RESPONSE",
			Message:  "No CORS headers found — server may not support CORS",
			Suggestion: "Ensure the server is configured to handle OPTIONS preflight requests",
		})
		return result
	}

	// Check 1: Wildcard origin with credentials
	if cfg.Origin.IsWildcard && cfg.Origin.AllowsCredentials {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityCritical,
			Code:      "WILDCARD_WITH_CREDENTIALS",
			Message:   "Wildcard origin (*) with credentials enabled is always rejected by browsers",
			Suggestion: "Use specific origins instead of * when credentials are required",
		})
	}

	// Check 2: Wildcard origin
	if cfg.Origin.IsWildcard {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityMedium,
			Code:      "WILDCARD_ORIGIN",
			Message:   "Wildcard origin (*) allows any domain to make cross-origin requests",
			Suggestion: "Specify explicit allowed origins for better security",
		})
	}

	// Check 3: Overly permissive methods
	allowAllMethods := len(cfg.Method.AllowedMethods) >= 10
	hasUnsafeMethods := false
	unsafeMethods := []string{"PUT", "DELETE", "PATCH", "POST"}
	for _, m := range cfg.Method.AllowedMethods {
		for _, unsafe := range unsafeMethods {
			if m == unsafe {
				hasUnsafeMethods = true
			}
		}
	}

	if allowAllMethods && hasUnsafeMethods {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityHigh,
			Code:      "OVERLY_PERMISSIVE_METHODS",
			Message:   "Many HTTP methods allowed including unsafe ones (PUT, DELETE, PATCH)",
			Suggestion: "Restrict allowed methods to only what's needed (typically GET, POST)",
		})
	}

	// Check 4: Wildcard headers
	for _, h := range cfg.Header.AllowedHeaders {
		if strings.EqualFold(h, "*") {
			result.Issues = append(result.Issues, Issue{
				Severity:  SeverityHigh,
				Code:      "WILDCARD_HEADERS",
				Message:   "Wildcard (*) allowed headers — any custom header can be sent",
				Suggestion: "Specify explicit allowed headers for better security",
			})
			break
		}
	}

	// Check 5: No max-age or very short max-age
	if cfg.MaxAge.Duration == 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityLow,
			Code:      "NO_MAX_AGE",
			Message:   "No Access-Control-Max-Age header — browser must send preflight every time",
			Suggestion: "Add Access-Control-Max-Age: 86400 to cache preflight responses for 24 hours",
		})
	} else if cfg.MaxAge.Duration < 600 {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityLow,
			Code:      "SHORT_MAX_AGE",
			Message:   "Very short max-age (less than 10 minutes) causes excessive preflight requests",
			Suggestion: "Increase max-age to at least 3600 (1 hour) for better performance",
		})
	}

	// Check 6: No exposed headers
	if len(cfg.Header.ExposedHeaders) == 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityInfo,
			Code:      "NO_EXPOSED_HEADERS",
			Message:   "No Access-Control-Expose-Headers — client can only access safe headers",
			Suggestion: "Add specific headers you want the client to read with Access-Control-Expose-Headers",
		})
	}

	// Check 7: Specific origin with wildcard methods
	if !cfg.Origin.IsWildcard && allowAllMethods {
		result.Issues = append(result.Issues, Issue{
			Severity:  SeverityMedium,
			Code:      "SPECIFIC_ORIGIN_PERMISSIVE_METHODS",
			Message:   "Specific origin but all methods allowed",
			Suggestion: "Restrict methods to only what's needed",
		})
	}

	// Calculate score
	result.calculateScore()
	return result
}

func (r *Result) calculateScore() {
	score := 100
	for _, issue := range r.Issues {
		switch issue.Severity {
		case SeverityCritical:
			score -= 40
		case SeverityHigh:
			score -= 25
		case SeverityMedium:
			score -= 15
		case SeverityLow:
			score -= 5
		case SeverityInfo:
			score -= 0 // Info doesn't reduce score
		}
	}
	if score < 0 {
		score = 0
	}
	r.Score = score

	// Determine grade
	switch {
	case score >= 90:
		r.Grade = "A"
	case score >= 80:
		r.Grade = "B"
	case score >= 70:
		r.Grade = "C"
	case score >= 60:
		r.Grade = "D"
	default:
		r.Grade = "F"
	}
}

// FormatSummary returns a human-readable summary of the audit result.
func (r *Result) FormatSummary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n=== CORS Audit: %s ===\n", r.URL))
	sb.WriteString(fmt.Sprintf("Status Code: %d\n", r.StatusCode))
	sb.WriteString(fmt.Sprintf("CORS Score: %d/100 (Grade: %s)\n", r.Score, r.Grade))

	if len(r.Issues) == 0 {
		sb.WriteString("No issues found — CORS configuration looks good!\n")
	} else {
		sb.WriteString(fmt.Sprintf("\nFound %d issue(s):\n\n", len(r.Issues)))
		for i, issue := range r.Issues {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n", i+1, issue.Severity, issue.Message))
			if issue.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("     Fix: %s\n", issue.Suggestion))
			}
		}
	}

	return sb.String()
}
