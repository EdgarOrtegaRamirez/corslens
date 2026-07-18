// Package report provides output formatting for CORS audit results.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/EdgarOrtegaRamirez/corslens/internal/audit"
)

// Format formats the audit results in the specified output format.
func Format(results []*audit.Result, format string) string {
	switch format {
	case "json":
		return formatJSON(results)
	case "text":
		return formatText(results)
	default:
		return formatText(results)
	}
}

func formatText(results []*audit.Result) string {
	var sb strings.Builder

	if len(results) == 1 {
		sb.WriteString(results[0].FormatSummary())
	} else {
		sb.WriteString(fmt.Sprintf("=== CORS Audit Report (%d URL(s)) ===\n\n", len(results)))

		// Summary table
		w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "URL\tStatus\tScore\tGrade\tIssues")
		fmt.Fprintln(w, "----\t------\t-----\t-----\t------")
		for _, r := range results {
			issueCount := len(r.Issues)
			fmt.Fprintf(w, "%s\t%d\t%d/100\t%s\t%d\n",
				r.URL, r.StatusCode, r.Score, r.Grade, issueCount)
		}
		w.Flush()

		// Detailed issues
		for _, r := range results {
			if len(r.Issues) > 0 {
				sb.WriteString(fmt.Sprintf("\n--- %s (Score: %d/100, Grade: %s) ---\n",
					r.URL, r.Score, r.Grade))
				for _, issue := range r.Issues {
					sb.WriteString(fmt.Sprintf("  [%s] %s\n", issue.Severity, issue.Message))
					if issue.Suggestion != "" {
						sb.WriteString(fmt.Sprintf("    → %s\n", issue.Suggestion))
					}
				}
			}
		}
	}

	return sb.String()
}

func formatJSON(results []*audit.Result) string {
	type JSONIssue struct {
		Severity   string `json:"severity"`
		Code       string `json:"code"`
		Message    string `json:"message"`
		Suggestion string `json:"suggestion,omitempty"`
	}

	type JSONResult struct {
		URL        string      `json:"url"`
		StatusCode int         `json:"status_code"`
		Score      int         `json:"score"`
		Grade      string      `json:"grade"`
		Issues     []JSONIssue `json:"issues"`
	}

	jsonResults := make([]JSONResult, len(results))
	for i, r := range results {
		issues := make([]JSONIssue, len(r.Issues))
		for j, issue := range r.Issues {
			issues[j] = JSONIssue{
				Severity:   string(issue.Severity),
				Code:       issue.Code,
				Message:    issue.Message,
				Suggestion: issue.Suggestion,
			}
		}
		jsonResults[i] = JSONResult{
			URL:        r.URL,
			StatusCode: r.StatusCode,
			Score:      r.Score,
			Grade:      r.Grade,
			Issues:     issues,
		}
	}

	data, _ := json.MarshalIndent(jsonResults, "", "  ")
	return string(data) + "\n"
}
