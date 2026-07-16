// Package main provides the corslens CLI entry point.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/EdgarOrtegaRamirez/corslens/internal/audit"
	"github.com/EdgarOrtegaRamirez/corslens/internal/report"
	"github.com/EdgarOrtegaRamirez/corslens/pkg/scan"
)

var (
	outputFormat string
	timeout      int
	urlFile      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "corslens [flags] <url>...",
		Short: "CORS Policy Analyzer — Inspect and audit CORS headers",
		Long: `CORSLens is a CLI tool for analyzing and auditing CORS (Cross-Origin Resource Sharing)
policies. It fetches CORS headers from any URL and produces a security report
with severity-graded issues and actionable suggestions.

Examples:
  corslens https://api.example.com
  corslens -f urls.txt
  corslens https://api.example.com https://cdn.example.com
  corslens --format json https://api.example.com`,
		Args: cobra.MinimumNArgs(0),
		RunE: runMain,
	}

	rootCmd.Flags().StringVarP(&outputFormat, "format", "o", "text", "Output format: text, json")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.Flags().StringVarP(&urlFile, "file", "f", "", "Read URLs from file (one per line)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runMain(cmd *cobra.Command, args []string) error {
	var urls []string

	// URLs from file
	if urlFile != "" {
		fileURLs, err := scan.ParseURLsFromFile(urlFile)
		if err != nil {
			return fmt.Errorf("failed to read URLs from file: %w", err)
		}
		urls = append(urls, fileURLs...)
	}

	// URLs from command line
	urls = append(urls, args...)

	if len(urls) == 0 {
		cmd.Usage()
		return nil
	}

	// Normalize URLs (add https:// if missing)
	for i, url := range urls {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			urls[i] = "https://" + url
		}
	}

	cfg := &scan.ScanningConfig{
		Timeout:      time.Duration(timeout) * time.Second,
		MaxRedirects: 5,
	}

	results := scan.ScanURLs(cfg, urls)
	output := report.Format(results, outputFormat)
	fmt.Print(output)

	// Exit with non-zero if any critical issues found
	for _, r := range results {
		for _, issue := range r.Issues {
			if issue.Severity == audit.SeverityCritical {
				os.Exit(1)
			}
		}
	}

	return nil
}
