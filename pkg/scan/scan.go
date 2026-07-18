// Package scan provides the scanning engine for CORS auditing.
package scan

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/corslens/internal/audit"
	"github.com/EdgarOrtegaRamirez/corslens/internal/cors"
)

// ScanningConfig holds options for the scanner.
type ScanningConfig struct {
	Timeout      time.Duration
	MaxRedirects int
}

// DefaultConfig returns a scanning config with sensible defaults.
func DefaultConfig() *ScanningConfig {
	return &ScanningConfig{
		Timeout:      10 * time.Second,
		MaxRedirects: 5,
	}
}

// ScanURL performs a CORS audit on the given URL.
func ScanURL(cfg *ScanningConfig, url string) (*audit.Result, error) {
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("too many redirects (%d)", cfg.MaxRedirects)
			}
			return nil
		},
	}

	// Try OPTIONS preflight first
	corsCfg := tryScan(client, url, "OPTIONS")
	if corsCfg != nil && corsCfg.StatusCode != 0 {
		return audit.AuditCORS(url, corsCfg), nil
	}

	// Try GET request
	corsCfg = tryScan(client, url, "GET")
	if corsCfg != nil && corsCfg.StatusCode != 0 {
		return audit.AuditCORS(url, corsCfg), nil
	}

	// No CORS headers found
	return audit.AuditCORS(url, cors.ParseCORSHeadersFromMap(map[string]string{}, 0)), nil
}

// ScanURLs scans multiple URLs and returns results.
func ScanURLs(cfg *ScanningConfig, urls []string) []*audit.Result {
	results := make([]*audit.Result, 0, len(urls))

	for _, url := range urls {
		result, err := ScanURL(cfg, url)
		if err != nil {
			results = append(results, &audit.Result{
				URL:   url,
				Score: 0,
				Grade: "E",
				Issues: []audit.Issue{
					{Severity: audit.SeverityCritical, Code: "SCAN_ERROR", Message: fmt.Sprintf("Scan failed: %v", err)},
				},
			})
			continue
		}
		results = append(results, result)
	}

	return results
}

// ParseURLsFromFile reads URLs from a file, one per line.
func ParseURLsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func tryScan(client *http.Client, url, method string) *cors.CORSConfig {
	var body io.Reader
	if method == "OPTIONS" {
		body = strings.NewReader("")
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil
	}

	if method == "OPTIONS" {
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	return cors.ParseCORSHeaders(resp)
}
