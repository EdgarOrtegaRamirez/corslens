# CORSLens — AI Agent Guide

## Overview

CORSLens is a CORS (Cross-Origin Resource Sharing) policy analyzer CLI tool. It inspects CORS headers on any URL, detects security issues, and produces a graded report.

## Building

```bash
go build -o corslens ./cmd/corslens/
```

## Running Tests

```bash
go test ./... -v
```

## Project Structure

- `cmd/corslens/` — CLI entry point using Cobra
- `internal/cors/` — CORS header parsing (origin, methods, headers, max-age)
- `internal/audit/` — Security analysis engine with severity scoring
- `internal/report/` — Output formatting (text, JSON)
- `pkg/scan/` — HTTP scanning engine (preflight + GET requests)

## Key Patterns

- Parsing: `cors.ParseCORSHeadersFromMap()` for testing, `cors.ParseCORSHeaders()` for real responses
- Auditing: `audit.AuditCORS(url, cfg)` returns `*audit.Result` with issues and score
- Scanning: `scan.ScanURL(cfg, url)` performs HTTP request + audit
- Reporting: `report.Format(results, format)` outputs text or JSON

## Adding a New Security Check

1. Add a new `Issue` in `internal/audit/audit.go`'s `AuditCORS()` function
2. Define a new severity constant if needed
3. Add a corresponding test in `internal/audit/audit_test.go`
4. Update README.md with the new check

## Testing Conventions

- Table-driven tests for parsing
- Unit tests for each audit rule
- Test both happy paths and edge cases
- Aim for >80% coverage
