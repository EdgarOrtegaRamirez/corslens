# CORSLens

**CORS Policy Analyzer** — Inspect and audit CORS headers on any URL, detect security issues, and generate compliance reports.

CORSLens fetches CORS headers from any URL (via OPTIONS preflight and GET requests), parses `Access-Control-Allow-*` headers, detects security issues, and outputs a compliance report with severity scores and actionable suggestions.

## Features

- **Preflight & GET scanning** — Tries OPTIONS preflight first, falls back to GET request
- **Security audit** — Detects 8+ CORS security anti-patterns
- **Severity grading** — Issues rated CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Compliance scoring** — 0-100 score with A-F grade
- **Multiple output formats** — Human-readable text or machine-parseable JSON
- **Batch scanning** — Scan multiple URLs from command line or file
- **Configurable timeout** — Adjust request timeout for slow servers

## Installation

```bash
go install github.com/EdgarOrtegaRamirez/corslens/cmd/corslens@latest
```

Or build from source:

```bash
git clone https://github.com/EdgarOrtegaRamirez/corslens.git
cd corslens
go build -o corslens ./cmd/corslens/
```

## Usage

### Scan a single URL

```bash
corslens https://api.example.com
```

### Scan multiple URLs

```bash
corslens https://api.example.com https://cdn.example.com
```

### Scan from file (one URL per line)

```bash
corslens -f urls.txt
```

### JSON output (for CI/CD)

```bash
corslens --format json https://api.example.com
```

### Custom timeout

```bash
corslens -t 30 https://slow-api.example.com
```

## Example Output

```
=== CORS Audit: https://api.example.com ===
Status Code: 200
CORS Score: 65/100 (Grade: D)

Found 3 issue(s):

  1. [MEDIUM] Wildcard origin (*) allows any domain to make cross-origin requests
     Fix: Specify explicit allowed origins for better security
  2. [LOW] No Access-Control-Max-Age header — browser must send preflight every time
     Fix: Add Access-Control-Max-Age: 86400 to cache preflight responses for 24 hours
  3. [INFO] No Access-Control-Expose-Headers — client can only access safe headers
     Fix: Add specific headers you want the client to read with Access-Control-Expose-Headers
```

## Security Checks

CORSLens detects the following issues:

| Code | Severity | Description |
|------|----------|-------------|
| `WILDCARD_WITH_CREDENTIALS` | CRITICAL | Wildcard origin with credentials enabled |
| `OVERLY_PERMISSIVE_METHODS` | HIGH | Too many HTTP methods including unsafe ones |
| `WILDCARD_HEADERS` | HIGH | Wildcard (*) allowed headers |
| `WILDCARD_ORIGIN` | MEDIUM | Wildcard origin allows any domain |
| `SPECIFIC_ORIGIN_PERMISSIVE_METHODS` | MEDIUM | Specific origin but all methods allowed |
| `NO_MAX_AGE` | LOW | No max-age header causes excessive preflight |
| `SHORT_MAX_AGE` | LOW | Max-age too short for practical use |
| `NO_EXPOSED_HEADERS` | INFO | No exposed headers defined |
| `NO_RESPONSE` | CRITICAL | No CORS headers found at all |

## CI/CD Integration

Use JSON output for automated checks:

```yaml
- name: Check CORS headers
  run: |
    corslens --format json https://api.example.com > cors-report.json
    # Exit 1 if any CRITICAL issues found
```

## License

MIT — See [LICENSE](LICENSE) for details.
