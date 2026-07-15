# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in CORSLens, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email: [security reporting channel] or open a private security advisory on GitHub
3. Include steps to reproduce and impact assessment

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Measures

- CORSLens only performs read-only HTTP requests
- No data is stored or transmitted to third parties
- Request timeouts prevent hanging on unresponsive servers
- No network ports are opened for listening
