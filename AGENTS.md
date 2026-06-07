# Project Context: DoT Block

## Overview
A DNS-over-TLS (DoT) server written in Go. Acts as a secure DNS forwarder with ad/tracker blocking.

## Core Architecture
- **DNS Logic:** Managed by `DNSDispatcher`.
- **DNS Server:** UDP/TCP (configurable port).
- **DoT Server:** TLS-encrypted (port 853), uses `miekg/dns`.
- **HTTP Server:** `gin-gonic/gin`, handles ACME http-01 challenges.
- **CLI:** `cobra`.
- **Observability:** Sentry (errors), Prometheus (metrics).

## Development Principles
- **Test-First:** Always verify existing behavior with tests and write failing tests before implementing changes. Use `github.com/stretchr/testify` for assertions.
- **Verify:** ALWAYS run a full build (`go build ./...`) and run tests (`go test ./...`) after making code changes to ensure no regressions.
- **Doc-Sync:** Whenever a feature, flag, or default value is changed, update the corresponding documentation (e.g., `README.md`) immediately.

## Development Workflow
### Run (Dev Mode)
Uses plain TCP instead of TLS for local testing.
```bash
go run main.go --dev-mode
```
- DNS: `8053`
- DoT (plain TCP): `8853`

### Test
```bash
go test -v ./...
```

### Build
```bash
go build -ldflags="-w -s" -o dot-block .
```

## Key Technologies
- **Language:** Go
- **Libraries:** `miekg/dns`, `gin-gonic/gin`, `cobra`
- **Containerization:** Docker / Docker Compose
