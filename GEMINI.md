# GEMINI.md

## Project Overview

This project is a DNS-over-TLS (DoT) server written in Go. It acts as a secure DNS forwarder, receiving DNS queries over a TLS-encrypted connection and forwarding them to an upstream DNS resolver.

The core components are:
- A `DNSDispatcher` struct encapsulates DNS forwarding logic for better modularity and shared data management.
- A DoT server built using the `miekg/dns` library, listening on port 853.
- An HTTP server using `gin-gonic/gin` to handle ACME http-01 challenges from Let's Encrypt for automatic TLS certificate acquisition.
- Command-line interface managed by `cobra`.
- Containerization using Docker and Docker Compose.

The server can be run in a "dev mode" which uses plain TCP instead of TLS for easier local testing.

## Building and Running

### Local Development

To run the server locally in development mode (no TLS on port 8053):

```bash
go run main.go --dev-mode
```

You can then test the server with `dig`:

```bash
dig @127.0.0.1 -p 8053 www.google.com A +tcp
```

### Docker

The project is designed to be run as a Docker container.

To build and run the container:

```bash
docker-compose up --build -d
```

The `docker-compose.yml` file is configured to use `dockflare` to automatically expose the DNS service and handle TLS termination for the DoT service via a Cloudflare Tunnel.

### Building from Source

To build the binary directly:

```bash
go build -tags=jsoniter -ldflags="-w -s" -o dot-block .
```

### Testing

The repository includes benchmark tests. To run them:

```bash
go test -bench=.
```

You can also test the deployed DoT server using `openssl` or `dig` as described in the `README.md`.

## Development Conventions

- **Dependencies:** Go modules are used for dependency management. Key libraries include `miekg/dns`, `gin-gonic/gin`, and `cobra`.
- **Configuration:** Server behavior is configured via command-line flags.
- **Containerization:** A multi-stage `Dockerfile` is used to create a small, optimized runtime image.
- **API:** The primary interface is the DoT service on port 853. An HTTP server on port 80 is used for the ACME challenge.
