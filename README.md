# DoT Block

DoT Block is a high-performance, caching, and filtering DNS-over-TLS (DoT) server written in Go. It acts as a secure DNS forwarder, encrypting your DNS queries and protecting you from advertisers, trackers, and malicious domains.

## Features

-   **DNS-over-TLS:** Encrypts your DNS queries to keep them private.
-   **Ad & Tracker Blocking:** Blocks a wide range of unwanted domains using customizable blocklists.
-   **High Performance:** Built with Go for speed and efficiency.
-   **Caching:** Caches DNS responses to speed up subsequent lookups.
-   **Easy to Deploy:** Can be run as a standalone binary or as a Docker container.
-   **Automatic TLS:** Uses Let's Encrypt to automatically obtain and renew TLS certificates.
-   **Prometheus Metrics:** Exports detailed metrics for monitoring.
-   **Error Reporting (Sentry):** Integrates with Sentry for real-time error tracking and reporting.

## Getting Started

### Docker (Recommended)

The easiest way to get started with DoT Block is to use Docker and Docker Compose.

1.  Clone this repository:
    ```bash
    git clone https://github.com/your-username/dot-block.git
    cd dot-block
    ```
2.  Update `docker-compose.yml` with your domain name and email address.
3.  Run the server:
    ```bash
    docker-compose up --build -d
    ```

The server will be accessible at `dot.your-domain.com`.

### Local Development

For local development, you can run the server in "dev mode", which uses plain TCP instead of TLS.

1.  Clone this repository:
    ```bash
    git clone https://github.com/your-username/dot-block.git
    cd dot-block
    ```
2.  Run the server:
    ```bash
    go run main.go --dev-mode --http-port=8080
    ```
    The DNS server will be listening on port `8053`, and HTTP server on port `8080`.

## Usage

You can test the server using `dig` or `openssl`.

### `dig`

**Production (TLS):**

```bash
dig @dot.your-domain.com -p 853 +tls example.com A
```

Note that the bundled `dig` binary in MacOS doesn't support the `+tls` options, so use an alternative like [kdig](https://www.knot-dns.cz/docs/2.6/html/man_kdig.html) instead.

**Local Development (no TLS):**

```bash
dig @127.0.0.1 -p 8053 www.google.com A +tcp
```

### `openssl`

```bash
openssl s_client -connect dot.your-domain.com:853 -alpn dot -servername dot.your-domain.com
```

## Building

To build the binary from source:

```bash
go build -ldflags="-w -s" -o dot-block .
```

## Testing

To run the tests:

```bash
go test ./...
```

## Configuration

DoT Block can be configured using the following command-line flags:

| Flag              | Description                                                     | Default                                                                                   |
| ----------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `--blocklist-url` | URL of the blocklist (wildcard hostname format).                | `https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro-onlydomains.txt` |
| `--cache-dir`     | Directory for the TLS certificate cache.                        | `./data/certcache`                                                                        |
| `--dev-mode`      | Run the server in dev mode (no TLS, plain TCP).                 | `false`                                                                                   |
| `--upstream`      | Upstream DNS resolver to forward queries to.                    | `1.1.1.1:53`                                                                              |
| `--http-port`     | The port to run the HTTP server on.                             | `80`                                                                                      |
| `--allowed-host`  | List of domains used for the CertManager allow policy.          | `nil`                                                                                     |
| `--metrics-auth`  | Credentials for basic auth on `/metrics` (format: `user:pass`). | `""`                                                                                      |

### Sentry Error Reporting

For error reporting, set the `SENTRY_DSN` environment variable. Not setting will deactivate remote error reporting.

```bash
export SENTRY_DSN="YOUR_SENTRY_DSN_HERE"
```

## Grafana Dashboard

A [dashboard.json](./dashboard.json) is available for importing into Grafana:

![dashboard screenshot](./docs/grafana.png)

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
