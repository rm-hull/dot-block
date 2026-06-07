# DoT Block

DoT Block is a high-performance, caching, and filtering DNS-over-TLS (DoT) server written in Go. It acts as a secure DNS forwarder, encrypting your DNS queries and protecting you from advertisers, trackers, and malicious domains.

## Features

-   **DNS-over-TLS:** Encrypts your DNS queries to keep them private.
-   **Regular DNS:** Supports standard UDP and TCP DNS queries (optional, disabled by default).
-   **Ad & Tracker Blocking:** Blocks a wide range of unwanted domains using customizable blocklists.
-   **High Performance:** Built with Go for speed and efficiency.
-   **Intelligent Caching:** Caches DNS responses to speed up subsequent lookups with configurable TTL flooring.
-   **Easy to Deploy:** Can be run as a standalone binary or as a Docker container.
-   **Automatic TLS:** Uses Let's Encrypt to automatically obtain and renew TLS certificates.
-   **Advanced Observability:** Exports detailed Prometheus metrics including upstream health, failure reasons, and cache effectiveness.
-   **Distributed Tracing:** Integrates with OpenTelemetry (OTel), providing end-to-end traces of DNS requests and correlating them with logs via `trace_id` and `span_id`.
-   **Noise-Reduced Error Reporting:** Integrates with Sentry, with intelligent filtering to avoid logging protocol-valid negative responses (like NXDOMAIN or NOTIMP) as errors.
-   **Proxy Protocol Support:** Supports PROXY protocol for DoT connections, enabling correct client IP identification when running behind a proxy.

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

#### Production Tuning

For high-traffic environments, you may need to tune the network stack to avoid port exhaustion and packet loss. You can apply these settings directly in your `docker-compose.yml` using `sysctls`:

```yaml
services:
  dot-block:
    # ... other configuration ...
    sysctls:
      - net.ipv4.ip_local_port_range=1024 65535
      - net.core.rmem_max=26214400
      - net.core.wmem_max=26214400
```

- `net.ipv4.ip_local_port_range`: Expands the ephemeral port range to allow more concurrent outgoing UDP requests.
- `net.core.rmem_max` & `net.core.wmem_max`: Increases the maximum OS receive and send buffer sizes for UDP to prevent packet drops during traffic spikes.

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
    The DNS server (UDP/TCP) will be listening on port `8053`, DoT (plain TCP) on `8853`, and the HTTP server on port `8080`.

## Usage

You can test the server using `dig` or `openssl`.

### `dig`

**Regular DNS (UDP/TCP, if configured):**

```bash
dig @dot.your-domain.com -p <DNS_PORT> example.com A
```

**Production (TLS):**

```bash
dig @dot.your-domain.com -p 853 +tls example.com A
```

Note that the bundled `dig` binary in MacOS doesn't support the `+tls` options, so use an alternative like [kdig](https://www.knot-dns.cz/docs/2.6/html/man_kdig.html) instead.

**Local Development:**

```bash
# Regular DNS (UDP)
dig @127.0.0.1 -p 8053 www.google.com A

# Regular DNS (TCP)
dig @127.0.0.1 -p 8053 www.google.com A +tcp

# DoT (plain TCP)
dig @127.0.0.1 -p 8853 www.google.com A +tcp
```

### `openssl`

```bash
openssl s_client -connect dot.your-domain.com:853 -alpn dot -servername dot.your-domain.com
```

### Management API

The server provides several HTTP endpoints for monitoring and management on the configured `--http-port` (default 80).

- `GET /metrics`: Exports Prometheus metrics.
- `GET /reload`: Triggers an asynchronous reload of the blocklists.
- `POST /check`: Checks whether provided domains are blocked. Accepts a JSON array of strings or a newline-separated list of domains in the request body.

If `--metrics-auth` is configured, `/metrics` and `/reload` are protected by basic authentication.

### iOS / iPadOS Configuration

To use DoT Block on your iPhone or iPad, you can install a configuration profile directly from the server:

1.  Open Safari on your iOS device.
2.  Navigate to `https://dot.your-domain.com/.mobileconfig`.
3.  Tap **Allow** when prompted to download the configuration profile.
4.  Open the **Settings** app.
5.  Tap **Profile Downloaded** near the top.
6.  Tap **Install** in the top right corner and follow the prompts.
7.  Once installed, your device will use DoT Block for all DNS queries.

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

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--allowed-hosts` | List of domains used for the CertManager allow policy. | `nil` |
| `--blocklist-url` | List of URL blocklists (wildcard hostname format). | `https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/hosts/pro.txt`, `https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/blocklist.txt` |
| `--cache-ttl-floor` | Minimum TTL for cached entries (in seconds). If a response is not "freshness sensitive" (e.g. contains `ocsp`, `crl`, `pki` or is `SOA`/`TXT`), the cache TTL will be at least this value. | `3600s` |
| `--dial-timeout` | Timeout for establishing TCP connections to upstream servers | `300ms` |
| `--read-timeout` | Timeout for waiting for responses from upstream DNS servers | `300ms` |
| `--write-timeout` | Timeout for writing upstream DNS queries | `100ms` |
| `--cron-schedule:cache-reaper` | Cron spec for cache reaper. | `0 3 * * *` (3:00am every day) |
| `--cron-schedule:downloader` | Cron spec for reloading blocklist. | `@every 19h` |
| `--cron-schedule:ip2location` | Cron spec for fetching IP2Location db. | `5 7 4 * *` (7:05am on the 4th of every month) |
| `--data-dir` | Directory for persisting data (e.g. TLS certificate cache). | `./data` |
| `--dev-mode` | Run the server in dev mode (no TLS, plain TCP). | `false` |
| `--dns-port` | The port to run regular DNS (UDP/TCP) server on. If omitted, the regular DNS server will not start. | `0` |
| `--dot-port` | The port to run DNS-over-TLS server on. | `853` |
| `--http-port` | The port to run the HTTP server on. | `80` |
| `--log-level` | The log level (DEBUG, INFO, WARN, ERROR). | `INFO` |
| `--metrics-auth` | Credentials for basic auth on `/metrics` (format: `user:pass`). | `""` |
| `--require-proxy-protocol` | Require PROXY protocol header for DoT connections. | `false` |
| `--trusted-proxies` | Comma-separated list of trusted proxy IP addresses or CIDR ranges. | `nil` |
| `--upstreams` | Upstream DNS resolvers to forward queries to. (Port 53 is assumed if omitted) | `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9`, `149.112.112.112` |

### Environment Variables

| Variable | Description | Required |
| :--- | :--- | :--- |
| `ACME_EMAIL` | Email address used for Let's Encrypt registration. | Yes (in production) |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token for DNS-01 challenge (CertManager). | Yes (in production) |
| `DEV_MODE` | Set to `true` to enable development mode (disables TLS). | No |
| `IP2LOCATION_TOKEN` | IP2Location token for downloading geoIP locations. | Yes |
| `SENTRY_DSN` | DSN for Sentry error reporting. | No |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry OTLP gRPC endpoint (e.g. `localhost:4317`). | No |
| `OTEL_SAMPLING_RATIO` | Ratio of traces to sample (0.0 to 1.0). Defaults to `0.01` (1%). | No |

## Grafana Dashboard

A [dashboard.json](./dashboard.json) is available for importing into Grafana:

![dashboard screenshot](./docs/grafana.png)

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
