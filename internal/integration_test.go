package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func TestIntegration_DNSFunctionality(t *testing.T) {
	// Pick 3 free ports for the test
	dnsPort := getFreePort(t)
	dotPort := getFreePort(t)
	httpPort := getFreePort(t)

	// App configuration for integration test
	cfg := config.DefaultConfig()
	cfg.Server.DevMode = true
	cfg.Server.DnsPort = dnsPort
	cfg.Server.DotPort = dotPort
	cfg.Server.HttpPort = httpPort
	cfg.Server.LetsEncrypt.AllowedHosts = []string{"127.0.0.1"}
	cfg.Server.DataDir = "../data"
	cfg.DNS.Upstreams = []string{"8.8.8.8", "1.1.1.1"}
	cfg.Blocklist.Sources = []config.BlocklistSource{
		{Name: "dot-block", URL: "file://../data/blocklist.txt", CronSchedule: "@every 19h"},
	}
	cfg.DNS.NoiseFilter.URL = "file://../data/noise-filter.csv"
	cfg.DNS.NoiseFilter.CronSchedule = "@every 19h"
	cfg.Geoblock.Ipinfo.Enabled = false
	cfg.DNS.Cache.MaxSize = 1000
	cfg.DNS.Cache.CronSchedule = "0 3 * * *"
	cfg.Geoblock.Ipinfo.CronSchedule = "5 7 4 * *"

	app := App{
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Config: cfg,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// RunServer will return when ctx is cancelled, but it starts multiple servers in a group.
	// We need to run it in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer(ctx)
	}()

	// Wait for the server to start by polling the DNS TCP port
	start := time.Now()
	for {
		select {
		case err := <-errCh:
			// Check if it's a port already in use error
			if err != nil && (strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "bind: address already in use")) {
				t.Fatalf("Port already in use: %v", err)
			}
			t.Fatalf("RunServer exited unexpectedly: %v", err)
		default:
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dnsPort), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("Server failed to start within 5 seconds")
		}
		time.Sleep(100 * time.Millisecond)
	}

	tests := []struct {
		name          string
		protocol      string // "udp", "tcp", "dot", "doh-get", "doh-post"
		port          int
		domain        string
		expectBlocked bool
	}{
		{
			name:          "UDP - Good Domain",
			protocol:      "udp",
			port:          dnsPort,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "UDP - Blocked Domain",
			protocol:      "udp",
			port:          dnsPort,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "TCP - Good Domain",
			protocol:      "tcp",
			port:          dnsPort,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "TCP - Blocked Domain",
			protocol:      "tcp",
			port:          dnsPort,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoT (Plain) - Good Domain",
			protocol:      "tcp",
			port:          dotPort,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoT (Plain) - Blocked Domain",
			protocol:      "tcp",
			port:          dotPort,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoH GET - Good Domain",
			protocol:      "doh-get",
			port:          httpPort,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoH GET - Blocked Domain",
			protocol:      "doh-get",
			port:          httpPort,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoH POST - Good Domain",
			protocol:      "doh-post",
			port:          httpPort,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoH POST - Blocked Domain",
			protocol:      "doh-post",
			port:          httpPort,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
	}

	// sendQuery sends a DNS query using the specified protocol and returns the response.
	// It is extracted as a helper to support retry logic for blocked-domain tests,
	// since the initial blocklist fetch is now asynchronous and may not have completed
	// by the time the DNS server starts accepting connections.
	sendQuery := func(t *testing.T, protocol string, port int, domain string) *dns.Msg {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeA)

		if protocol == "doh-get" || protocol == "doh-post" {
			packed, err := msg.Pack()
			require.NoError(t, err)

			var httpResp *http.Response
			var httpErr error

			if protocol == "doh-get" {
				encoded := base64.RawURLEncoding.EncodeToString(packed)
				url := fmt.Sprintf("http://127.0.0.1:%d/dns-query?dns=%s", port, encoded)
				httpResp, httpErr = http.Get(url)
			} else {
				url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", port)
				httpResp, httpErr = http.Post(url, "application/dns-message", bytes.NewReader(packed))
			}

			require.NoError(t, httpErr, "HTTP request failed")
			defer func() { _ = httpResp.Body.Close() }()
			require.Equal(t, http.StatusOK, httpResp.StatusCode)

			body, err := io.ReadAll(httpResp.Body)
			require.NoError(t, err)

			resp := new(dns.Msg)
			err = resp.Unpack(body)
			require.NoError(t, err, "Failed to unpack DNS response from DoH")
			return resp
		}

		client := &dns.Client{
			Net:     protocol,
			Timeout: 2 * time.Second,
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		resp, _, err := client.Exchange(msg, addr)
		require.NoError(t, err, "DNS exchange failed")
		return resp
	}

	// isBlocked checks whether the DNS response contains a blocked SOA record.
	isBlocked := func(resp *dns.Msg) bool {
		for _, rr := range append(resp.Answer, resp.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok {
				if soa.Ns == "ns.blocked.local." {
					return true
				}
			}
		}
		return false
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendQuery(t, tt.protocol, tt.port, tt.domain)
			require.NotNil(t, resp, "DNS response is nil")

			if tt.expectBlocked {
				// The initial blocklist fetch is asynchronous, so the bloom filter may not
				// be populated yet. Retry the query a few times to allow the background
				// fetch to complete.
				foundBlockedSOA := false
				for attempt := 0; attempt < 10; attempt++ {
					if isBlocked(resp) {
						foundBlockedSOA = true
						break
					}
					time.Sleep(200 * time.Millisecond)
					resp = sendQuery(t, tt.protocol, tt.port, tt.domain)
				}
				assert.True(t, foundBlockedSOA, "Expected blocked SOA record for %s", tt.domain)
			} else {
				assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Expected NOERROR for %s", tt.domain)
				assert.NotEmpty(t, resp.Answer, "Expected answers for %s", tt.domain)
			}
		})
	}
}
