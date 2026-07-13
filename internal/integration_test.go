package internal

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_DNSFunctionality(t *testing.T) {
	// App configuration for integration test
	app := App{
		Logger:         slog.Default(),
		DevMode:        true,
		DnsPort:        8053,
		DotPort:        8853,
		HttpPort:       8080, // Fixed port for DoH tests
		Upstreams:      []string{"8.8.8.8", "1.1.1.1"},
		BlockListURLs:  []string{"file://../data/blocklist.txt"},
		AllowedHosts:   []string{"127.0.0.1"},
		NoiseFilterURL: "file://../data/noise-filter.csv",
		DataDir:        "../data",
		DisableIpinfo:  true,
		MaxCacheSize:   1000,
		CronSchedule: struct {
			Downloader  string `json:"downloader"`
			CacheReaper string `json:"cache_reaper"`
			IPInfo      string `json:"ipinfo"`
		}{
			Downloader:  "@every 19h",
			CacheReaper: "0 3 * * *",
			IPInfo:      "5 7 4 * *",
		},
	}

	ctx := t.Context()

	// RunServer will return when ctx is cancelled, but it starts multiple servers in a group.
	// We need to run it in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer(ctx)
	}()

	// Wait for the server to start by polling the TCP port
	start := time.Now()
	for {
		select {
		case err := <-errCh:
			t.Fatalf("RunServer exited unexpectedly: %v", err)
		default:
		}

		conn, err := net.DialTimeout("tcp", "127.0.0.1:8053", 50*time.Millisecond)
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
			port:          8053,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "UDP - Blocked Domain",
			protocol:      "udp",
			port:          8053,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "TCP - Good Domain",
			protocol:      "tcp",
			port:          8053,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "TCP - Blocked Domain",
			protocol:      "tcp",
			port:          8053,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoT (Plain) - Good Domain",
			protocol:      "tcp",
			port:          8853,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoT (Plain) - Blocked Domain",
			protocol:      "tcp",
			port:          8853,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoH GET - Good Domain",
			protocol:      "doh-get",
			port:          8080,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoH GET - Blocked Domain",
			protocol:      "doh-get",
			port:          8080,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
		{
			name:          "DoH POST - Good Domain",
			protocol:      "doh-post",
			port:          8080,
			domain:        "google.com.",
			expectBlocked: false,
		},
		{
			name:          "DoH POST - Blocked Domain",
			protocol:      "doh-post",
			port:          8080,
			domain:        "doubleclick.net.",
			expectBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *dns.Msg
			var err error

			if tt.protocol == "doh-get" || tt.protocol == "doh-post" {
				msg := new(dns.Msg)
				msg.SetQuestion(tt.domain, dns.TypeA)
				packed, err := msg.Pack()
				require.NoError(t, err)

				var httpResp *http.Response
				var httpErr error

				if tt.protocol == "doh-get" {
					encoded := base64.RawURLEncoding.EncodeToString(packed)
					url := fmt.Sprintf("http://127.0.0.1:%d/dns-query?dns=%s", tt.port, encoded)
					httpResp, httpErr = http.Get(url)
				} else {
					url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", tt.port)
					httpResp, httpErr = http.Post(url, "application/dns-message", bytes.NewReader(packed))
				}

				require.NoError(t, httpErr, "HTTP request failed")
				defer func() { _ = httpResp.Body.Close() }()
				require.Equal(t, http.StatusOK, httpResp.StatusCode)

				body, err := io.ReadAll(httpResp.Body)
				require.NoError(t, err)

				resp = new(dns.Msg)
				err = resp.Unpack(body)
				require.NoError(t, err, "Failed to unpack DNS response from DoH")
			} else {
				msg := new(dns.Msg)
				msg.SetQuestion(tt.domain, dns.TypeA)

				client := &dns.Client{
					Net:     tt.protocol,
					Timeout: 2 * time.Second,
				}

				addr := fmt.Sprintf("127.0.0.1:%d", tt.port)
				resp, _, err = client.Exchange(msg, addr)
				require.NoError(t, err, "DNS exchange failed")
			}

			require.NotNil(t, resp, "DNS response is nil")

			if tt.expectBlocked {
				// Based on internal/forwarder/dispatcher.go, blocked domains return a SOA record with ns.blocked.local.
				foundBlockedSOA := false
				for _, ans := range resp.Answer {
					if soa, ok := ans.(*dns.SOA); ok {
						if soa.Ns == "ns.blocked.local." {
							foundBlockedSOA = true
							break
						}
					}
				}
				assert.True(t, foundBlockedSOA, "Expected blocked SOA record for %s", tt.domain)
			} else {
				assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Expected NOERROR for %s", tt.domain)
				assert.NotEmpty(t, resp.Answer, "Expected answers for %s", tt.domain)
			}
		})
	}
}
