package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_DNSFunctionality(t *testing.T) {
	// App configuration for integration test
	app := App{
		Logger:             slog.Default(),
		DevMode:            true,
		DnsPort:            8053,
		DotPort:            8853,
		HttpPort:           0, // Random port
		Upstreams:          []string{"8.8.8.8", "1.1.1.1"},
		BlockListURLs:      []string{"file://../data/blocklist.txt"},
		AllowedHosts:       []string{"example.com"},
		DataDir:            "../data",
		DisableIp2Location: true,
		MaxCacheSize:       1000,
		CronSchedule: struct {
			Downloader  string `json:"downloader"`
			CacheReaper string `json:"cache_reaper"`
			IP2Location string `json:"ip2location"`
		}{
			Downloader:  "@every 19h",
			CacheReaper: "0 3 * * *",
			IP2Location: "5 7 4 * *",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// RunServer will return when ctx is cancelled, but it starts multiple servers in a group.
	// We need to run it in a goroutine.
	go func() {
		if err := app.RunServer(ctx); err != nil {
			t.Errorf("RunServer failed: %v", err)
		}
	}()

	// Wait for the server to start by polling the TCP port
	start := time.Now()
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8053", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatal("Server failed to start within 30 seconds")
		}
		time.Sleep(500 * time.Millisecond)
	}

	tests := []struct {
		name          string
		protocol      string // "udp", "tcp", "dot"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(tt.domain, dns.TypeA)

			var resp *dns.Msg
			var err error

			client := &dns.Client{
				Net:     tt.protocol,
				Timeout: 2 * time.Second,
			}

			addr := fmt.Sprintf("127.0.0.1:%d", tt.port)
			resp, _, err = client.Exchange(msg, addr)

			require.NoError(t, err, "DNS exchange failed")
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
