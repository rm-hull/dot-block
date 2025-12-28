package main

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func BenchmarkDoTQueryMultipleHosts(b *testing.B) {
	server := "dot.destructuring-bind.org:853"
	tlsConfig := &tls.Config{
		ServerName: "dot.destructuring-bind.org",
		NextProtos: []string{"dot"},
	}

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
	}

	hosts := []string{
		"www.google.com.",
		"www.facebook.com.",
		"www.github.com.",
		"www.cloudflare.com.",
		"www.stackoverflow.com.",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qname := hosts[i%len(hosts)]

		msg := new(dns.Msg)
		msg.SetQuestion(qname, dns.TypeA)

		_, _, err := client.Exchange(msg, server)
		if err != nil {
			b.Fatalf("Query %d (%s) failed: %v", i, qname, err)
		}
	}
}

func BenchmarkDoTQueryConcurrent(b *testing.B) {
	server := "dot.destructuring-bind.org:853"
	tlsConfig := &tls.Config{
		ServerName: "dot.destructuring-bind.org",
		NextProtos: []string{"dot"},
	}

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   5 * time.Second,
	}

	hosts := []string{
		"www.google.com.",
		"www.facebook.com.",
		"www.github.com.",
		"www.cloudflare.com.",
		"www.stackoverflow.com.",
	}

	concurrency := 10
	var successCount int64
	var failureCount int64
	latencies := make([]time.Duration, 0, b.N)
	var latenciesMu sync.Mutex

	jobs := make(chan int, b.N)

	// Pre-fill jobs
	for i := 0; i < b.N; i++ {
		jobs <- i
	}
	close(jobs)

	b.ResetTimer()
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				qname := hosts[j%len(hosts)]

				msg := new(dns.Msg)
				msg.SetQuestion(qname, dns.TypeA)

				start := time.Now()
				_, _, err := client.Exchange(msg, server)
				elapsed := time.Since(start)

				if err != nil {
					atomic.AddInt64(&failureCount, 1)
					b.Logf("Query %d (%s) failed: %v", j, qname, err)
				} else {
					atomic.AddInt64(&successCount, 1)
					latenciesMu.Lock()
					latencies = append(latencies, elapsed)
					latenciesMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	b.StopTimer()

	// Calculate average latency
	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}
	avgLatency := time.Duration(0)
	if len(latencies) > 0 {
		avgLatency = totalLatency / time.Duration(len(latencies))
	}

	fmt.Printf("\nBenchmark summary:\n")
	fmt.Printf("  Total queries: %d\n", b.N)
	fmt.Printf("  Successful queries: %d\n", successCount)
	fmt.Printf("  Failed queries: %d\n", failureCount)
	fmt.Printf("  Average latency: %v\n", avgLatency)
}
