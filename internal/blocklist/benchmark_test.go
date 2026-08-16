package blocklist

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
)

const nrd7AsteriskURL = "https://raw.githubusercontent.com/Cebeerre/dnsblocklists/refs/heads/main/NRD/nrd7_asterisk.txt"

// fetchNRD7Asterisk downloads the NRD 7 asterisk blocklist to a temp file
// and returns the path. The download happens outside the benchmark timer
// so it is not included in the measured performance.
func fetchNRD7Asterisk(b *testing.B) string {
	b.Helper()

	tmpDir := b.TempDir()
	path := filepath.Join(tmpDir, "nrd7_asterisk.txt")

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(nrd7AsteriskURL)
	if err != nil {
		b.Fatalf("failed to download blocklist: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b.Fatalf("unexpected HTTP status %d", resp.StatusCode)
	}

	f, err := os.Create(path)
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		b.Fatalf("failed to write temp file: %v", err)
	}

	return path
}

// BenchmarkBlocklist_ProcessFile benchmarks BlockList.processFile using a
// real-world blocklist (Hagezi's NRD 7 days wildcard list, ~2.6M entries,
// ~52 MB). The file is downloaded once to a temp directory before the
// benchmark begins; only the processing (file I/O, line counting, parsing,
// and bloom filter construction) is measured.
//
// Run with:  go test ./internal/blocklist/ -bench=BenchmarkBlocklist_ProcessFile -benchmem
// Skip in short mode: go test -short ...
func BenchmarkBlocklist_ProcessFile(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	path := fetchNRD7Asterisk(b)

	// Report throughput in terms of file size processed.
	info, err := os.Stat(path)
	if err != nil {
		b.Fatalf("failed to stat file: %v", err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	source := &config.BlocklistSource{Name: "nrd7_asterisk", URL: nrd7AsteriskURL}
	blockList := NewStaticBlockList(source, 0.0001, logger)

	b.ResetTimer()

	for b.Loop() {
		if err := blockList.processFile(path); err != nil {
			b.Fatalf("processFile failed: %v", err)
		}
	}
}
