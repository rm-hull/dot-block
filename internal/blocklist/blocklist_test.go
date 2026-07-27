package blocklist

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBlocklist_DisableAndIsBlocked(t *testing.T) {
	// Use a dummy handler that won't panic when passed nil
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	// Create a blocklist with one entry
	blockList := NewBlockList("test", "http://dummy_url", 0.0001, logger)
	blockList.Load([]string{"example.com"})

	// Initially, example.com should be blocked
	isBlocked, err := blockList.IsBlocked("example.com")
	assert.NoError(t, err)
	assert.True(t, isBlocked, "example.com should be blocked initially")

	// Disable the blocklist for 1 second
	blockList.Disable(1 * time.Second)

	// Now example.com should not be blocked (but should log a warning)
	isBlocked, err = blockList.IsBlocked("example.com")
	assert.NoError(t, err)
	assert.False(t, isBlocked, "example.com should not be blocked when disabled")

	// Wait for the disable period to expire
	time.Sleep(2 * time.Second)

	// After the disable period, example.com should be blocked again
	isBlocked, err = blockList.IsBlocked("example.com")
	assert.NoError(t, err)
	assert.True(t, isBlocked, "example.com should be blocked again after disable period expires")
}

func TestBlocklist_Fetch(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// Create a temporary blocklist file with metadata and entries
	content := `# Title: Test Blocklist
# Author: Tester
#
0.0.0.0 ads.example.com tracker.example.com
127.0.0.1 badsite.org
*.malware.net
example.com
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "blocklist.txt")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	assert.NoError(t, err)

	blockList := NewBlockList("test", "file://"+tmpFile, 0.0001, logger)

	err = blockList.Fetch(t.Context())
	assert.NoError(t, err)

	// Verify hosts are blocked
	for _, host := range []string{"ads.example.com", "tracker.example.com", "badsite.org", "malware.net", "example.com"} {
		isBlocked, err := blockList.IsBlocked(host)
		assert.NoError(t, err)
		assert.True(t, isBlocked, "%s should be blocked", host)
	}

	// Verify metadata was extracted
	assert.Equal(t, "Test Blocklist", blockList.Metadata("title", ""))
	assert.Equal(t, "Tester", blockList.Metadata("author", ""))

	// Verify status
	status := blockList.Status()
	assert.Equal(t, uint(5), status.Size)
	assert.Equal(t, "Test Blocklist", status.MetaData["title"])
	assert.Equal(t, "Tester", status.MetaData["author"])
}

func TestBlocklist_Fetch_EmptyFile(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.txt")
	err := os.WriteFile(tmpFile, []byte(""), 0644)
	assert.NoError(t, err)

	blockList := NewBlockList("test", "file://"+tmpFile, 0.0001, logger)

	err = blockList.Fetch(t.Context())
	assert.NoError(t, err)

	// Should not panic and should have a bloom filter (with 0 items guarded to 1)
	status := blockList.Status()
	assert.Equal(t, uint(1), status.Size)
}
