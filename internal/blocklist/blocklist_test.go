package blocklist

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestBlocklist_DisableAndIsBlocked(t *testing.T) {
	// Use a dummy handler that won't panic when passed nil
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	source := &config.BlocklistSource{Name: "test", URL: "http://dummy_url"}
	blockList := NewBlockList(source, 0.0001, logger)
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

func TestBlocklist_SubdomainHierarchy(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	source := &config.BlocklistSource{Name: "test", URL: "http://dummy_url"}
	blockList := NewBlockList(source, 0.0001, logger)
	blockList.Load([]string{"lox.legalendowmad.com"})

	testCases := []struct {
		domain        string
		expectBlocked bool
	}{
		{"lox.legalendowmad.com", true},
		{"8.lox.legalendowmad.com", true},
		{"sub.8.lox.legalendowmad.com", true},
		{"legalendowmad.com", false},
		{"other.com", false},
	}

	for _, tc := range testCases {
		isBlocked, err := blockList.IsBlocked(tc.domain)
		assert.NoError(t, err)
		assert.Equal(t, tc.expectBlocked, isBlocked, "domain %s expected blocked=%v", tc.domain, tc.expectBlocked)
	}
}
