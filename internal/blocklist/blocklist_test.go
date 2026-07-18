package blocklist

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBlocklist_DisableAndIsBlocked(t *testing.T) {
	// Use a dummy handler that won't panic when passed nil
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	// Create a blocklist with one entry
	blockList := NewBlockList([]string{"example.com"}, 0.0001, logger)

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
