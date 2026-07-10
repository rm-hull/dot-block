package blocklist

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBlocked_ApexDomain_PublicSuffix(t *testing.T) {
	assert := assert.New(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	blockList := NewBlockList([]string{"host1.com", "host2.com"}, 0.0001, logger)

	isBlocked, err := blockList.IsBlocked("s3.amazonaws.com.")
	assert.NoError(err)
	assert.False(isBlocked)
}

func TestNewBlockList_NilItems(t *testing.T) {
	assert := assert.New(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	
	// This should not panic when IsBlocked is called
	blockList := NewBlockList(nil, 0.0001, logger)
	
	assert.NotPanics(func() {
		_, _ = blockList.IsBlocked("test.com")
	})
}

func TestNewBlockList_EmptyItems(t *testing.T) {
	assert := assert.New(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	
	blockList := NewBlockList([]string{}, 0.0001, logger)
	
	assert.NotPanics(func() {
		_, _ = blockList.IsBlocked("test.com")
	})
}
