package blocklist

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCustomBlocklist(t *testing.T) {
	logger := slog.Default()
	bl := NewCustomBlocklist(logger)

	assert.Equal(t, CustomBlocklistName, bl.Name())
	assert.NotEmpty(t, bl.Title())
	assert.NotEmpty(t, bl.Description())
	assert.Empty(t, bl.URL())
	assert.NoError(t, bl.Fetch(context.TODO()))

	// Initially not blocked
	blocked, err := bl.IsBlocked("example.com")
	assert.NoError(t, err)
	assert.False(t, blocked)

	// Add domains
	bl.Add([]string{"example.com", "malware.test"})
	assert.Len(t, bl.Domains(), 2)

	blocked, err = bl.IsBlocked("example.com.")
	assert.NoError(t, err)
	assert.True(t, blocked)

	blocked, err = bl.IsBlocked("sub.malware.test")
	assert.NoError(t, err)
	assert.True(t, blocked)

	// Remove domains
	bl.Remove([]string{"example.com"})
	blocked, err = bl.IsBlocked("example.com")
	assert.NoError(t, err)
	assert.False(t, blocked)

	// Status
	status := bl.Status()
	assert.Equal(t, CustomBlocklistName, status.Name)
	assert.Equal(t, uint(1), *status.Size)

	// Disable and reenable
	until := bl.Disable(time.Hour)
	assert.False(t, until.IsZero())
	blocked, err = bl.IsBlocked("malware.test")
	assert.NoError(t, err)
	assert.False(t, blocked)

	assert.True(t, bl.Reenable())
	blocked, err = bl.IsBlocked("malware.test")
	assert.NoError(t, err)
	assert.True(t, blocked)
}
