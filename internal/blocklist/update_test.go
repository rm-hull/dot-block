package blocklist

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdater_Run(t *testing.T) {
	// Use slog.Default() to prevent nil pointer in Fetch()
	bl := NewBlockList("list1", "http://localhost:8080/does-not-exist", 0.001, slog.Default())
	updater := NewUpdater(bl, 5*time.Second)

	// Expect Run() to return without panicking
	assert.NotPanics(t, func() { updater.Run() })
}
