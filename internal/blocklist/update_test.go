package blocklist

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdater_Run(t *testing.T) {
	// Use slog.Default() to prevent nil pointer in Fetch()
	bls := []*BlockList{
		NewBlockList("list1", "http://localhost:8080/does-not-exist", 0.001, slog.Default()),
	}
	updater := NewUpdater(bls, 5*time.Second)

	// Expect Run() to return without panicking
	assert.NotPanics(t, func() { updater.Run() })
}

func TestUpdater_AllLoaded(t *testing.T) {
	logger := slog.Default()

	t.Run("all loaded", func(t *testing.T) {
		bl := NewBlockList("test", "http://dummy.url", 0.0001, logger)
		bl.Load([]string{"example.com"})
		updater := NewUpdater([]*BlockList{bl}, 1*time.Minute)
		assert.True(t, updater.AllLoaded())
	})

	t.Run("not loaded", func(t *testing.T) {
		bl := NewBlockList("test", "http://dummy.url", 0.0001, logger)
		updater := NewUpdater([]*BlockList{bl}, 1*time.Minute)
		assert.False(t, updater.AllLoaded())
	})

	t.Run("mixed loaded", func(t *testing.T) {
		bl1 := NewBlockList("loaded", "http://dummy.url", 0.0001, logger)
		bl1.Load([]string{"example.com"})
		bl2 := NewBlockList("not-loaded", "http://dummy.url", 0.0001, logger)
		updater := NewUpdater([]*BlockList{bl1, bl2}, 1*time.Minute)
		assert.False(t, updater.AllLoaded())
	})

	t.Run("empty updater", func(t *testing.T) {
		updater := NewUpdater([]*BlockList{}, 1*time.Minute)
		assert.True(t, updater.AllLoaded())
	})
}
