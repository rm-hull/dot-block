package blocklist

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdater_Run(t *testing.T) {
	// Use slog.Default() to prevent nil pointer in Fetch()
	bls := []*BlockList{
		NewBlockList("list1", "http://localhost:8080/does-not-exist", 0.001, slog.Default()),
	}
	updater := NewUpdater(bls)

	// Expect Run() to return without panicking
	assert.NotPanics(t, func() { updater.Run() })
}
