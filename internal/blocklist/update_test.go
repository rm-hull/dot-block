package blocklist

import (
	"log/slog"
	"testing"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestUpdater_Run(t *testing.T) {
	source := &config.BlocklistSource{Name: "list1", URL: "http://localhost:8080/does-not-exist"}
	bl := NewStaticBlockList(source, 0.001, slog.Default())
	updater := NewUpdater(bl, 5*time.Second)

	// Expect Run() to return without panicking
	assert.NotPanics(t, func() { updater.Run() })
}
