package logging

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBridgeStandardLog_SourceReporting(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{AddSource: true})
	logger := slog.New(handler)

	// TEST 1: Direct logger call
	logger.Info("direct call", "key", "val")
	output1 := buf.String()
	buf.Reset()
	fmt.Printf("Direct call output: %s\n", output1)
	assert.Contains(t, output1, "key")
	assert.Contains(t, output1, "val")

	// TEST 2: Bridge call
	BridgeStandardLog(handler)
	log.Println("test bridged message")
	output2 := buf.String()
	fmt.Printf("Bridged call output: %s\n", output2)
	assert.Contains(t, output2, "test bridged message")
	assert.Contains(t, output2, "source")
}
