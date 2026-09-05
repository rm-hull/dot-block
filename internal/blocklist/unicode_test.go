package blocklist

import (
	"log/slog"
	"testing"

	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestUnicodeBlocklist_Enabled(t *testing.T) {
	logger := slog.Default()
	bl := NewUnicodeBlocklist(&config.UnicodeConfig{Enabled: true}, logger)

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", false},
		{"google.com", false},
		{"xn--example.com", true}, // Punycode
		{"exämple.com", true},     // Non-ASCII
		{"测试.com", true},          // Non-ASCII
	}

	for _, tc := range tests {
		blocked, err := bl.IsBlocked(tc.domain)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, blocked, "Domain %s should be blocked: %v", tc.domain, tc.expected)
	}
}

func TestUnicodeBlocklist_Disabled(t *testing.T) {
	logger := slog.Default()
	bl := NewUnicodeBlocklist(&config.UnicodeConfig{Enabled: false}, logger)

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", false},
		{"google.com", false},
		{"xn--example.com", false}, // Punycode - should be allowed when disabled
		{"exämple.com", false},     // Non-ASCII - should be allowed when disabled
		{"测试.com", false},          // Non-ASCII - should be allowed when disabled
	}

	for _, tc := range tests {
		blocked, err := bl.IsBlocked(tc.domain)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, blocked, "Domain %s should be blocked: %v", tc.domain, tc.expected)
	}
}
