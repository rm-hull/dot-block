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
		{"xn--example.com", true},                    // Punycode
		{"exämple.com", true},                        // Non-ASCII
		{"测试.com", true},                             // Non-ASCII
		{"\\230\\181\\139\\232\\175\\149.com", true}, // Escaped Unicode bytes (DNS presentation format)
		{"\\101xample.com", false},                   // Escaped ASCII (\101 = 'A') - should not be blocked
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
		{"xn--example.com", false},     // Punycode - should be allowed when disabled
		{"exämple.com", false},         // Non-ASCII - should be allowed when disabled
		{"测试.com", false},              // Non-ASCII - should be allowed when disabled
		{"\\230\\181\\139.com", false}, // Escaped Unicode - should be allowed when disabled
	}

	for _, tc := range tests {
		blocked, err := bl.IsBlocked(tc.domain)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, blocked, "Domain %s should be blocked: %v", tc.domain, tc.expected)
	}
}
