package dnsutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeDNSName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain ascii domain",
			input:    "example.com.",
			expected: "example.com.",
		},
		{
			name:     "escaped utf8 domain",
			input:    "\\230\\181\\139\\232\\175\\149.com.",
			expected: "测试.com.",
		},
		{
			name:     "invalid escape sequence",
			input:    "example\\abc.com.",
			expected: "example\\abc.com.",
		},
		{
			name:     "incomplete escape at end",
			input:    "example\\23",
			expected: "example\\23",
		},
		{
			name:     "invalid utf8 result returns original",
			input:    "\\255\\255.com.",
			expected: "\\255\\255.com.",
		},
		{
			name:     "no escape characters fast path",
			input:    "google.com.",
			expected: "google.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DecodeDNSName(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func BenchmarkDecodeDNSName_Plain(b *testing.B) {
	domain := "example.com."
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecodeDNSName(domain)
	}
}

func BenchmarkDecodeDNSName_Escaped(b *testing.B) {
	domain := "\\230\\181\\139\\232\\175\\149.com."
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecodeDNSName(domain)
	}
}
