package dnsutil

import (
	"strings"
	"testing"
)

var domain = "example.com."

func BenchmarkContains(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(domain, "\\")
	}
}

func BenchmarkManualLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		has := false
		for j := 0; j < len(domain); j++ {
			if domain[j] == '\\' {
				has = true
				break
			}
		}
		_ = has
	}
}
