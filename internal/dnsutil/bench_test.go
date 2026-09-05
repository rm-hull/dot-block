package dnsutil

import (
	"strings"
	"testing"
)

var domain = "example.com."

func BenchmarkContains(b *testing.B) {
	for b.Loop() {
		_ = strings.Contains(domain, "\\")
	}
}

func BenchmarkManualLoop(b *testing.B) {
	for b.Loop() {
		has := false
		for j := range len(domain) {
			if domain[j] == '\\' {
				has = true
				break
			}
		}
		_ = has
	}
}

func BenchmarkDecodeDNSName_Plain(b *testing.B) {
	domain := "example.com."

	for b.Loop() {
		_ = DecodeDNSName(domain)
	}
}

func BenchmarkDecodeDNSName_Escaped(b *testing.B) {
	domain := "\\230\\181\\139\\232\\175\\149.com."

	for b.Loop() {
		_ = DecodeDNSName(domain)
	}
}
