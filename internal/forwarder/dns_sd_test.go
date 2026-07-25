package forwarder

import (
	"testing"
)

func TestIsDNSSDQuery(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"db._dns-sd._udp.0.68.168.192.in-addr.arpa.", true},
		{"b._dns-sd._udp.local.", true},
		{"r._dns-sd._udp.example.com.", true},
		{"dr._dns-sd._udp.example.com.", true},
		{"lb._dns-sd._udp.example.com.", true},
		{"example.com.", false},
		{"_dns-sd._udp.example.com.", false},
		{"_services._dns-sd._udp.example.com.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDNSSDQuery(tt.name); got != tt.want {
				t.Errorf("isDNSSDQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}
