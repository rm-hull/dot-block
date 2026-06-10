package noisefilter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoiseFilter_ShouldSuppress(t *testing.T) {
	tests := []struct {
		name           string
		triplets       []Triplet
		category       string
		rcode          string
		domain         string
		expectSuppress bool
	}{
		{
			name: "Exact match - should suppress",
			triplets: []Triplet{
				{Category: "upstream", Rcode: "REFUSED", DomainSuffix: "akadns.net"},
			},
			category:       "upstream",
			rcode:          "REFUSED",
			domain:         "test.akadns.net",
			expectSuppress: true,
		},
		{
			name: "Exact match - different subdomain - should suppress",
			triplets: []Triplet{
				{Category: "upstream", Rcode: "REFUSED", DomainSuffix: "akadns.net"},
			},
			category:       "upstream",
			rcode:          "REFUSED",
			domain:         "sub.test.akadns.net",
			expectSuppress: true,
		},
		{
			name: "Wrong category - should NOT suppress",
			triplets: []Triplet{
				{Category: "upstream", Rcode: "REFUSED", DomainSuffix: "akadns.net"},
			},
			category:       "blocklist",
			rcode:          "REFUSED",
			domain:         "test.akadns.net",
			expectSuppress: false,
		},
		{
			name: "Wrong rcode - should NOT suppress",
			triplets: []Triplet{
				{Category: "upstream", Rcode: "REFUSED", DomainSuffix: "akadns.net"},
			},
			category:       "upstream",
			rcode:          "SERVFAIL",
			domain:         "test.akadns.net",
			expectSuppress: false,
		},
		{
			name: "Wrong domain suffix - should NOT suppress",
			triplets: []Triplet{
				{Category: "upstream", Rcode: "REFUSED", DomainSuffix: "akadns.net"},
			},
			category:       "upstream",
			rcode:          "REFUSED",
			domain:         "test.google.com",
			expectSuppress: false,
		},
		{
			name:           "Empty filter - should NOT suppress",
			triplets:       []Triplet{},
			category:       "upstream",
			rcode:          "REFUSED",
			domain:         "test.akadns.net",
			expectSuppress: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nf := NewNoiseFilter()

			// Normalize triplets as Load would
			normalizedTriplets := make([]Triplet, 0, len(tt.triplets))
			for _, tr := range tt.triplets {
				suffix := tr.DomainSuffix
				if suffix != "" && !strings.HasSuffix(suffix, ".") {
					suffix += "."
				}
				normalizedTriplets = append(normalizedTriplets, Triplet{
					Category:     strings.ToUpper(tr.Category),
					Rcode:        strings.ToUpper(tr.Rcode),
					DomainSuffix: suffix,
				})
			}

			nf.mu.Lock()
			nf.triplets = normalizedTriplets
			nf.mu.Unlock()

			assert.Equal(t, tt.expectSuppress, nf.ShouldSuppress(tt.category, tt.rcode, tt.domain))
		})
	}
}

func TestNoiseFilter_Load(t *testing.T) {
	csvData := `category,rcode,domain_suffix
upstream,REFUSED,akadns.net
upstream,REFUSED,akamaiedge.net
blocklist,ERROR,example.com
`
	reader := strings.NewReader(csvData)
	nf := NewNoiseFilter()
	err := nf.Load(reader)
	assert.NoError(t, err)

	assert.True(t, nf.ShouldSuppress("upstream", "REFUSED", "test.akadns.net"))
	assert.True(t, nf.ShouldSuppress("upstream", "REFUSED", "test.akamaiedge.net"))
	assert.True(t, nf.ShouldSuppress("blocklist", "ERROR", "test.example.com"))
	assert.False(t, nf.ShouldSuppress("upstream", "REFUSED", "test.google.com"))
}
