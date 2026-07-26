package metrics

import (
	"testing"

	"github.com/earthboundkid/versioninfo/v2"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSpaceSaverStatsCallback(t *testing.T) {
	testCases := []struct {
		name     string
		capacity int
		adds     []string
		topK     int
		expected map[string]int
	}{
		{
			name:     "eviction case",
			capacity: 2,
			adds:     []string{"a", "a", "b", "c"},
			topK:     2,
			expected: map[string]int{"a": 2, "c": 1},
		},
		{
			name:     "topK smaller than items",
			capacity: 2,
			adds:     []string{"a", "a", "a", "b"},
			topK:     1,
			expected: map[string]int{"a": 3},
		},
		{
			name:     "empty space saver",
			capacity: 2,
			adds:     []string{},
			topK:     2,
			expected: map[string]int{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			ss := NewSpaceSaver(tc.capacity)
			for _, item := range tc.adds {
				ss.Add(item)
			}

			callback := newSpaceSaverStatsCallback(ss, tc.topK)
			results := callback()

			assert.Equal(tc.expected, results)
		})
	}
}

// mockCache is a no-op implementation of the Cache interface for testing.
type mockCache struct{}

func (m *mockCache) Stat() cache.Stats { return cache.Stats{} }
func (m *mockCache) Len() int          { return 0 }
func (m *mockCache) OnDrop(_ func())   {}

// mockGeoIpLookup is a no-op implementation of geoblock.GeoIpLookup for testing.
type mockGeoIpLookup struct{}

func (m *mockGeoIpLookup) Reopen() error { return nil }
func (m *mockGeoIpLookup) GetAll(_ string) (*geoblock.GeoData, error) {
	return &geoblock.GeoData{}, nil
}
func (m *mockGeoIpLookup) IsValid(_ string) bool { return false }

func TestDNSInfoMetric(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	dnsMetrics, err := NewDNSMetrics(&mockCache{}, &mockGeoIpLookup{}, DefaultTopKConfig())
	require.NoError(err)

	// The dns_info metric should always be set to 1 (like go_info)
	assert.Equal(1.0, testutil.ToFloat64(dnsMetrics.Version))

	// The version label should be populated with the application version
	var dto dto.Metric
	require.NoError(dnsMetrics.Version.Write(&dto))

	var versionLabel string
	for _, label := range dto.Label {
		if label.GetName() == "version" {
			versionLabel = label.GetValue()
		}
	}
	assert.NotEmpty(versionLabel, "expected version label to be set on dns_info metric")
	assert.Equal(versioninfo.Short(), versionLabel)
}
