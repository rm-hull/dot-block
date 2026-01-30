package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

