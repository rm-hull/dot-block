package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSpaceSaverStatsCallback(t *testing.T) {
	assert := assert.New(t)

	// Create a more controlled test.
	ss := NewSpaceSaver(2)
	ss.Add("a") // a: {C:1, E:0}
	ss.Add("a") // a: {C:2, E:0}
	ss.Add("b") // a: {C:2, E:0}, b: {C:1, E:0}
	ss.Add("c") // a: {C:2, E:0}, c: {C:1+1=2, E:1} (b is replaced)

	callback := newSpaceSaverStatsCallback(ss, 2)
	results := callback()

	assert.Len(results, 2)
	assert.Equal(2, results["a"]) // Count(2) - Error(0) = 2
	assert.Equal(1, results["c"]) // Count(2) - Error(1) = 1
}

