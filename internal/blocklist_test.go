package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestIsBlocked_ApexDomain_PublicSuffix(t *testing.T) {
	assert := assert.New(t)

	blockList := NewBlockList([]string{"host1.com", "host2.com"}, 0.0001)

	isBlocked, err := blockList.IsBlocked("s3.amazonaws.com.")
	assert.NoError(err)
	assert.False(isBlocked)
}
