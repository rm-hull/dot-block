package internal

import (
	"log"

	"github.com/bits-and-blooms/bloom/v3"
)

type BlockList struct {
	bloomFilter *bloom.BloomFilter
}

func NewBlockList(items []string, fpRate float64) *BlockList {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, fpRate)

	for _, item := range items {
		bf.AddString(item)
	}

	m, k := bloom.EstimateParameters(n, fpRate)
	log.Printf("Bloom filter created: actual FP rate = %f, approx size = %d", bloom.EstimateFalsePositiveRate(m, k, n), bf.ApproximatedSize())

	return &BlockList{
		bloomFilter: bf,
	}
}

// Returns whether the URL (or part of the URL) is on a block list.
// If true, might be a false positive, but if false (i.e. allowed) is definitely not blocked
func (blockList *BlockList) IsBlocked(url string) bool {
	// TODO: also chop up the URL to parent.tld and test that well
	return blockList.bloomFilter.TestString(url)
}
