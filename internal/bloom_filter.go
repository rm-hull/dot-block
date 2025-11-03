package internal

import (
	"log"

	"github.com/bits-and-blooms/bloom/v3"
)

func NewBloomFilter(items []string, fpRate float64) *bloom.BloomFilter {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, fpRate)

	for _, item := range items {
		bf.AddString(item)
	}

	m, k := bloom.EstimateParameters(n, fpRate)
	log.Printf("Bloom filter created: actual FP rate = %f, approx size = %d", bloom.EstimateFalsePositiveRate(m, k, n), bf.ApproximatedSize())

	return bf
}
