package internal

import (
	"log"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/net/publicsuffix"
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
func (blockList *BlockList) IsBlocked(fqdn string) (bool, error) {

	domain, _ := strings.CutSuffix(fqdn, ".")
	isBlocked := blockList.bloomFilter.TestString(domain)

	if isBlocked {
		return true, nil
	}

	// Try the apex domain
	apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return true, err
	}

	return blockList.bloomFilter.TestString(apexDomain), nil
}

func getApexDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}
