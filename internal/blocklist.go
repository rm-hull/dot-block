package internal

import (
	"log"
	"math"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/publicsuffix"
)

type BlockList struct {
	bloomFilter *bloom.BloomFilter
	updated     time.Time
}

func NewBlockList(items []string, fpRate float64) *BlockList {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, fpRate)
	for _, item := range items {
		bf.AddString(item)
	}

	m, k := bloom.EstimateParameters(n, fpRate)
	log.Printf("Bloom filter created: actual FP rate = %f, approx size = %d", bloom.EstimateFalsePositiveRate(m, k, n), bf.ApproximatedSize())

	blocklist := BlockList{
		bloomFilter: bf,
		updated:     time.Now(),
	}

	count := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blocklist_size",
		Help: "The number of entries in the blocklist",
	})
	count.Set(float64(n))

	age := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "blocklist_age",
		Help: "The age (in seconds) since the blocklist was loaded",
	}, func() float64 {
		return math.Round(time.Since(blocklist.updated).Seconds())
	})

	_ = shouldRegister(count, age)

	return &blocklist
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
		// ignore: the domain effectively /is/ the apex domain - see https://publicsuffix.org/learn/
		if strings.HasPrefix(err.Error(), "publicsuffix: cannot derive eTLD+1") {
			return false, nil
		}
		return false, err
	}

	return blockList.bloomFilter.TestString(apexDomain), nil
}
