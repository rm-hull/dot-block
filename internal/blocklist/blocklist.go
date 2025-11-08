package blocklist

import (
	"log/slog"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/rm-hull/dot-block/internal/metrics"
	"golang.org/x/net/publicsuffix"
)

type BlockList struct {
	fpRate      float64
	bloomFilter *bloom.BloomFilter
	metrics     *metrics.BlockListMetrics
	logger      *slog.Logger
}

func NewBlockList(items []string, fpRate float64, logger *slog.Logger) *BlockList {
	metrics, _ := metrics.NewBlockListMetrics()

	blocklist := &BlockList{
		fpRate:  fpRate,
		metrics: metrics,
		logger:  logger,
	}

	blocklist.Load(items)

	return blocklist
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

func (blocklist *BlockList) Load(items []string) {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, blocklist.fpRate)
	for _, item := range items {
		bf.AddString(item)
	}

	m, k := bloom.EstimateParameters(n, blocklist.fpRate)
	blocklist.logger.Info("Bloom filter created", "actual_fp_rate", bloom.EstimateFalsePositiveRate(m, k, n), "approx_size", bf.ApproximatedSize())
	blocklist.bloomFilter = bf
	blocklist.metrics.Update(n)
}
