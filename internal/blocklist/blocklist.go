package blocklist

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/rm-hull/dot-block/internal/metrics"
	"golang.org/x/net/publicsuffix"
)

type BlockList struct {
	name          string
	fpRate        float64
	bloomFilter   *bloom.BloomFilter
	metrics       *metrics.BlockListMetrics
	logger        *slog.Logger
	mutex         *sync.RWMutex
	disabledUntil *time.Time
}

func NewBlockList(name string, items []string, fpRate float64, logger *slog.Logger) *BlockList {
	metrics, _ := metrics.NewBlockListMetrics()

	blocklist := &BlockList{
		name:    name,
		fpRate:  fpRate,
		metrics: metrics,
		logger:  logger,
		mutex:   &sync.RWMutex{},
	}

	blocklist.Load(items)
	return blocklist
}

func (BlockList *BlockList) Name() string {
	return BlockList.name
}

// Returns whether the URL (or part of the URL) is on a block list.
// If true, might be a false positive, but if false (i.e. allowed) is definitely not blocked
func (blockList *BlockList) IsBlocked(fqdn string) (bool, error) {
	domain, _ := strings.CutSuffix(fqdn, ".")

	blockList.mutex.RLock()
	defer blockList.mutex.RUnlock()

	isBlocked := blockList.bloomFilter.TestString(domain)

	// Try the apex domain
	apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "publicsuffix: cannot derive eTLD+1") {
			return false, err
		}
	} else if !isBlocked {
		isBlocked = blockList.bloomFilter.TestString(apexDomain)
	}

	if isBlocked {
		// Check if blocklist is temporarily disabled
		if blockList.disabledUntil != nil && time.Now().Before(*blockList.disabledUntil) {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

func (blocklist *BlockList) Load(items []string) {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, blocklist.fpRate)
	for _, item := range items {
		bf.AddString(item)
	}

	blocklist.ApplyBloomFilter(bf, n)
}

func (blocklist *BlockList) Disable(duration time.Duration) time.Time {
	t := time.Now().Add(duration)
	blocklist.mutex.Lock()
	blocklist.disabledUntil = &t
	blocklist.mutex.Unlock()
	blocklist.logger.Warn("Blocklist temporarily disabled",
		"name", blocklist.name,
		"until", t)

	return t
}

func (blocklist *BlockList) Reenable() bool {
	blocklist.mutex.Lock()
	defer blocklist.mutex.Unlock()

	if blocklist.disabledUntil == nil || time.Now().After(*blocklist.disabledUntil) {
		return false
	}

	blocklist.disabledUntil = nil
	blocklist.logger.Info("Blocklist re-enabled", "name", blocklist.name)
	return true
}

type BlocklistStatus struct {
	Disabled          bool       `json:"disabled"`
	Until             *time.Time `json:"until,omitempty"`
	ApproxSize        uint32     `json:"approx_size"`
	FalsePositiveRate float64    `json:"false_positive_rate"`
}

// Status returns whether the blocklist is currently disabled and until when
func (blocklist *BlockList) Status() *BlocklistStatus {
	blocklist.mutex.RLock()
	defer blocklist.mutex.RUnlock()

	var until *time.Time
	disabled := blocklist.disabledUntil != nil && time.Now().Before(*blocklist.disabledUntil)
	if disabled {
		until = blocklist.disabledUntil
	}
	status := BlocklistStatus{
		Disabled:          disabled,
		Until:             until,
		ApproxSize:        blocklist.bloomFilter.ApproximatedSize(),
		FalsePositiveRate: blocklist.fpRate,
	}

	return &status
}

func (blocklist *BlockList) ApplyBloomFilter(bf *bloom.BloomFilter, n uint) {
	m, k := bloom.EstimateParameters(n, blocklist.fpRate)
	blocklist.logger.Info("Bloom filter created",
		"name", blocklist.name,
		"actual_fp_rate", bloom.EstimateFalsePositiveRate(m, k, n),
		"approx_size", bf.ApproximatedSize())

	blocklist.mutex.Lock()
	blocklist.bloomFilter = bf
	blocklist.mutex.Unlock()

	blocklist.metrics.Update(n)
}
