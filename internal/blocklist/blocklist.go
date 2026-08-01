package blocklist

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cockroachdb/errors"
	"github.com/rm-hull/dot-block/internal/downloader"
	"github.com/rm-hull/dot-block/internal/metrics"
	"golang.org/x/net/publicsuffix"
)

type BlockList struct {
	name            string
	schedule        string
	url             string
	metadata        map[string]string
	lastUpdated     *time.Time
	minFpRate       float64
	estimatedFpRate float64
	bloomFilter     *bloom.BloomFilter
	size            uint
	metrics         *metrics.BlockListMetrics
	logger          *slog.Logger
	mutex           *sync.RWMutex
	disabledUntil   *time.Time
}

type BlocklistStatus struct {
	Name              string            `json:"name"`
	URL               string            `json:"url"`
	Size              uint              `json:"size"`
	Schedule          string            `json:"schedule"`
	MetaData          map[string]string `json:"metadata,omitempty"`
	LastUpdated       *time.Time        `json:"last_updated,omitempty"`
	DisabledUntil     *time.Time        `json:"disabled_until,omitempty"`
	FalsePositiveRate float64           `json:"estimated_false_positive_rate"`
}

func NewBlockList(name, schedule, url string, fpRate float64, logger *slog.Logger) *BlockList {
	metrics, _ := metrics.NewBlockListMetrics(name)

	blocklist := &BlockList{
		name:      name,
		schedule:  schedule,
		url:       url,
		minFpRate: fpRate,
		metrics:   metrics,
		logger:    logger.With("name", name),
		mutex:     &sync.RWMutex{},
	}

	return blocklist
}

func (BlockList *BlockList) Name() string {
	return BlockList.name
}

func (blockList *BlockList) URL() string {
	return blockList.url
}

func (BlockList *BlockList) Metadata(attr, defaultValue string) string {
	if value, ok := BlockList.metadata[attr]; ok {
		return value
	}
	return defaultValue
}

// Returns whether the URL (or part of the URL) is on a block list.
// If true, might be a false positive, but if false (i.e. allowed) is definitely not blocked
func (blockList *BlockList) IsBlocked(fqdn string) (bool, error) {
	domain, _ := strings.CutSuffix(fqdn, ".")

	blockList.mutex.RLock()
	defer blockList.mutex.RUnlock()

	// Check whether blocklist was initializaed first
	if blockList.bloomFilter == nil {
		return false, nil
	}

	// 1. Check exact domain first (e.g., "8.lox.legalendowmad.com")
	current := domain
	if blockList.bloomFilter.TestString(current) {
		return blockList.checkDisabled()
	}

	// 2. Iteratively check parent subdomains up to the apex domain (EffectiveTLDPlusOne)
	apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err == nil {
		for {
			idx := strings.Index(current, ".")
			if idx == -1 {
				break
			}
			current = current[idx+1:]

			if blockList.bloomFilter.TestString(current) {
				return blockList.checkDisabled()
			}

			if current == apexDomain {
				break
			}
		}
	}

	return false, nil
}

func (blockList *BlockList) checkDisabled() (bool, error) {
	if blockList.disabledUntil != nil && time.Now().Before(*blockList.disabledUntil) {
		return false, nil
	}
	return true, nil
}

func (blocklist *BlockList) Load(items []string) {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, blocklist.minFpRate)
	for _, item := range items {
		bf.AddString(item)
	}

	blocklist.applyBloomFilter(bf, n, nil)
}

func (blocklist *BlockList) Disable(duration time.Duration) time.Time {
	blocklist.mutex.Lock()
	defer blocklist.mutex.Unlock()

	blocklist.disabledUntil = new(time.Now().Add(duration))
	blocklist.logger.Warn("Blocklist temporarily disabled",
		"name", blocklist.name,
		"until", blocklist.disabledUntil)

	return *blocklist.disabledUntil
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

func (blocklist *BlockList) Status() *BlocklistStatus {
	blocklist.mutex.RLock()
	defer blocklist.mutex.RUnlock()

	var disabledUntil *time.Time
	if blocklist.disabledUntil != nil && time.Now().Before(*blocklist.disabledUntil) {
		disabledUntil = blocklist.disabledUntil
	}
	status := BlocklistStatus{
		Name:              blocklist.name,
		Schedule:          blocklist.schedule,
		URL:               blocklist.url,
		Size:              blocklist.size,
		MetaData:          blocklist.metadata,
		LastUpdated:       blocklist.lastUpdated,
		DisabledUntil:     disabledUntil,
		FalsePositiveRate: blocklist.estimatedFpRate,
	}

	return &status
}

func (blocklist *BlockList) applyBloomFilter(bf *bloom.BloomFilter, n uint, metadata map[string]string) {
	m, k := bloom.EstimateParameters(n, blocklist.minFpRate)
	estimatedFpRate := bloom.EstimateFalsePositiveRate(m, k, n)

	blocklist.mutex.Lock()
	blocklist.bloomFilter = bf
	blocklist.size = n
	blocklist.metadata = metadata
	blocklist.lastUpdated = new(time.Now())
	blocklist.estimatedFpRate = estimatedFpRate
	blocklist.mutex.Unlock()

	blocklist.logger.Info("Bloom filter created",
		"name", blocklist.name,
		"actual_size", n,
		"estimated_size", bf.ApproximatedSize(),
		"estimated_fp_rate", estimatedFpRate)

	blocklist.metrics.Update(n)
}

func (blockList *BlockList) Fetch(ctx context.Context) error {
	path, _, isTemp, err := downloader.Download(ctx, blockList.logger, "", "blocklist", blockList.url, "")
	if err != nil {
		return errors.Wrap(err, "failed to download blocklist")
	}

	defer func() {
		if isTemp {
			_ = os.Remove(path)
		}
	}()

	return blockList.processFile(path)
}

// processFile reads a blocklist file from disk, counts entries, builds a bloom
// filter, and applies it. It is the core processing logic shared by Fetch
// (which first downloads the file) and is also used directly by benchmarks.
func (blockList *BlockList) processFile(path string) error {
	file, err := os.Open(path)
	// count, err := countLines(path)
	if err != nil {
		return errors.Wrapf(err, "failed to open blocklist file %s (url: %s)", path, blockList.url)
	}
	defer func() { _ = file.Close() }()

	estimate, err := countNewlines(file)
	if err != nil {
		return errors.Wrapf(err, "failed to count lines in file %s (url: %s)", path, blockList.url)
	}

	// Seek back to the beginning for streaming
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.Wrapf(err, "failed to seek to beginning of file %s (url: %s)", path, blockList.url)
	}

	bloomFilter := bloom.NewWithEstimates(estimate+1, blockList.minFpRate)

	// Stream the file in a single pass: add hostnames directly to the bloom
	// filter and extract metadata comments into a map. Rather than logging
	// metadata as it is encountered, we dump it in a single log message afterwards.
	var hostCount uint
	metadata, err := stream(file, func(host []byte) bool {
		bloomFilter.Add(host)
		hostCount++
		return false
	})
	if err != nil {
		return errors.Wrapf(err, "failed to stream hosts from file %s", path)
	}

	if len(metadata) > 0 {
		blockList.logger.Info("Loaded hosts into blocklist", "metadata", metadata)
	}

	blockList.applyBloomFilter(bloomFilter, hostCount, metadata)
	return nil
}
