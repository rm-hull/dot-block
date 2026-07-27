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
	"github.com/rm-hull/dot-block/internal/blocklist/hostfile"
	"github.com/rm-hull/dot-block/internal/downloader"
	"github.com/rm-hull/dot-block/internal/metrics"
	"golang.org/x/net/publicsuffix"
)

type BlockList struct {
	name            string
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
	MetaData          map[string]string `json:"metadata,omitempty"`
	LastUpdated       *time.Time        `json:"last_updated,omitempty"`
	DisabledUntil     *time.Time        `json:"disabled_until,omitempty"`
	FalsePositiveRate float64           `json:"estimated_false_positive_rate"`
}

func NewBlockList(name string, url string, fpRate float64, logger *slog.Logger) *BlockList {
	metrics, _ := metrics.NewBlockListMetrics(name)

	blocklist := &BlockList{
		name:      name,
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

	isBlocked := blockList.bloomFilter.TestString(domain)

	// Try the apex domain (e.g. for "ads.example.com", check "example.com")
	// EffectiveTLDPlusOne returns an error for bare TLDs (e.g. "com") or domains
	// with invalid labels, which is expected — we simply skip the apex domain check.
	if !isBlocked {
		if apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
			isBlocked = blockList.bloomFilter.TestString(apexDomain)
		}
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
		return errors.Wrapf(err, "failed to download blocklist for counting: %s", blockList.url)
	}

	defer func() {
		if isTemp {
			_ = os.Remove(path)
		}
	}()

	return blockList.processFile(path)
}

func (blockList *BlockList) processFile(path string) error {

	file, err := os.Open(path)
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

	// Avoid creating a bloom filter with 0 items, which will panic
	bloomFilter := bloom.NewWithEstimates(estimate+1, blockList.minFpRate)

	// Stream the file in a single pass: add hostnames directly to the bloom
	// filter and extract metadata comments into a map. Rather than logging
	// metadata as it is encountered, we dump it in a single log message afterwards.
	var hostCount uint
	metadata, err := hostfile.Stream(file, func(entry hostfile.Entry) error {
		for _, host := range entry.Hostnames {
			bloomFilter.AddString(host)
			hostCount++
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "failed to stream hosts from file %s (url: %s)", path, blockList.url)
	}

	if len(metadata) > 0 {
		blockList.logger.Info("Loaded hosts into blocklist", "metadata", metadata)
	}

	blockList.applyBloomFilter(bloomFilter, hostCount, metadata)
	return nil
}

// countNewlines reads through an io.Reader and counts newline characters,
// providing a fast, low-memory estimate of the number of lines (and thus
// approximate number of hosts) in a blocklist file.
func countNewlines(r io.Reader) (uint, error) {
	var count uint
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		for i := range n {
			if buf[i] == '\n' {
				count++
			}
		}
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return 0, err
		}
	}
}
