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
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/rm-hull/dot-block/internal/downloader"
	"github.com/rm-hull/dot-block/internal/metrics"
	"golang.org/x/net/publicsuffix"
)

// StaticBlocklist is a blocklist backed by a downloaded, static list of
// domains. Entries are stored in a Bloom filter so that membership tests are
// fast and memory-efficient, at the cost of a small, configurable false
// positive rate.
type StaticBlocklist struct {
	source          *config.BlocklistSource
	metadata        map[string]string
	lastFetched     *time.Time
	lastUpdated     *time.Time
	lastError       error
	minFpRate       float64
	estimatedFpRate float64
	bloomFilter     *bloom.BloomFilter
	size            uint
	metrics         *metrics.BlockListMetrics
	logger          *slog.Logger
	mutex           *sync.RWMutex
	disabledUntil   *time.Time
}

// NewStaticBlockList constructs a new StaticBlocklist backed by the given source.
//
// The fpRate argument controls the desired false-positive rate of the
// underlying Bloom filter and should be a small probability (e.g. 0.0001).
func NewStaticBlockList(source *config.BlocklistSource, fpRate float64, logger *slog.Logger) *StaticBlocklist {
	metrics, _ := metrics.NewBlockListMetrics(source.Name)

	blocklist := &StaticBlocklist{
		source:    source,
		metadata:  make(map[string]string),
		minFpRate: fpRate,
		metrics:   metrics,
		logger:    logger.With("name", source.Name),
		mutex:     &sync.RWMutex{},
	}

	return blocklist
}

func (blockList *StaticBlocklist) Name() string {
	return blockList.source.Name
}

func (blockList *StaticBlocklist) Title() string {
	if title, ok := blockList.metadata["title"]; ok {
		return title
	}
	return blockList.source.Title
}

func (blockList *StaticBlocklist) Description() string {
	if description, ok := blockList.metadata["description"]; ok {
		return description
	}
	return blockList.source.Description
}

func (blockList *StaticBlocklist) URL() string {
	return blockList.source.URL
}

// Returns whether the URL (or part of the URL) is on a block list.
// If true, might be a false positive, but if false (i.e. allowed) is definitely not blocked
func (blockList *StaticBlocklist) IsBlocked(fqdn string) (bool, error) {
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

func (blockList *StaticBlocklist) checkDisabled() (bool, error) {
	if blockList.disabledUntil != nil && time.Now().Before(*blockList.disabledUntil) {
		return false, nil
	}
	return true, nil
}

func (blockList *StaticBlocklist) Load(items []string) {
	n := uint(len(items))
	bf := bloom.NewWithEstimates(n, blockList.minFpRate)
	for _, item := range items {
		bf.AddString(item)
	}

	blockList.applyBloomFilter(bf, n, nil)
}

func (blockList *StaticBlocklist) Disable(duration time.Duration) time.Time {
	blockList.mutex.Lock()
	defer blockList.mutex.Unlock()

	blockList.disabledUntil = new(time.Now().Add(duration))
	blockList.logger.Warn("Blocklist temporarily disabled",
		"name", blockList.Name(),
		"until", blockList.disabledUntil)

	return *blockList.disabledUntil
}

func (blockList *StaticBlocklist) Reenable() bool {
	blockList.mutex.Lock()
	defer blockList.mutex.Unlock()

	if blockList.disabledUntil == nil || time.Now().After(*blockList.disabledUntil) {
		return false
	}

	blockList.disabledUntil = nil
	blockList.logger.Info("Blocklist re-enabled", "name", blockList.Name())
	return true
}

func (blockList *StaticBlocklist) Status() *BlocklistStatus {
	blockList.mutex.RLock()
	defer blockList.mutex.RUnlock()

	var disabledUntil *time.Time
	if blockList.disabledUntil != nil && time.Now().Before(*blockList.disabledUntil) {
		disabledUntil = blockList.disabledUntil
	}
	errorMessage := ""
	if blockList.lastError != nil {
		errorMessage = blockList.lastError.Error()
	}
	status := BlocklistStatus{
		Name:              blockList.Name(),
		Title:             blockList.Title(),
		Description:       blockList.Description(),
		Schedule:          blockList.source.CronSchedule,
		URL:               blockList.URL(),
		Size:              new(blockList.size),
		MetaData:          blockList.metadata,
		LastFetched:       blockList.lastFetched,
		LastUpdated:       blockList.lastUpdated,
		LastError:         errorMessage,
		DisabledUntil:     disabledUntil,
		FalsePositiveRate: blockList.estimatedFpRate,
	}

	return &status
}

func (blockList *StaticBlocklist) applyBloomFilter(bf *bloom.BloomFilter, n uint, metadata map[string]string) {
	m, k := bloom.EstimateParameters(n, blockList.minFpRate)
	estimatedFpRate := bloom.EstimateFalsePositiveRate(m, k, n)

	blockList.mutex.Lock()
	blockList.bloomFilter = bf
	blockList.size = n
	blockList.metadata = metadata
	blockList.lastFetched = new(time.Now())
	blockList.estimatedFpRate = estimatedFpRate
	blockList.mutex.Unlock()

	blockList.logger.Info("Bloom filter created",
		"name", blockList.Name(),
		"actual_size", n,
		"estimated_size", bf.ApproximatedSize(),
		"estimated_fp_rate", estimatedFpRate)

	blockList.metrics.Update(n)
}

func (blockList *StaticBlocklist) Fetch(ctx context.Context) error {
	path, header, isTemp, err := downloader.Download(ctx, blockList.logger, "", "blocklist", blockList.URL(), "")
	if err != nil {
		blockList.lastError = err
		return errors.Wrap(err, "failed to download blocklist")
	}

	defer func() {
		if isTemp {
			_ = os.Remove(path)
		}
	}()

	blockList.lastError = nil
	if lastUpdatedStr := header.Get("Last-Modified"); lastUpdatedStr != "" {
		if t, err := time.Parse(time.RFC1123, lastUpdatedStr); err == nil {
			blockList.lastUpdated = &t
		}
	}

	return blockList.processFile(path)
}

// processFile reads a blocklist file from disk, counts entries, builds a bloom
// filter, and applies it. It is the core processing logic shared by Fetch
// (which first downloads the file) and is also used directly by benchmarks.
func (blockList *StaticBlocklist) processFile(path string) error {
	file, err := os.Open(path)
	// count, err := countLines(path)
	if err != nil {
		return errors.Wrapf(err, "failed to open blocklist file %s (url: %s)", path, blockList.URL())
	}
	defer func() { _ = file.Close() }()

	estimate, err := countNewlines(file)
	if err != nil {
		return errors.Wrapf(err, "failed to count lines in file %s (url: %s)", path, blockList.URL())
	}

	// Seek back to the beginning for streaming
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.Wrapf(err, "failed to seek to beginning of file %s (url: %s)", path, blockList.URL())
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
