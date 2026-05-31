package forwarder

import (
	"log/slog"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
)

const CACHE_UPDATE_BUFFER_SIZE = 10_000

type cacheUpdate struct {
	key    string
	values []dns.RR
	ttl    time.Duration
}

type DNSCache struct {
	cache  cache.Cache[string, []dns.RR]
	logger *slog.Logger
	update chan cacheUpdate
	done   chan struct{}
}

func NewDNSCache(maxSize int, logger *slog.Logger) *DNSCache {
	logger.Info("Initializing DNS cache", "maxCcheSize", maxSize, "updateBufferSize", CACHE_UPDATE_BUFFER_SIZE)
	c := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()

	dc := &DNSCache{
		cache:  c,
		update: make(chan cacheUpdate, CACHE_UPDATE_BUFFER_SIZE),
		logger: logger,
	}

	go dc.runUpdateWorker()
	logger.Info("Started DNS cache update worker...")

	return dc
}

func (dc *DNSCache) runUpdateWorker() {
	for {
		select {
		case update, ok := <-dc.update:
			if !ok {
				return
			}
			dc.cache.Set(update.key, update.values, update.ttl)
		case <-dc.done:
			return
		}
	}
}

func (dc *DNSCache) Close() {
	close(dc.done)
}

//go:inline
func (dc *DNSCache) Get(key string) ([]dns.RR, bool) {
	return dc.cache.Get(key)
}

//go:inline
func (dc *DNSCache) Set(key string, values []dns.RR, ttl time.Duration) {
	select {
	case <-dc.done:
		return
	case dc.update <- cacheUpdate{key: key, values: values, ttl: ttl}:
	default:
		dc.logger.Warn("DNS cache update channel full, dropping update", "key", key)
	}
}

func (dc *DNSCache) DeleteExpired() {
	dc.cache.DeleteExpired()
}

func (dc *DNSCache) Len() int {
	return dc.cache.Len()
}

func (dc *DNSCache) Stat() cache.Stats {
	return dc.cache.Stat()
}
