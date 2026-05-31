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
	cache    cache.Cache[string, []dns.RR]
	logger   *slog.Logger
	update   chan cacheUpdate
	done     chan struct{}
	onDrop   func()
	lastWarn time.Time
}

func NewDNSCache(maxSize int, logger *slog.Logger) *DNSCache {
	logger.Info("Initializing DNS cache", "maxCacheSize", maxSize, "updateBufferSize", CACHE_UPDATE_BUFFER_SIZE)
	c := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()

	dc := &DNSCache{
		cache:  c,
		logger: logger,
		update: make(chan cacheUpdate, CACHE_UPDATE_BUFFER_SIZE),
		done:   make(chan struct{}),
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

func (dc *DNSCache) OnDrop(fn func()) {
	dc.onDrop = fn
}

func (dc *DNSCache) Get(key string) ([]dns.RR, bool) {
	return dc.cache.Get(key)
}

func (dc *DNSCache) Set(key string, values []dns.RR, ttl time.Duration) {
	select {
	case <-dc.done:
		return
	case dc.update <- cacheUpdate{key: key, values: values, ttl: ttl}:
	default:
		if dc.onDrop != nil {
			dc.onDrop()
		}

		if time.Since(dc.lastWarn) > 1*time.Minute {
			dc.logger.Warn("DNS cache update channel full, dropping update", "key", key)
			dc.lastWarn = time.Now()
		}
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
