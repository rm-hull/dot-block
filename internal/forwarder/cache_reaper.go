package forwarder

import (
	"log/slog"

	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/robfig/cron/v3"
)

type CacheReaper struct {
	cache   *DNSCache
	logger  *slog.Logger
	metrics *metrics.DnsMetrics
}

func NewCacheReaperCronJob(dispatcher *DNSDispatcher) cron.Job {
	return &CacheReaper{cache: dispatcher.cache, logger: dispatcher.logger, metrics: dispatcher.metrics}
}

func (job *CacheReaper) Run() {
	sizeBefore := job.cache.Len()
	job.cache.DeleteExpired()

	sizeAfter := job.cache.Len()
	job.logger.Info("Cleaned up expired DNS cache entries",
		"size", sizeAfter,
		"removed", sizeBefore-sizeAfter)

	job.metrics.CacheReaperCalls.Inc()
}
