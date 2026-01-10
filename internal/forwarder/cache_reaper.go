package forwarder

import "github.com/robfig/cron/v3"

type CacheReaper struct {
	dispatcher *DNSDispatcher
}

func NewCacheReaperCronJob(dispatcher *DNSDispatcher) cron.Job {
	return &CacheReaper{
		dispatcher: dispatcher,
	}
}

func (job *CacheReaper) Run() {
	sizeBefore := job.dispatcher.cache.Len()
	job.dispatcher.cache.DeleteExpired()

	sizeAfter := job.dispatcher.cache.Len()
	job.dispatcher.logger.Info("Cleaned up expired DNS cache entries",
		"size", sizeAfter,
		"removed", sizeBefore-sizeAfter)

	job.dispatcher.metrics.CacheReaperCalls.Inc()
}
