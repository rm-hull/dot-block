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
	job.dispatcher.logger.Info("Cleaning up expired DNS cache entries")
	job.dispatcher.cache.DeleteExpired()
	job.dispatcher.metrics.CacheReaperCalls.Inc()
}
