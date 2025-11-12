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
	job.dispatcher.logger.Info("Running cache reaper to cleardown expired entries.")
	job.dispatcher.cache.DeleteExpired()
	job.dispatcher.metrics.CacheReaperCalls.Inc()
}
