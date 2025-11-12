package forwarder

import "github.com/robfig/cron/v3"

type CronJob struct{
	dispatcher *DNSDispatcher
}

func NewCronJob(dispatcher *DNSDispatcher) cron.Job {
	return &CronJob{
		dispatcher: dispatcher,
	}
}

func (job *CronJob) Run() {

	job.dispatcher.logger.Info("Running cache reaper to cleardown expired entries.")
	job.dispatcher.cache.DeleteExpired()
	job.dispatcher.metrics.CacheReaperCalls.Inc()
}
