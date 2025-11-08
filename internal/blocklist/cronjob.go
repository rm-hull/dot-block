package blocklist

import (
	"github.com/robfig/cron/v3"
)

type CronJob struct {
	blocklist *BlockList
	url       string
}

func NewCronJob(blocklist *BlockList, url string) cron.Job {
	return &CronJob{
		blocklist: blocklist,
		url:       url,
	}
}

func (job *CronJob) Run() {
	items, err := DownloadBlocklist(job.url, job.blocklist.logger)
	if err != nil {
		panic(err)
	}

	job.blocklist.Load(items)
}
