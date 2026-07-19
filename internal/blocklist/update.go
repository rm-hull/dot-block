package blocklist

type Updater struct {
	Blocklists []*BlockList
}

func NewUpdater(blocklists []*BlockList) *Updater {
	return &Updater{Blocklists: blocklists}
}

func (job *Updater) Run() {
	for _, blockList := range job.Blocklists {
		if err := blockList.Fetch(); err != nil {
			blockList.logger.Error("failed to download blocklist for cron reload",
				"error", err,
				"name", blockList.name,
				"url", blockList.url)
		}
	}
}
