package blocklist

import (
	"context"
	"time"
)

type Updater struct {
	Blocklist *StaticBlocklist
	Timeout   time.Duration
}

func NewUpdater(blocklist *StaticBlocklist, timeout time.Duration) *Updater {
	return &Updater{Blocklist: blocklist, Timeout: timeout}
}

func (job *Updater) Run() {
	ctx, cancel := context.WithTimeout(context.Background(), job.Timeout)
	defer cancel()

	if err := job.Blocklist.Fetch(ctx); err != nil {
		job.Blocklist.logger.Error("failed to download blocklist",
			"error", err,
			"name", job.Blocklist.Name(),
			"url", job.Blocklist.URL())
	}
}
