package blocklist

import (
	"context"
	"sync"
	"time"
)

type Updater struct {
	Blocklists []*BlockList
	Timeout    time.Duration
}

func NewUpdater(blocklists []*BlockList, timeout time.Duration) *Updater {
	return &Updater{Blocklists: blocklists, Timeout: timeout}
}

func (job *Updater) Run() {
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), job.Timeout)
	defer cancel()
	
	for _, blockList := range job.Blocklists {
		wg.Add(1)
		go func(bl *BlockList) {
			defer wg.Done()

			if err := bl.Fetch(ctx); err != nil {
				bl.logger.Error("failed to download blocklist",
					"error", err,
					"name", bl.name,
					"url", bl.url)
			}
		}(blockList)
	}
	wg.Wait()
}
