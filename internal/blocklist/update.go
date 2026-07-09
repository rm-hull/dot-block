package blocklist

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rm-hull/dot-block/internal/downloader"
)

var PREFIX_LIST = []string{"*.", "www.", "0.0.0.0 "}

type BlocklistUpdater struct {
	Blocklist *BlockList
	URLs      []string
}

func NewBlocklistUpdater(blocklist *BlockList, urls []string) *BlocklistUpdater {
	return &BlocklistUpdater{
		Blocklist: blocklist,
		URLs:      urls,
	}
}

func (job *BlocklistUpdater) Run() {
	allHosts := make([]string, 0)
	for _, url := range job.URLs {
		hosts, err := Fetch(url, job.Blocklist.logger)
		if err != nil {
			job.Blocklist.logger.Error("failed to download blocklist for cron reload", "error", err, "url", url)
			return
		}

		allHosts = append(allHosts, hosts...)
	}
	job.Blocklist.Load(allHosts)
}

func Fetch(url string, logger *slog.Logger) ([]string, error) {
	blocklist := make([]string, 0, 100_000)
	err := downloader.TransientDownload(logger, "", "blocklist", url, "", func(tmpFile string, header http.Header) error {
		file, err := os.Open(tmpFile)
		if err != nil {
			return errors.Wrap(err, "failed to open downloaded blocklist")
		}

		defer func() {
			if err := file.Close(); err != nil {
				logger.Warn("error closing blocklist file", "error", err)
			}
		}()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "# ") {
				logger.Info("Blocklist", "comment", line)
			} else if len(strings.Trim(line, "# ")) == 0 || strings.HasPrefix(line, "## ") {
				continue
			} else {
				for _, prefix := range PREFIX_LIST {
					if after, ok := strings.CutPrefix(line, prefix); ok {
						line = after
					}
				}
				blocklist = append(blocklist, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "error reading response body")
		}

		return nil
	})

	logger.Info("Blocklist loaded successfully", "count", len(blocklist))
	return blocklist, err
}
