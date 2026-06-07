package blocklist

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/downloader"
)

type BlocklistUpdater struct {
	blocklist *BlockList
	urls      []string
}

func NewBlocklistUpdater(blocklist *BlockList, urls []string) *BlocklistUpdater {
	return &BlocklistUpdater{
		blocklist: blocklist,
		urls:      urls,
	}
}

func (job *BlocklistUpdater) Run() {
	allHosts := make([]string, 0)
	for _, url := range job.urls {
		hosts, err := Fetch(url, job.blocklist.logger)
		if err != nil {
			job.blocklist.logger.Error("failed to download blocklist for cron reload", "error", err, "url", url)
			return
		}

		allHosts = append(allHosts, hosts...)
	}
	job.blocklist.Load(allHosts)
}

func (job *BlocklistUpdater) NewHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		go job.Run()
		c.JSON(http.StatusAccepted, gin.H{
			"message": "Blocklist reload triggered",
			"urls":    job.urls,
		})
	}
}

func (job *BlocklistUpdater) NewCheckHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var domains []string

		if c.ContentType() == "application/json" {
			if err := c.ShouldBindJSON(&domains); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON array of domains"})
				return
			}
		} else {
			body, err := c.GetRawData()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
				return
			}
			lines := strings.Split(string(body), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					domains = append(domains, line)
				}
			}
		}

		allowed := make([]string, 0)
		blocked := make([]string, 0)

		for _, domain := range domains {
			isBlocked, err := job.blocklist.IsBlocked(domain)
			if err != nil {
				allowed = append(allowed, domain)
				continue
			}
			if isBlocked {
				blocked = append(blocked, domain)
			} else {
				allowed = append(allowed, domain)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"allowed": allowed,
			"blocked": blocked,
		})
	}
}

func Fetch(url string, logger *slog.Logger) ([]string, error) {
	blocklist := make([]string, 0, 100_000)
	err := downloader.TransientDownload(logger, "blocklist", url, "", func(tmpFile string, header http.Header) error {
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
				if after, ok := strings.CutPrefix(line, "0.0.0.0 "); ok {
					line = after
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
