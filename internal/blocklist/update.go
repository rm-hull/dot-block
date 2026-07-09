package blocklist

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cockroachdb/errors"
	"github.com/rm-hull/dot-block/internal/downloader"
)

var prefixes = []string{"0.0.0.0 ", "*.", "www."}

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
	if err := LoadFromURLs(job.Blocklist, job.URLs); err != nil {
		job.Blocklist.logger.Error("failed to download blocklist for cron reload", "error", err)
	}
}

func LoadFromURLs(bl *BlockList, urls []string) error {
	type downloadedFile struct {
		path   string
		url    string
		isTemp bool
	}
	files := make([]downloadedFile, 0, len(urls))

	for _, url := range urls {
		path, _, isTemp, err := downloader.Download(bl.logger, "", "blocklist", url, "")
		if err != nil {
			return errors.Wrapf(err, "failed to download blocklist for counting: %s", url)
		}
		files = append(files, downloadedFile{path: path, url: url, isTemp: isTemp})
	}

	defer func() {
		for _, f := range files {
			if f.isTemp {
				_ = os.Remove(f.path)
			}
		}
	}()

	var totalCount uint
	for _, f := range files {
		count, err := countFromFile(f.path, bl.logger)
		if err != nil {
			return errors.Wrapf(err, "failed to count hosts in file %s (url: %s)", f.path, f.url)
		}
		totalCount += uint(count)
	}

	bf := bloom.NewWithEstimates(totalCount, bl.fpRate)
	for _, f := range files {
		if err := streamFromFile(f.path, bl.logger, func(host string) {
			bf.AddString(host)
		}); err != nil {
			return errors.Wrapf(err, "failed to stream hosts from file %s (url: %s)", f.path, f.url)
		}
	}

	bl.ApplyBloomFilter(bf, totalCount)
	return nil
}

func Fetch(url string, logger *slog.Logger) ([]string, error) {
	blocklist := make([]string, 0, 100_000)
	err := streamHosts(url, logger, func(host string) {
		blocklist = append(blocklist, host)
	})

	if err == nil {
		logger.Info("Blocklist loaded successfully", "count", len(blocklist))
	}
	return blocklist, err
}

func scanBlocklist(file *os.File, logger *slog.Logger, handler func(string)) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# ") {
			logger.Info("Blocklist", "comment", line)
		} else if len(strings.Trim(line, "# ")) == 0 || strings.HasPrefix(line, "## ") {
			continue
		} else {
			for _, prefix := range prefixes {
				if after, ok := strings.CutPrefix(line, prefix); ok {
					line = after
				}
			}
			handler(line)
		}
	}
	return scanner.Err()
}

func countFromFile(path string, logger *slog.Logger) (int, error) {
	count := 0
	file, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "failed to open blocklist file for counting")
	}
	defer file.Close()
	err = scanBlocklist(file, logger, func(_ string) {
		count++
	})
	return count, err
}

func streamFromFile(path string, logger *slog.Logger, handler func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "failed to open blocklist file for streaming")
	}
	defer file.Close()
	return scanBlocklist(file, logger, handler)
}

func streamHosts(url string, logger *slog.Logger, handler func(string)) error {
	return downloader.TransientDownload(logger, "", "blocklist-stream", url, "", func(tmpFile string, header http.Header) error {
		return streamFromFile(tmpFile, logger, handler)
	})
}
