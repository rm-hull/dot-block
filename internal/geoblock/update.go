package geoblock

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rm-hull/dot-block/internal/downloader"
)

type IpinfoUpdater struct {
	logger      *slog.Logger
	fileName    string
	token       string
	geoIpLookup GeoIpLookup
}

func NewIpinfoUpdaterCronJob(logger *slog.Logger, fileName string, token string, geoIpLookup GeoIpLookup) *IpinfoUpdater {
	return &IpinfoUpdater{
		logger:      logger,
		fileName:    fileName,
		token:       token,
		geoIpLookup: geoIpLookup,
	}
}

func (job *IpinfoUpdater) Run() {
	if _, err := Fetch(job.fileName, job.token, job.logger); err != nil {
		job.logger.Error("failed to download ip2location list for cron reload", "error", err)
	}

	if err := job.geoIpLookup.Reopen(); err != nil {
		job.logger.Error("failed to reopen geoblock database after update", "error", err)
	}
}

func Fetch(fileName string, token string, logger *slog.Logger) ([]string, error) {

	if token == "" {
		return nil, errors.New("ipinfo token not configured (set geoblock.ipinfo.token in config.yaml)")
	}
	url := fmt.Sprintf("https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token=%s", token)

	dataDir := path.Dir(fileName)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, errors.Wrapf(err, "failed to create data directory %q", dataDir)
	}

	files := make([]string, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	err := downloader.TransientDownload(ctx, logger, dataDir, "ipinfo", url, token, func(srcPath string, header http.Header) error {
		logger.Info("Moving downloaded file", "to", fileName)
		if err := os.Rename(srcPath, fileName); err != nil {
			return errors.Wrapf(err, "failed to move file from %q to %q", srcPath, fileName)
		}
		files = append(files, fileName)

		return nil
	})

	return files, err
}
