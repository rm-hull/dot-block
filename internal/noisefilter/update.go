package noisefilter

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/rm-hull/dot-block/internal/downloader"
)

type NoiseFilterUpdater struct {
	NoiseFilter *NoiseFilter
	URL         string
	Logger      *slog.Logger
}

func NewNoiseFilterUpdater(nf *NoiseFilter, url string, logger *slog.Logger) *NoiseFilterUpdater {
	return &NoiseFilterUpdater{
		NoiseFilter: nf,
		URL:         url,
		Logger:      logger,
	}
}

func (job *NoiseFilterUpdater) Run() {
	job.NoiseFilter.Reset()
	err := Fetch(job.URL, job.NoiseFilter, job.Logger)
	if err != nil {
		job.Logger.Error("failed to download noise filter for cron reload", "error", err, "url", job.URL)
	}
}

func Fetch(url string, nf *NoiseFilter, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	err := downloader.TransientDownload(ctx, logger, "", "noisefilter", url, "", func(tmpFile string, header http.Header) error {
		f, err := os.Open(tmpFile)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		if err := nf.Load(f); err != nil {
			return err
		}

		return nil
	})

	if err == nil {
		logger.Info("Noise filter loaded successfully", "count", len(nf.triplets))
	}
	return err
}
