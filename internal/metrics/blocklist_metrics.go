package metrics

import (
	"math"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type BlockListMetrics struct {
	count *prometheus.Gauge
	age   *prometheus.CounterFunc
}

func NewBlockListMetrics(size uint) (*BlockListMetrics, error) {
	now := time.Now()
	count := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blocklist_size",
		Help: "The number of entries in the blocklist",
	})
	count.Set(float64(size))

	age := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "blocklist_age",
		Help: "The age (in seconds) since the blocklist was loaded",
	}, func() float64 {
		return math.Round(time.Since(now).Seconds())
	})

	if err := shouldRegister(count, age); err != nil {
		return nil, errors.Wrap(err, "failed to register blocklist metrics")
	}

	return &BlockListMetrics{
		count: &count,
		age:   &age,
	}, nil
}
