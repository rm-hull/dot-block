package metrics

import (
	"math"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type BlockListMetrics struct {
	mu          sync.RWMutex
	size        prometheus.Gauge
	age         prometheus.GaugeFunc
	reloads     prometheus.Counter
	lastUpdated time.Time
}

func NewBlockListMetrics() (*BlockListMetrics, error) {

	metrics := &BlockListMetrics{
		lastUpdated: time.Now(),
	}
	metrics.size = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blocklist_size",
		Help: "The number of entries in the blocklist",
	})

	metrics.age = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "blocklist_age",
		Help: "The age (in seconds) since the blocklist was last reloaded",
	}, func() float64 {
		metrics.mu.RLock()
		lastUpdated := metrics.lastUpdated
		metrics.mu.RUnlock()
		return math.Round(time.Since(lastUpdated).Seconds())
	})

	metrics.reloads = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blocklist_reloads",
		Help: "The number of times the blocklist was reloaded",
	})

	if err := shouldRegister(metrics.size, metrics.age, metrics.reloads); err != nil {
		return nil, errors.Wrap(err, "failed to register blocklist metrics")
	}

	return metrics, nil
}

func (m *BlockListMetrics) Update(n uint) {
	m.mu.Lock()
	m.lastUpdated = time.Now()
	m.mu.Unlock()
	m.size.Set(float64(n))
	m.reloads.Inc()
}
