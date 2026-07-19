package metrics

import (
	"math"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type BlockListMetrics struct {
	name        string
	mu          sync.RWMutex
	age         prometheus.GaugeFunc
	lastUpdated time.Time
}

var (
	sizeMetric    *prometheus.GaugeVec
	reloadsMetric *prometheus.CounterVec
	once          sync.Once
)

func initMetrics() {
	sizeMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blocklist_size",
		Help: "The number of entries in the blocklist",
	}, []string{"name"})

	reloadsMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "blocklist_reloads",
		Help: "The number of times the blocklist was reloaded",
	}, []string{"name"})

	prometheus.MustRegister(sizeMetric, reloadsMetric)
}

func NewBlockListMetrics(name string) (*BlockListMetrics, error) {
	once.Do(initMetrics)

	metrics := &BlockListMetrics{
		name:        name,
		lastUpdated: time.Now(),
	}

	metrics.age = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "blocklist_age",
		Help:        "The age (in seconds) since the blocklist was last reloaded",
		ConstLabels: prometheus.Labels{"name": name},
	}, func() float64 {
		metrics.mu.RLock()
		lastUpdated := metrics.lastUpdated
		metrics.mu.RUnlock()
		return math.Round(time.Since(lastUpdated).Seconds())
	})

	if err := shouldRegister(metrics.age); err != nil {
		return nil, errors.Wrap(err, "failed to register blocklist age metric")
	}

	return metrics, nil
}

func (m *BlockListMetrics) Update(n uint) {
	m.mu.Lock()
	m.lastUpdated = time.Now()
	m.mu.Unlock()
	sizeMetric.WithLabelValues(m.name).Set(float64(n))
	reloadsMetric.WithLabelValues(m.name).Inc()
}
