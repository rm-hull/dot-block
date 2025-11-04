package internal

import (
	"github.com/prometheus/client_golang/prometheus"
)

type StatsCollector struct {
	callbackFn func() map[string]int
	desc  *prometheus.Desc
}

func (coll *StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- coll.desc
}

func (coll *StatsCollector) Collect(ch chan<- prometheus.Metric) {
	for label, value := range coll.callbackFn() {
		ch <- prometheus.MustNewConstMetric(
			coll.desc,
			prometheus.GaugeValue,
			float64(value),
			label,
		)
	}
}

func NewStatsCollector(desc, help string, callbackFn func() map[string]int) *StatsCollector {
	return &StatsCollector{
		callbackFn: callbackFn,
		desc: prometheus.NewDesc(
			desc,
			help,
			[]string{"type"},
			nil,
		),
	}
}
