package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type StatsCollector struct {
	callbackFn func() map[string]int
	desc       *prometheus.Desc
}

func (coll *StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- coll.desc
}

func (coll *StatsCollector) Collect(ch chan<- prometheus.Metric) {
	for labels, value := range coll.callbackFn() {
		labelsArr := strings.Split(labels, ",")
		ch <- prometheus.MustNewConstMetric(
			coll.desc,
			prometheus.GaugeValue,
			float64(value),
			labelsArr...,
		)
	}
}

func NewStatsCollector(desc string, labels []string, help string, callbackFn func() map[string]int) *StatsCollector {
	return &StatsCollector{
		callbackFn: callbackFn,
		desc: prometheus.NewDesc(
			desc,
			help,
			labels,
			nil,
		),
	}
}
