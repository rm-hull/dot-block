package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func MetricsJSON(reg *prometheus.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		mfs, err := reg.Gather()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result := make(map[string]any)
		for _, mf := range mfs {
			result[mf.GetName()] = metricFamilyToMap(mf)
		}

		c.JSON(http.StatusOK, result)
	}
}

func metricFamilyToMap(mf *dto.MetricFamily) map[string]any {
	var metrics []map[string]any
	for _, m := range mf.GetMetric() {
		entry := map[string]any{}
		labels := labelsToMap(m.GetLabel())
		if len(labels) > 0 {
			entry["labels"] = labels
		}
		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			entry["value"] = m.GetCounter().GetValue()
		case dto.MetricType_GAUGE:
			entry["value"] = m.GetGauge().GetValue()
		case dto.MetricType_HISTOGRAM:
			entry["buckets"] = m.GetHistogram().GetBucket()
			entry["sample_count"] = m.GetHistogram().GetSampleCount()
			entry["sample_sum"] = m.GetHistogram().GetSampleSum()
		case dto.MetricType_SUMMARY:
			entry["sample_count"] = m.GetSummary().GetSampleCount()
			entry["sample_sum"] = m.GetSummary().GetSampleSum()
		}
		metrics = append(metrics, entry)
	}
	return map[string]any{
		"help":    mf.GetHelp(),
		"type":    mf.GetType().String(),
		"metrics": metrics,
	}
}

func labelsToMap(labels []*dto.LabelPair) map[string]string {
	m := make(map[string]string)
	for _, l := range labels {
		m[l.GetName()] = l.GetValue()
	}
	return m
}
