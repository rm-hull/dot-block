package handlers

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestMetricFamilyToMap_OmitsEmptyLabels(t *testing.T) {
	value := 1.23
	mf := &dto.MetricFamily{
		Name: new("test_total"),
		Type: dto.MetricType_COUNTER.Enum(),
		Metric: []*dto.Metric{
			{
				Counter: &dto.Counter{Value: &value},
			},
		},
	}

	result := metricFamilyToMap(mf)
	metrics, ok := result["metrics"].([]map[string]any)
	assert.True(t, ok)
	assert.Len(t, metrics, 1)
	assert.NotContains(t, metrics[0], "labels")
	assert.Equal(t, value, metrics[0]["value"])
}

func TestMetricFamilyToMap_IncludesLabelsWhenPresent(t *testing.T) {
	value := 2.34
	mf := &dto.MetricFamily{
		Name: new("test_total"),
		Type: dto.MetricType_COUNTER.Enum(),
		Metric: []*dto.Metric{
			{
				Label: []*dto.LabelPair{
					{Name: new("name"), Value: new("foo")},
					{Name: new("value"), Value: new("bar")},
				},
				Counter: &dto.Counter{Value: &value},
			},
		},
	}

	result := metricFamilyToMap(mf)
	metrics, ok := result["metrics"].([]map[string]any)
	assert.True(t, ok)
	assert.Len(t, metrics, 1)
	assert.Contains(t, metrics[0], "labels")
	assert.Equal(t, map[string]string{"name": "foo", "value": "bar"}, metrics[0]["labels"])
	assert.Equal(t, value, metrics[0]["value"])
}
