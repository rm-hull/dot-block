package config

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStructToMap_Redacted(t *testing.T) {
	t.Run("redacts non-zero redacted field", func(t *testing.T) {
		cfg := &Config{
			Server: &ServerConfig{
				MetricsAuth: "user:secretpass",
			},
		}

		val := structToMap(cfg)
		m, ok := val.(map[string]any)
		assert.True(t, ok)

		serverMap, ok := m["server"].(map[string]any)
		assert.True(t, ok)

		assert.Equal(t, "********", serverMap["metrics_auth"])
	})

	t.Run("does not include zero value redacted field with omitempty", func(t *testing.T) {
		cfg := &Config{
			Server: &ServerConfig{
				MetricsAuth: "",
			},
		}

		val := structToMap(cfg)
		m, ok := val.(map[string]any)
		assert.True(t, ok)

		serverMap, ok := m["server"].(map[string]any)
		assert.True(t, ok)

		_, exists := serverMap["metrics_auth"]
		assert.False(t, exists, "metrics_auth should be omitted when empty (omitempty)")
	})

	t.Run("handles time.Duration formatting", func(t *testing.T) {
		cfg := &Config{
			DNS: &DNSConfig{
				Timeouts: &TimeoutsConfig{
					Read: 5 * time.Second,
				},
			},
		}

		val := structToMap(cfg)
		m, ok := val.(map[string]any)
		assert.True(t, ok)

		dnsMap, ok := m["dns"].(map[string]any)
		assert.True(t, ok)

		timeoutsMap, ok := dnsMap["timeouts"].(map[string]any)
		assert.True(t, ok)

		assert.Equal(t, "5s", timeoutsMap["read"])
	})

	t.Run("LogValue implements slog.LogValuer", func(t *testing.T) {
		cfg := &Config{
			Server: &ServerConfig{
				MetricsAuth: "admin:password",
			},
		}

		slogVal := cfg.LogValue()
		assert.Equal(t, slog.KindAny, slogVal.Kind())
	})
}
