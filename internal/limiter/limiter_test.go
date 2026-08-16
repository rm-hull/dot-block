package limiter

import (
	"testing"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockMetrics struct {
	rateLimitedCalled map[Reason]int
	trackedIPs        int
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		rateLimitedCalled: make(map[Reason]int),
	}
}

func (m *mockMetrics) IncRateLimited(reason Reason) {
	m.rateLimitedCalled[reason]++
}

func (m *mockMetrics) SetTrackedIPs(n int) {
	m.trackedIPs = n
}

func TestLimiter_Disabled(t *testing.T) {
	metrics := newMockMetrics()
	cfg := &config.RateLimitConfig{
		Enabled: false,
	}
	l, err := New(cfg, metrics)
	require.NoError(t, err)
	defer l.Close()

	ok, reason := l.Allow("1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, ReasonNone, reason)
}

func TestLimiter_TokenBucket_RPS(t *testing.T) {
	metrics := newMockMetrics()
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             2,
		BanDuration:       time.Minute,
		MaxTrackedIPs:     100,
	}
	l, err := New(cfg, metrics)
	require.NoError(t, err)
	defer l.Close()

	ip := "192.168.1.10"

	// First two requests should pass due to burst = 2
	ok, _ := l.Allow(ip)
	assert.True(t, ok)

	ok, _ = l.Allow(ip)
	assert.True(t, ok)

	// Third request should be rate limited (exceeded RPS/burst)
	ok, reason := l.Allow(ip)
	assert.False(t, ok)
	assert.Equal(t, ReasonExceededRPS, reason)
	assert.Equal(t, 1, metrics.rateLimitedCalled[ReasonExceededRPS])
}

func TestLimiter_NXDOMAIN_Flood_And_Ban(t *testing.T) {
	metrics := newMockMetrics()
	cfg := &config.RateLimitConfig{
		Enabled:            true,
		RequestsPerSecond:  1000,
		Burst:              1000,
		BanDuration:        1 * time.Hour,
		NXDOMAINWindow:     1 * time.Minute,
		NXDOMAINMinQueries: 5,
		NXDOMAINThreshold:  0.8,
		MaxTrackedIPs:      100,
	}
	l, err := New(cfg, metrics)
	require.NoError(t, err)
	defer l.Close()

	ip := "10.0.0.5"

	// Send 4 queries (below NXDOMAINMinQueries = 5) with NXDOMAIN
	for i := 0; i < 4; i++ {
		ok, _ := l.Allow(ip)
		assert.True(t, ok)
		l.RecordResult(ip, true)
	}
	l.Flush()

	// Should not be banned yet
	bannedMap := l.BannedIPs()
	assert.Empty(t, bannedMap)

	// 5th query with NXDOMAIN triggers threshold (5/5 = 100% >= 80%)
	ok, _ := l.Allow(ip)
	assert.True(t, ok)
	l.RecordResult(ip, true)
	l.Flush()

	// Now the IP should be banned
	bannedMap = l.BannedIPs()
	assert.Contains(t, bannedMap, ip)

	// Subsequent Allow should fail with ReasonBanned
	ok, reason := l.Allow(ip)
	assert.False(t, ok)
	assert.Equal(t, ReasonBanned, reason)
	assert.Equal(t, 1, metrics.rateLimitedCalled[ReasonBanned])

	// RetryAfter should return remaining ban duration
	retryAfter := l.RetryAfter(ip)
	assert.Greater(t, retryAfter, 0*time.Second)
}

func TestLimiter_RetryAfter_RPS(t *testing.T) {
	metrics := newMockMetrics()
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BanDuration:       time.Minute,
	}
	l, err := New(cfg, metrics)
	require.NoError(t, err)
	defer l.Close()

	ip := "172.16.0.1"

	// Exhaust token
	ok, _ := l.Allow(ip)
	assert.True(t, ok)

	// Next one fails
	ok, _ = l.Allow(ip)
	assert.False(t, ok)

	retryAfter := l.RetryAfter(ip)
	assert.GreaterOrEqual(t, retryAfter, 1*time.Second)
}

func TestLimiter_Reap(t *testing.T) {
	metrics := newMockMetrics()
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             10,
		IdleTTL:           10 * time.Millisecond,
		NXDOMAINWindow:    10 * time.Millisecond,
		BanDuration:       10 * time.Millisecond,
		MaxTrackedIPs:     100,
	}
	l, err := New(cfg, metrics)
	require.NoError(t, err)
	defer l.Close()

	ip := "10.1.1.1"
	ok, _ := l.Allow(ip)
	assert.True(t, ok)
	l.RecordResult(ip, true)
	l.Flush()
	l.ban(ip, time.Now().Add(-1*time.Hour)) // Force ban expiry in the past

	assert.Equal(t, 1, metrics.trackedIPs)

	// Wait for TTLs to pass
	time.Sleep(20 * time.Millisecond)

	l.Reap()

	// Should be reaped / cleaned up
	assert.Empty(t, l.BannedIPs())
}
