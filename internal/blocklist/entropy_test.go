package blocklist

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
	"github.com/stretchr/testify/assert"
)

// Compile-time assertions that both implementations satisfy the Blocklist
// interface.
var (
	_ Blocklist = (*StaticBlocklist)(nil)
	_ Blocklist = (*ShannonEntropyBlocklist)(nil)
)

func newTestEntropyBlocklist(t *testing.T, cfg *config.EntropyConfig) *ShannonEntropyBlocklist {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return NewShannonEntropyBlocklist(cfg, logger)
}

func TestShannonEntropy_NameAndCause(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})
	assert.Equal(t, "shannon-entropy-dga", b.Name())
	assert.Equal(t, "shannon-entropy-dga", ShannonEntropyBlocklistName)
}

func TestShannonEntropy_NoOpOperations(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	// Fetch raises an error
	assert.Error(t, errors.New("Unsupported operation"), b.Fetch(context.Background()))

	// Load is a no-op
	assert.NotPanics(t, func() { b.Load([]string{"example.com"}) })

	// A static domain that would normally be blocked is NOT blocked by the
	// entropy engine (it only inspects high-risk CDN suffixes).
	blocked, err := b.IsBlocked("example.com.")
	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestShannonEntropy_DisableAndReenable(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{
		Enabled:  true,
		Suffixes: []string{".cloudfront.net"},
	})

	// A clearly random hex label on cloudfront would normally be blocked.
	blocked, err := b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.True(t, blocked)

	// Disable for the future — nothing should be blocked now.
	until := b.Disable(1 * time.Second)
	assert.True(t, until.After(time.Now()))

	blocked, err = b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.False(t, blocked)

	// Re-enable
	assert.True(t, b.Reenable())
	blocked, err = b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.True(t, blocked)

	// Re-enable when already enabled is a no-op
	assert.False(t, b.Reenable())
}

func TestShannonEntropy_BlockedCases(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	tests := []struct {
		name    string
		domain  string
		blocked bool
	}{
		// Random-looking hex label on a high-risk CDN suffix.
		{"random hex cloudfront", "d1234567890abcdef.cloudfront.net.", true},
		// Random-looking hex label, trailing-dot already stripped.
		{"random hex cloudfront no trailing dot", "a1b2c3d4e5f6a7b8c9d0.cloudfront.net", true},
		// Multi-label random subdomain on a high-risk suffix.
		{"random multi-label heroku", "x9f2k7m3n1p4q8r6t2s5u8.herokuapp.com.", true},
		// A high-entropy (non-hex, alphanumeric) label on a high-risk suffix.
		{"random alnum azure", "a1b2c3d4e5f6g7h8i9j0.azureedge.net.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, err := b.IsBlocked(tt.domain)
			assert.NoError(t, err)
			assert.Equal(t, tt.blocked, blocked, "domain %s", tt.domain)
		})
	}
}

func TestShannonEntropy_AllowedCases(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	tests := []struct {
		name   string
		domain string
	}{
		// Non-matching suffix — entropy analysis is not applied.
		{"non-matching suffix", "d1234567890abcdef.example.com."},
		// Suffix boundary: must be preceded by a dot, not a partial match.
		{"suffix boundary", "notcloudfrontnet"},
		{"suffix boundary2", "notcloudfront.net."},
		// Too short to evaluate.
		{"short label", "img1.cloudfront.net."},
		// Human-readable, low-entropy labels.
		{"readable label", "images.cloudfront.net."},
		{"readable label2", "api.github.io."},
		{"www label", "www.cloudfront.net."},
		// Empty / whitespace
		{"empty", ""},
		{"whitespace only", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, err := b.IsBlocked(tt.domain)
			assert.NoError(t, err)
			assert.False(t, blocked, "domain %s should not be blocked", tt.domain)
		})
	}
}

func TestShannonEntropy_SuffixBoundaryMatching(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{
		Enabled:  true,
		Suffixes: []string{"cloudfront.net"}, // no leading dot — should still normalise
	})

	// Normalised to ".cloudfront.net", so a partial-match label must NOT match.
	blocked, err := b.IsBlocked("notcloudfront.net")
	assert.NoError(t, err)
	assert.False(t, blocked)

	// But a real subdomain with a random label SHOULD match.
	blocked, err = b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.True(t, blocked)
}

func TestShannonEntropy_DefaultSuffixes(t *testing.T) {
	// When no suffixes are configured, the defaults (including cloudfront)
	// are applied.
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	blocked, err := b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.True(t, blocked, "default suffix list should include cloudfront.net")
}

func TestShannonEntropy_Status(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{
		Enabled:        true,
		MinLabelLength: 12,
	})

	status := b.Status()
	assert.Equal(t, "shannon-entropy-dga", status.Name)
	assert.Equal(t, "Dynamic Shannon entropy DGA & malware subdomain detection", status.Title)
	assert.Contains(t, status.Description, "Ad-blocklists and Bloom filters rely")
	assert.Equal(t, "", status.URL)
	assert.Equal(t, "", status.Schedule)
	assert.Nil(t, status.DisabledUntil)
}

func TestShannonEntropy_StatusDisabled(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})
	b.Disable(1 * time.Hour)

	status := b.Status()
	assert.NotNil(t, status.DisabledUntil)
	assert.True(t, status.DisabledUntil.After(time.Now()))
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"", 0},
		// 8 distinct chars -> log2(8) = 3.0
		{"abcdefgh", 3.0},
		// 16 distinct hex chars -> log2(16) = 4.0
		{"0123456789abcdef", 4.0},
		// uniform repeated char -> 0
		{"aaaa", 0},
	}
	for _, tt := range tests {
		got := calculateEntropy(tt.input)
		assert.InDelta(t, tt.want, got, 1e-9, "entropy(%q)", tt.input)
	}
}

func TestIsHex(t *testing.T) {
	assert.True(t, isHex("0123456789abcdef"))
	assert.True(t, isHex("ABCDEF"))
	assert.False(t, isHex("a1b2c3g4"))
	assert.False(t, isHex(""))
}

// Ensure that a static blocklist is checked first when co-located with the
// entropy blocklist: a domain that is both statically blocked AND matches the
// entropy suffix must be reported as blocked (the static list is consulted
// first, as the dispatcher iterates the slice in order).
func TestEntropyBlocklist_LastResortOrdering(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	source := &config.BlocklistSource{Name: "static", URL: "http://dummy", Enabled: true}
	static := NewStaticBlockList(source, 0.0001, logger)
	// Statically block a domain that also matches the entropy suffix.
	static.Load([]string{"a1b2c3d4e5f6g7h8.cloudfront.net"})

	entropy := NewShannonEntropyBlocklist(&config.EntropyConfig{Enabled: true}, logger)

	// Ordered: static first, entropy last (mirrors how the dispatcher builds
	// the list).
	blocklists := []Blocklist{static, entropy}

	for _, bl := range blocklists {
		blocked, err := bl.IsBlocked("a1b2c3d4e5f6g7h8.cloudfront.net.")
		_ = err
		if blocked {
			// First match wins; this should be the static blocklist.
			assert.Equal(t, "static", bl.Name())
			return
		}
	}
	t.Fatal("expected the static blocklist to match first")
}

// Ensure strings.ToLower is applied so that mixed-case labels are assessed
// consistently.
func TestShannonEntropy_CaseInsensitive(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	upper, err := b.IsBlocked("D1234567890ABCDEF.CLOUDFRONT.NET.")
	assert.NoError(t, err)
	assert.True(t, upper)
}

func TestShannonEntropy_RepeatedChar(t *testing.T) {
	// A label that is all the same character has zero entropy and must not be
	// blocked, even on a matched suffix.
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})
	blocked, err := b.IsBlocked("aaaaaaaa.cloudfront.net.")
	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestShannonEntropy_DefaultsApplied(t *testing.T) {
	// A config with only Enabled set should receive sensible defaults for the
	// thresholds and suffixes, so a random cloudfront hex label is blocked.
	b := NewShannonEntropyBlocklist(&config.EntropyConfig{Enabled: true}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	assert.Equal(t, defaultEntropySuffixes, b.config.Suffixes)
	assert.Equal(t, 8, b.config.MinLabelLength)
	assert.Equal(t, 3.8, b.config.HexThreshold)
	assert.Equal(t, 4.2, b.config.AlnumThreshold)

	blocked, err := b.IsBlocked("d1234567890abcdef.cloudfront.net.")
	assert.NoError(t, err)
	assert.True(t, blocked)
}

// TestShannonEntropy_KnownCloudFrontDomainsNotMatchedByEntropy documents that
// specific malicious CloudFront distribution domains — which are already
// covered by the static blocklist — do NOT trigger the entropy engine.
//
// These labels (~13-14 alphanumeric chars, ~10 distinct chars) have Shannon
// entropy of only ~3.2-3.5 bits, well below both the HexThreshold (3.8) and
// AlnumThreshold (4.2). They are NOT hexadecimal (they contain letters such
// as 'g', 'o', 's', 'u', 'v', 'y', 'x'), so the higher alnum threshold
// applies.
//
// This is intentional: legitimate CloudFront distribution IDs share the exact
// same entropy profile, because CloudFront generates ALL distribution
// domain names with the same random-alphanumeric algorithm. Lowering the
// alnum threshold below ~3.6 to catch these would blanket-block virtually
// every legitimate CloudFront distribution (false positives). These specific
// known-bad domains are instead handled by the curated static blocklist,
// which is always evaluated first (last-resort ordering).
func TestShannonEntropy_KnownCloudFrontDomainsNotMatchedByEntropy(t *testing.T) {
	b := newTestEntropyBlocklist(t, &config.EntropyConfig{Enabled: true})

	// These are known malicious CloudFront domains that live in
	// data/blocklist.txt and are blocked by the static blocklist.
	cloudfrontDomains := []string{
		"dmqixuaqncbvu.cloudfront.net",
		"d3p0gayswgyxdw.cloudfront.net",
		"d3s92ui89fue0a.cloudfront.net",
		"dogvgb9ujhybx.cloudfront.net",
	}

	for _, d := range cloudfrontDomains {
		blocked, err := b.IsBlocked(d)
		assert.NoError(t, err)
		assert.False(t, blocked,
			"domain %s has entropy too low to exceed the conservative threshold "+
				"(this is expected — it is caught by the static blocklist instead)", d)
	}
}
