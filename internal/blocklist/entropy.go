package blocklist

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/rm-hull/dot-block/internal/config"
)

// Name under which entropy-based blocks are reported as the "cause" in
// blocked responses, telemetry and the SSE event stream.
const ShannonEntropyBlocklistName = "shannon-entropy-dga"

// defaultEntropySuffixes are the shared-infrastructure / CDN suffixes that are
// commonly abused to host dynamically generated (often DGA-produced)
// subdomains. Only domains ending in one of these suffixes are candidates
// for entropy analysis, which keeps the expensive entropy calculation off the
// hot path for the vast majority of queries.
var defaultEntropySuffixes = []string{
	".cloudfront.net",
	".herokuapp.com",
	".azureedge.net",
	".github.io",
	".s3.amazonaws.com",
	".storage.googleapis.com",
	".googleusercontent.com",
	".blob.core.windows.net",
}

// ShannonEntropyBlocklist is a heuristic blocklist that dynamically flags
// subdomains of high-risk shared hosting / CDN suffixes whose leftmost
// subdomain label looks randomly generated (as is typical of DGA malware and
// command-and-control infrastructure).
//
// It does not download anything, so Fetch is a no-op, and it holds no set of
// static entries — IsBlocked performs an on-the-fly analysis of the queried
// domain. Because it is appended to the dispatcher's blocklist list *after*
// the static blocklists, it is only consulted as a last resort when no static
// blocklist matches.
type ShannonEntropyBlocklist struct {
	config        *config.EntropyConfig
	logger        *slog.Logger
	mutex         *sync.RWMutex
	disabledUntil *time.Time
}

// NewShannonEntropyBlocklist constructs a ShannonEntropyBlocklist from the
// given configuration. If no thresholds/suffixes are configured, sensible
// defaults are applied.
func NewShannonEntropyBlocklist(cfg *config.EntropyConfig, logger *slog.Logger) *ShannonEntropyBlocklist {
	if cfg == nil {
		cfg = &config.EntropyConfig{}
	}

	if len(cfg.Suffixes) == 0 {
		cfg.Suffixes = append([]string{}, defaultEntropySuffixes...)
	}
	if cfg.MinLabelLength <= 0 {
		cfg.MinLabelLength = 8
	}
	if cfg.HexThreshold <= 0 {
		cfg.HexThreshold = 3.8
	}
	if cfg.AlnumThreshold <= 0 {
		cfg.AlnumThreshold = 4.2
	}

	return &ShannonEntropyBlocklist{
		config: cfg,
		logger: logger.With("name", ShannonEntropyBlocklistName),
		mutex:  &sync.RWMutex{},
	}
}

// Name returns the blocklist identifier used as the block "cause".
func (b *ShannonEntropyBlocklist) Name() string {
	return ShannonEntropyBlocklistName
}

// Title returns a human-readable title for reporting/status endpoints.
func (b *ShannonEntropyBlocklist) Title() string {
	return "Dynamic Shannon entropy DGA & malware subdomain detection"
}

// Description returns the configuration description of the blocklist.
func (b *ShannonEntropyBlocklist) Description() string {
	return `Ad-blocklists and Bloom filters rely on known static domains. However, modern malware and C2
		infrastructure frequently leverage legitimate CDNs and cloud storage providers (e.g., CloudFront,
		AWS S3, Azure Blob) via dynamically generated subdomains matching patterns like d<random-chars>.cloudfront.net
		or using Domain Generation Algorithms (DGAs). This blocklist inspects subdomains on high-risk shared
		hosting/CDN suffixes and dynamically flags/blocks high-entropy or random-looking subdomains indicative
		of malware or DGA activity.`
}

// URL returns the source URL of the blocklist. As the entropy blocklist is a
// built-in heuristic rather than a downloadable list, this is empty.
func (b *ShannonEntropyBlocklist) URL() string {
	return ""
}

// Fetch is a no-op for the entropy blocklist, which has no downloadable
// source. It exists only to satisfy the Blocklist interface so that the
// blocklist can participate in reload/disable/status operations uniformly.
func (b *ShannonEntropyBlocklist) Fetch(_ context.Context) error {
	return errors.New("unsuppoted operation")
}

// Load is a no-op for the entropy blocklist, which holds no static entries.
func (b *ShannonEntropyBlocklist) Load(_ []string) {}

// Disable temporarily disables the entropy blocklist for the given duration.
func (b *ShannonEntropyBlocklist) Disable(duration time.Duration) time.Time {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.disabledUntil = new(time.Now().Add(duration))
	b.logger.Warn("Blocklist temporarily disabled",
		"name", b.Name(),
		"until", b.disabledUntil)

	return *b.disabledUntil
}

// Reenable re-enables a previously disabled entropy blocklist.
func (b *ShannonEntropyBlocklist) Reenable() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.disabledUntil == nil || time.Now().After(*b.disabledUntil) {
		return false
	}

	b.disabledUntil = nil
	b.logger.Info("Blocklist re-enabled", "name", b.Name())
	return true
}

// Status returns a status snapshot for the entropy blocklist.
func (b *ShannonEntropyBlocklist) Status() *BlocklistStatus {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	var disabledUntil *time.Time
	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		disabledUntil = b.disabledUntil
	}

	return &BlocklistStatus{
		Name:          b.Name(),
		Title:         b.Title(),
		Description:   b.Description(),
		URL:           b.URL(),
		MetaData:      map[string]string{},
		DisabledUntil: disabledUntil,
	}
}

// IsBlocked reports whether the given fully-qualified domain should be blocked
// on the basis of Shannon entropy analysis.
//
// The check is only performed for domains whose registrable suffix matches one
// of the configured (high-risk) CDN / shared-hosting suffixes. The subdomain
// portion preceding the suffix is examined: if it is long enough and its
// character-level Shannon entropy exceeds the configured threshold (a lower
// threshold is used for purely-hexadecimal labels, which have a smaller
// alphabet and therefore naturally lower maximum entropy), the domain is
// flagged as suspicious.
func (b *ShannonEntropyBlocklist) IsBlocked(fqdn string) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	if b.disabledUntil != nil && time.Now().Before(*b.disabledUntil) {
		return false, nil
	}

	domain, _ := strings.CutSuffix(fqdn, ".")
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, nil
	}

	subdomain, matched := b.matchSuffix(domain)
	if !matched || subdomain == "" {
		return false, nil
	}

	// Collapse the subdomain portion (which may contain multiple labels) into
	// a single string of label characters, preserving the relative frequency
	// of each character. Dots are dropped so that multi-label subdomains such
	// as "a.b.cloudfront.net" are assessed on their content rather than their
	// label structure.
	label := strings.ReplaceAll(subdomain, ".", "")
	if len(label) < b.config.MinLabelLength {
		return false, nil
	}

	entropy := calculateEntropy(label)

	threshold := b.config.AlnumThreshold
	if isHex(label) {
		threshold = b.config.HexThreshold
	}

	if entropy >= threshold {
		b.logger.Debug("Domain blocked by entropy analysis",
			"domain", fqdn,
			"label", label,
			"entropy", entropy,
			"threshold", threshold,
		)
		return true, nil
	}

	return false, nil
}

// matchSuffix reports whether the domain ends with one of the configured
// high-risk suffixes, returning the subdomain portion preceding the first
// matching suffix. Suffixes are normalised to carry a leading dot so that the
// suffix boundary is respected (e.g. ".cloudfront.net" does not match
// "notcloudfront.net").
func (b *ShannonEntropyBlocklist) matchSuffix(domain string) (subdomain string, matched bool) {
	for _, suffix := range b.config.Suffixes {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix == "" {
			continue
		}
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if strings.HasSuffix(domain, suffix) {
			return strings.TrimSuffix(domain, suffix), true
		}
	}
	return "", false
}

// calculateEntropy returns the Shannon entropy (in bits) of the string s.
// A value close to 0 indicates a highly predictable string (e.g. "aaaa"),
// while a value approaching the alphabet-size maximum (log2(len(alphabet)))
// indicates a random string.
func calculateEntropy(s string) float64 {
	n := len(s)
	if n == 0 {
		return 0
	}
	freq := make(map[rune]int, n)
	for _, c := range s {
		freq[c]++
	}
	var h float64
	total := float64(n)
	for _, c := range freq {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// isHex reports whether s is composed entirely of hexadecimal characters
// (case-insensitive). Hex strings have a 16-character alphabet and so a lower
// entropy ceiling (4.0 bits) than the full alphanumeric alphabet.
func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
